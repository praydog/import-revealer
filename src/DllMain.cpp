#include <windows.h>
#include <ppl.h>

#include <fstream>
#include <iostream>
#include <cstdint>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <shared_mutex>

#include <nlohmann/json.hpp>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_sinks.h>

#include <utility/Scan.hpp>
#include <utility/Module.hpp>

struct Import {
    void** pointer_to_export;
    std::string export_name;
};

struct Export {
    void* export_address;
    std::string export_name;
};

// Cache of export names to avoid repeated lookups
std::unordered_map<void*, std::string> g_export_names{};
std::unordered_set<void*> g_seen_pointers{};
std::shared_mutex g_export_names_mutex{};
std::shared_mutex g_seen_pointers_mutex{};

void cache_module_exports(HMODULE module_within) {
    {
        std::shared_lock lock{g_export_names_mutex};

        if (g_export_names.contains(module_within)) {
            return;
        }
    }

    if (module_within == nullptr) {
        return;
    }

    // Parse the PE header of the module
    const IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)module_within;
    const IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((uint8_t*)module_within + dos_header->e_lfanew);

    // Check magic
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        spdlog::error("Invalid NT signature for module: {:x}", (uintptr_t)module_within);
        return;
    }

    // Get the export directory
    const IMAGE_DATA_DIRECTORY* export_directory = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (export_directory->Size == 0) {
        spdlog::error("No export directory for module: {:x}", (uintptr_t)module_within);
        return;
    }

    // Get the export data
    const IMAGE_EXPORT_DIRECTORY* export_data = (IMAGE_EXPORT_DIRECTORY*)((uint8_t*)module_within + export_directory->VirtualAddress);

    // Get the names of the exports
    const uint32_t* export_names = (uint32_t*)((uint8_t*)module_within + export_data->AddressOfNames);
    const uint16_t* export_ordinal = (uint16_t*)((uint8_t*)module_within + export_data->AddressOfNameOrdinals);
    const uint32_t* export_rva = (uint32_t*)((uint8_t*)module_within + export_data->AddressOfFunctions);

    auto resolve_forwarded_export = [](this auto& self, const char* forwarded) -> std::optional<Export> {
        auto export_name = strchr(forwarded, '.');
        if (export_name == nullptr) {
            return std::nullopt;
        }

        export_name++; // Skip the dot

        auto module_name = std::string{forwarded, (size_t)(((uintptr_t)strchr(forwarded, '.') - (uintptr_t)forwarded))};
        const auto module = GetModuleHandleA(module_name.c_str());

        if (module == nullptr) {
            return std::nullopt;
        }

        const auto addr = GetProcAddress(module, export_name);
        if (addr == nullptr) {
            return std::nullopt;
        }

        return Export{addr, export_name};
    };

    const auto export_directory_rva = export_directory->VirtualAddress;
    const auto export_directory_size = export_directory->Size;

    for (size_t i = 0; i < export_data->NumberOfFunctions; i++) {
        uintptr_t function_rva = export_rva[i];

        // Check if the function RVA is within the export directory to determine if it's forwarded
        if (function_rva >= export_directory_rva && function_rva < export_directory_rva + export_directory_size) {
            // This function is forwarded.
            const char* forwarded = (const char*)((uint8_t*)module_within + function_rva);

            if (auto resolved = resolve_forwarded_export(forwarded); resolved.has_value()) {
                std::unique_lock lock{g_export_names_mutex};
                g_export_names[(void*)((uint8_t*)module_within + export_rva[i])] = resolved->export_name;
                //g_export_names[resolved->export_address] = resolved->export_name;
            }

            continue; // Move to the next export
        }


        // Walk the export names to find the name of the export given the ordinal
        for (size_t j = 0; j < export_data->NumberOfNames; j++) {
            if (export_ordinal[j] == i) {
                const char* name = (const char*)((uint8_t*)module_within + export_names[export_ordinal[j]]);

                if (name == nullptr || IsBadReadPtr(name, sizeof(void*)) || name[0] == '\0') {
                    continue;
                }

                {
                    std::unique_lock lock{g_export_names_mutex};
                    g_export_names[(void*)((uint8_t*)module_within + export_rva[i])] = name;
                }

                break;
            }
        }
    }
}

// Walk the exports of the module containing the candidate, and check
// if any of the exports match the candidate
std::optional<std::string> get_export_name(void* candidate) {
    {
        std::shared_lock lock{g_export_names_mutex};
        if (auto it = g_export_names.find(candidate); it != g_export_names.end()) {
            return it->second;
        }
    }

    {
        std::shared_lock lock{g_seen_pointers_mutex};
        if (g_seen_pointers.contains(candidate)) {
            return std::nullopt;
        }
    }

    {
        std::unique_lock lock{g_seen_pointers_mutex};
        g_seen_pointers.insert(candidate);
    }

    const auto module_within = utility::get_module_within(candidate);

    if (!module_within.has_value() || *module_within == utility::get_executable()) {
        return std::nullopt;
    }

    cache_module_exports(*module_within);

    std::shared_lock lock{g_export_names_mutex};
    if (auto it = g_export_names.find(candidate); it != g_export_names.end()) {
        return it->second;
    }

    return std::nullopt;
}

std::optional<Import> get_import(void** candidate) {
    if (IsBadReadPtr((void*)candidate, sizeof(void*))) {
        return std::nullopt;
    }

    if (IsBadReadPtr(*candidate, sizeof(void*))) {
        return std::nullopt;
    }

    const auto export_name = get_export_name(*candidate);

    if (!export_name.has_value()) {
        return std::nullopt;
    }

    return Import{candidate, export_name.value()};
}

// Scan through entire process memory looking for pointers to valid exports
std::vector<Import> locate_imports() {
    const auto base = (uintptr_t)utility::get_executable();
    const auto size = utility::get_module_size(utility::get_executable()).value_or(0);

    std::vector<Import> imports{};
    std::mutex mtx{};

    concurrency::parallel_for((size_t)base, (size_t)(base + size - sizeof(void*)), sizeof(void*), [&](size_t i) {
        void** ptr = (void**)i;

        if (const auto imp = get_import(ptr); imp.has_value()) {
            spdlog::info("Found import: {} -> {:x}", imp->export_name, (uintptr_t)imp->pointer_to_export);

            std::scoped_lock lock{mtx};
            imports.push_back(imp.value());
        }
    });

    return imports;
}

class SimpleScheduler {
public:
    SimpleScheduler() {
        m_evt = CreateEvent(NULL, FALSE, FALSE, NULL);

        Concurrency::SchedulerPolicy policy(1, Concurrency::ContextPriority, THREAD_PRIORITY_HIGHEST);
        m_impl = Concurrency::Scheduler::Create(policy);
        m_impl->RegisterShutdownEvent(m_evt);
        m_impl->Attach();
    }

    virtual ~SimpleScheduler() {
        if (m_impl != nullptr) {
            Concurrency::CurrentScheduler::Detach();
            m_impl->Release();

            SPDLOG_INFO("Waiting for the scheduler to shut down...");
            if (WaitForSingleObject(m_evt, 1000) == WAIT_OBJECT_0) {
                SPDLOG_INFO("Scheduler has shut down.");
                CloseHandle(m_evt);
            } else {
                SPDLOG_ERROR("Failed to wait for the scheduler to shut down.");
            }
        }
    }
private:
    Concurrency::Scheduler* m_impl{nullptr};
    HANDLE m_evt{nullptr};
};


void attach() {
    SimpleScheduler current_thread_scheduler{};

    // Spawn console window
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);

    // Initialize logger
    // Set up spdlog to sink to the console
    spdlog::set_pattern("[%H:%M:%S] [%^%l%$] [import-dumper] %v");
    spdlog::set_level(spdlog::level::info);
    spdlog::flush_on(spdlog::level::info);
    spdlog::set_default_logger(spdlog::stdout_logger_mt("console"));

    spdlog::info("DLL_PROCESS_ATTACH");

    const auto imports = locate_imports();

    nlohmann::json j{};
    j["imports"] = nlohmann::json::object();

    const auto base = (uintptr_t)utility::get_executable();

    // Dump the imports to a JSON file
    for (const auto& imp : imports) {
        if (std::any_of(imp.export_name.begin(), imp.export_name.end(), [](char c) { return !std::isprint(c); })) {
            continue;
        }

        if (!j["imports"].contains(imp.export_name)) {
            j["imports"][imp.export_name] = nlohmann::json::array();
        }

        const auto rva = (uintptr_t)imp.pointer_to_export - base;
        j["imports"][imp.export_name].push_back(std::format("{:x}", rva));
    }

    std::ofstream file("imports.json");
    file << j.dump(4);
    file.close();

    spdlog::info("Dumped imports to imports.json");
}

uint32_t __stdcall DllMain(void* module, uint32_t ul_reason_for_call, void* reserved) {
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)attach, NULL, 0, NULL);
        break;
    }
    return 1;
}