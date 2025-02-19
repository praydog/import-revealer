# This file is automatically generated from cmake.toml - DO NOT EDIT
# See https://github.com/build-cpp/cmkr for more information

cmake_minimum_required(VERSION 3.15)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
	message(FATAL_ERROR "In-tree builds are not supported. Run CMake from a separate directory: cmake -B build")
endif()

set(CMKR_ROOT_PROJECT OFF)
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
	set(CMKR_ROOT_PROJECT ON)

	# Bootstrap cmkr and automatically regenerate CMakeLists.txt
	include(cmkr.cmake OPTIONAL RESULT_VARIABLE CMKR_INCLUDE_RESULT)
	if(CMKR_INCLUDE_RESULT)
		cmkr()
	endif()

	# Enable folder support
	set_property(GLOBAL PROPERTY USE_FOLDERS ON)

	# Create a configure-time dependency on cmake.toml to improve IDE support
	configure_file(cmake.toml cmake.toml COPYONLY)
endif()

add_compile_options($<$<CXX_COMPILER_ID:MSVC>:/MP>)

project(template-project)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /MP")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP")

if ("${CMAKE_BUILD_TYPE}" MATCHES "Release")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /MT")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MT")

    # Statically compile runtime
    string(REGEX REPLACE "/MD" "/MT" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    string(REGEX REPLACE "/MD" "/MT" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
    string(REGEX REPLACE "/MD" "/MT" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
    string(REGEX REPLACE "/MD" "/MT" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")

    message(NOTICE "Building in Release mode")
endif()

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

include(FetchContent)

# Fix warnings about DOWNLOAD_EXTRACT_TIMESTAMP
if(POLICY CMP0135)
	cmake_policy(SET CMP0135 NEW)
endif()
message(STATUS "Fetching spdlog (v1.13.0)...")
FetchContent_Declare(spdlog SYSTEM
	GIT_REPOSITORY
		"https://github.com/gabime/spdlog"
	GIT_TAG
		v1.13.0
)
FetchContent_MakeAvailable(spdlog)

message(STATUS "Fetching bddisasm (v1.34.10)...")
FetchContent_Declare(bddisasm SYSTEM
	GIT_REPOSITORY
		"https://github.com/bitdefender/bddisasm"
	GIT_TAG
		v1.34.10
)
FetchContent_MakeAvailable(bddisasm)

message(STATUS "Fetching kananlib (main)...")
FetchContent_Declare(kananlib SYSTEM
	GIT_REPOSITORY
		"https://github.com/cursey/kananlib"
	GIT_TAG
		main
)
FetchContent_MakeAvailable(kananlib)

message(STATUS "Fetching json (bc889afb4c5bf1c0d8ee29ef35eaaf4c8bef8a5d)...")
FetchContent_Declare(json SYSTEM
	GIT_REPOSITORY
		"https://github.com/nlohmann/json"
	GIT_TAG
		bc889afb4c5bf1c0d8ee29ef35eaaf4c8bef8a5d
)
FetchContent_MakeAvailable(json)

# Target: vrproject
set(vrproject_SOURCES
	"src/DllMain.cpp"
	cmake.toml
)

add_library(vrproject SHARED)

target_sources(vrproject PRIVATE ${vrproject_SOURCES})
source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${vrproject_SOURCES})

target_compile_features(vrproject PUBLIC
	cxx_std_23
)

target_compile_options(vrproject PUBLIC
	"/GS-"
	"/bigobj"
	"/EHa"
	"/MP"
)

target_include_directories(vrproject PUBLIC
	"src/"
)

target_link_libraries(vrproject PUBLIC
	shlwapi
	spdlog
	kananlib
	nlohmann_json
)

set_target_properties(vrproject PROPERTIES
	OUTPUT_NAME
		TEMPLATE
	RUNTIME_OUTPUT_DIRECTORY_RELEASE
		"${CMAKE_BINARY_DIR}/bin/${CMKR_TARGET}"
	RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO
		"${CMAKE_BINARY_DIR}/bin/${CMKR_TARGET}"
	LIBRARY_OUTPUT_DIRECTORY_RELEASE
		"${CMAKE_BINARY_DIR}/lib/${CMKR_TARGET}"
	LIBRARY_OUTPUT_DIRECTORY_RELWITHDEBINFO
		"${CMAKE_BINARY_DIR}/lib/${CMKR_TARGET}"
	ARCHIVE_OUTPUT_DIRECTORY_RELEASE
		"${CMAKE_BINARY_DIR}/lib/${CMKR_TARGET}"
	ARCHIVE_OUTPUT_DIRECTORY_RELWITHDEBINFO
		"${CMAKE_BINARY_DIR}/lib/${CMKR_TARGET}"
)
