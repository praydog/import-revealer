# Convert our JSON import data to IDA Python script to name functions
import json
import fire
import os

def main(imports_path = "imports.json", out_path = "imports.py"):
    if not os.path.exists(imports_path):
        print("{} does not exist".format(imports_path))
        return
    
    with open(imports_path, "r", encoding="utf8") as f:
        imports_json = json.load(f)
    
    out_str = "import idaapi\n"
    out_str = out_str + "imagebase = idaapi.get_imagebase()\n"

    imports = imports_json["imports"]
    for import_name, addresses in imports.items():
        count = 0
        for address in addresses:
            if count == 0:
                out_str = out_str + "idc.MakeName(imagebase + 0x%s, '%s')\n" % (address, import_name)
            else:
                appended_name = import_name + "_" + str(count)
                out_str = out_str + "idc.MakeName(imagebase + 0x%s, '%s')\n" % (address, appended_name)
            
            count = count + 1
    
    with open(out_path, "w", encoding="utf8") as f:
        f.write(out_str)
    
    print("Wrote to {}".format(out_path))


if __name__ == '__main__':
    fire.Fire(main)