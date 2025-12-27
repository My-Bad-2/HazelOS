import sys
import subprocess


def generate_symbol_table(nm_path, elf_path, output_c_path):
    cmd = f"{nm_path} -n -C {elf_path}"

    try:
        output = subprocess.check_output(cmd, shell=True).decode("utf-8")
    except:
        print("Error running nm.")
        return

    symbols = []
    for line in output.splitlines():
        parts = line.split()
        
        if len(parts) < 3:
            continue

        addr_str = parts[0]
        type_char = parts[1].upper()
        name = " ".join(parts[2:])
        
        if "kernel_symbols" in name or "kernel_symbol_count" in name:
            continue

        if type_char in ["T", "t", "W", "w"]:
            symbols.append((int(addr_str, 16), name))

    with open(output_c_path, "w") as f:
        f.write('#include "libs/symbols.h"\n')
        f.write("#include <stddef.h>\n\n")
        f.write("const kernel_symbol_t kernel_symbols[] = {\n")

        for addr, name in symbols:
            safe_name = name.replace('"', '\\"')
            f.write(f'    {{ 0x{addr:x}, "{safe_name}" }},\n')

        f.write("};\n\n")
        f.write(f"const size_t kernel_symbol_count = {len(symbols)};\n")


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python3 map_to_c.py <nm_path> <kernel_elf> <output_c_file>")
        sys.exit(1)

    generate_symbol_table(sys.argv[1], sys.argv[2], sys.argv[3])
