import math


def generate_pelt_table():
    half_life_ms = 32
    scale_bits = 32
    table_size = 32

    # Formula: y^32 = 0.5  =>  y = 0.5^(1/32)
    decay_factor = 0.5 ** (1.0 / half_life_ms)

    scale_max = 2**scale_bits

    print(f"/* CPU PELT Lookup Table (Half-life: {half_life_ms}ms) */")
    print(f"/* Base Factor (y): {decay_factor:.8f} */")
    print("static const uint32_t runnable_avg_yN_inv[] = {")

    line_buffer = []

    for n in range(table_size):
        value_float = decay_factor**n
        value_int = int(value_float * scale_max)

        if n == 0:
            value_int = 0xFFFFFFFF

        hex_str = f"0x{value_int:08x}"
        line_buffer.append(hex_str)

        if len(line_buffer) == 4:
            print(f"    {', '.join(line_buffer)}, // {n-3}-{n}")
            line_buffer = []

    if line_buffer:
        print(f"    {', '.join(line_buffer)} // Remaining")

    print("};")


if __name__ == "__main__":
    generate_pelt_table()
