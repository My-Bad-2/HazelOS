import math


def calculate_pelt_factors():
    FIXED_1 = 32768

    # Formula: Factor = 0.5 ^ (i / 32)
    print("static const uint16_t pelt_decay_factors[32] = {")

    for i in range(32):
        decay = math.pow(0.5, i / 32.0)
        value = int(round(decay * FIXED_1))
        prefix = f"    /* {i:2d}ms */ "
        print(f"{prefix}0x{value:x},", end="")

        if (i + 1) % 4 == 0:
            print()

    print("};")


if __name__ == "__main__":
    calculate_pelt_factors()
