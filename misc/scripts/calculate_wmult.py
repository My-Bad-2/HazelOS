import math

NICE_0_LOAD = 1024
FACTOR = 1.25
SHIFT_AMOUNT = 32

def calculate_inverse_weights():
    print("static const uint32_t prio_to_wmult[40] = {")
    
    for nice in range(-20, 20):
        # Formula: 1024 / (FACTOR ^ nice)
        raw_weight = NICE_0_LOAD / math.pow(FACTOR, nice)
        
        # Formula: (2^32) / Weight
        if raw_weight < 1: 
            raw_weight = 1
            
        wmult = (2**SHIFT_AMOUNT) / raw_weight
        
        wmult_int = int(wmult)
        prefix = f"    /* {nice:3d} */ "
        print(f"{prefix}0x{wmult_int:08X},", end="")

        if (nice + 21) % 4 == 0:
            print()

    print("};")

if __name__ == "__main__":
    calculate_inverse_weights()