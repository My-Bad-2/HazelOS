import math

def calculate_cfs_weights():
    NICE_0_LOAD = 1024
    FACTOR = 1.25

    print("static const size_t prio_to_weight[40] = {")
    
    # Formula: Weight = 1024 / (FACTOR ^ nice)
    for nice in range(-20, 20):
        # High priority (Negative nice) -> Large Weight
        # Low priority (Positive Nice) -> Small Weight
        weight_raw = NICE_0_LOAD / math.pow(FACTOR, nice)
        weight = int(round(weight_raw))
        
        print(f"{weight},", end="")
        if (nice + 21) % 5 == 0:
            print()

    print("};")

if __name__ == "__main__":
    calculate_cfs_weights()