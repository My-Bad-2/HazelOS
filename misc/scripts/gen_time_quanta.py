def generate_exponential_quanta(levels, start_ms, growth_rate=None, target_max_ms=None):
    quanta = []
    
    # Mode 1: Calculate based on target max value (Interpolation)
    if target_max_ms is not None:
        # target = start * (rate)^(levels-1)
        # rate = (target / start) ^ (1 / (levels - 1))
        growth_rate = (target_max_ms / start_ms) ** (1 / (levels - 1))
        print(f"[INFO] Calculated Growth Rate to hit {target_max_ms}ms: {growth_rate:.4f} (approx {(growth_rate-1)*100:.1f}%)")
    
    # Mode 2: Default Growth Rate (Standard is ~1.15 for smooth curves)
    elif growth_rate is None:
        growth_rate = 1.15 
        print(f"[INFO] Using default Growth Rate: {growth_rate:.2f}")

    # Generate values
    for i in range(levels):
        val = start_ms * (growth_rate ** i)
        quanta.append(round(val))

    return quanta

def print_cpp_array(quanta):
    print(f"constexpr int TIME_SLICE_QUANTA[{len(quanta)}] = {{")
    
    row_size = 8
    for i in range(0, len(quanta), row_size):
        row = quanta[i:i+row_size]
        row_str = ", ".join(map(str, row))
        
        if i + row_size < len(quanta):
            print(f"    {row_str},")
        else:
            print(f"    {row_str}")
            
    print("};")

TOTAL_LEVELS = int(input("Total MLFQ levels: "))
INITIAL_QUANTA = int(input("Initial Quanta: "))

# Set a specific multiplier (1.1 = 10% increase per level)
GROWTH_RATE = 1.1 
TARGET_MAX = None

if __name__ == "__main__":
    result = generate_exponential_quanta(TOTAL_LEVELS, INITIAL_QUANTA, GROWTH_RATE, TARGET_MAX)
    print_cpp_array(result)