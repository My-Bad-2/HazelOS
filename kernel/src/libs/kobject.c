#include "libs/kobject.h"

#include <stdint.h>

#include "arch.h"
#include "compiler.h"
#include "cpu/smp.h"

#define SHIFT_TYPE   56
#define MASK_PAYLOAD 0x00fffffffffffffful  // 56 bits
#define MASK_HALF    0x0ffffffful          // 28 bits

#define BLOCK_SIZE 4096
#define STRIDE     7

static _Atomic(uint64_t) global_koid_base = 0;
static uint32_t boot_keys[4]              = {0};

static struct koid_allocator early_bsp_allocator = {0, 0};

static inline uint32_t integer_f(uint32_t right_half, uint32_t round_key) {
    uint32_t x = right_half ^ round_key;

    // Borrowed from MurmurHash3's fmix32
    // Original: https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp
    x ^= x >> 16;
    x *= 0x85ebca6b;
    x ^= x >> 13;
    x *= 0xc2b2ae35;
    x ^= x >> 16;

    return x;
}

// 4-Round Feistel Cipher to scramble 56 bits
static inline uint64_t scramble_56bit(uint64_t monotonic_id) {
    uint32_t L    = (monotonic_id >> 28) & MASK_HALF;
    uint32_t R    = monotonic_id & MASK_HALF;
    uint32_t temp = 0;

    temp = R;
    R    = L ^ (integer_f(R, boot_keys[0]) & MASK_HALF);
    L    = temp;

    temp = R;
    R    = L ^ (integer_f(R, boot_keys[1]) & MASK_HALF);
    L    = temp;

    temp = R;
    R    = L ^ (integer_f(R, boot_keys[2]) & MASK_HALF);
    L    = temp;

    temp = R;
    R    = L ^ (integer_f(R, boot_keys[3]) & MASK_HALF);
    L    = temp;

    return ((uint64_t)L << 28) | R;
}

static void fetch_new_block(struct koid_allocator* core) {
    uint64_t new_base =
        atomic_fetch_add_explicit(&global_koid_base, BLOCK_SIZE, memory_order_relaxed);

    core->curr_id      = new_base;
    core->block_max_id = new_base + BLOCK_SIZE;
}

void koid_init(void) {
    for (int i = 0; i < sizeof(boot_keys) / sizeof(boot_keys[0]); ++i) {
        boot_keys[i] = arch_get_random_bytes();
    }

    atomic_init(&global_koid_base, 1);
}

uint64_t generate_koid(struct koid_allocator* core, uint8_t object_type) {
    if (unlikely(core->curr_id + STRIDE) >= core->block_max_id) {
        fetch_new_block(core);
    }

    uint64_t monotonic = core->curr_id;
    core->curr_id += STRIDE;

    monotonic &= MASK_PAYLOAD;
    uint64_t payload = scramble_56bit(monotonic);
    return ((uint64_t)object_type << SHIFT_TYPE) | payload;
}

struct koid_allocator* koid_get_current_allocator(void) {
    if (likely(smp_is_initialized())) {
        return &smp_current_core()->allocator;
    }

    return &early_bsp_allocator;
}