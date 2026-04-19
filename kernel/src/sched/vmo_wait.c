#include <string.h>

#include "cpu/smp.h"
#include "libs/hashtable.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "memory/memory.h"
#include "sched/process.h"
#include "sched/scheduler.h"
#include "sched/wait.h"

#define PAGE_WAIT_TABLE_BITS 8
#define PAGE_WAIT_TABLE_SIZE (1 << PAGE_WAIT_TABLE_BITS)

static struct page_wait_bucket* global_page_wait_table;

void vmm_wait_table_init(void) {
    const size_t size      = sizeof(struct page_wait_bucket) * PAGE_WAIT_TABLE_SIZE;
    global_page_wait_table = kmalloc(size);
    memset(global_page_wait_table, 0, size);
}

static inline uint64_t vmo_wait_hash_key(struct vm_object* vmo, size_t offset) {
    return ((uint64_t)vmo >> PAGE_SHIFT_SMALL) ^ (offset >> PAGE_SHIFT_SMALL);
}

void sched_prepare_page_wait(struct vmo_page_waiter* waiter, struct vm_object* vmo, size_t offset) {
    struct thread* curr = smp_current_core()->curr_thread;

    waiter->thread = curr;
    waiter->vmo    = vmo;
    waiter->offset = offset;
    ht_init_node(&waiter->node);

    uint64_t key                    = vmo_wait_hash_key(vmo, offset);
    uint32_t bucket_idx             = ht_hash_64(key, PAGE_WAIT_TABLE_BITS);
    struct page_wait_bucket* bucket = &global_page_wait_table[bucket_idx];

    acquire_qspinlock(&bucket->lock);

    __ht_link_node(&bucket->waiters, &waiter->node);

    acquire_qspinlock(&curr->lock);
    curr->state = THREAD_BLOCKED;
    release_qspinlock(&curr->lock);

    release_qspinlock(&bucket->lock);
}

void sched_commit_page_wait(void) {
    scheduler_yield();
}

void sched_abort_page_wait(struct vmo_page_waiter* waiter) {
    uint64_t key                    = vmo_wait_hash_key(waiter->vmo, waiter->offset);
    uint32_t bucket_idx             = ht_hash_64(key, PAGE_WAIT_TABLE_BITS);
    struct page_wait_bucket* bucket = &global_page_wait_table[bucket_idx];

    acquire_qspinlock(&bucket->lock);
    if (!ht_unhashed(&waiter->node)) ht_remove(&waiter->node);
    release_qspinlock(&bucket->lock);

    thread_t* curr = smp_current_core()->curr_thread;
    acquire_qspinlock(&curr->lock);
    curr->state = THREAD_READY;
    release_qspinlock(&curr->lock);
}

void sched_wake_threads_waiting_on_page(struct vm_object* vmo, size_t base_offset, size_t length) {
    if (unlikely(!vmo || length == 0)) return;

    size_t end_offset = base_offset + length;
    for (size_t current_offset = base_offset; current_offset < end_offset;
         current_offset += PAGE_SIZE_SMALL) {
        uint64_t key                    = vmo_wait_hash_key(vmo, current_offset);
        uint32_t bucket_idx             = ht_hash_64(key, PAGE_WAIT_TABLE_BITS);
        struct page_wait_bucket* bucket = &global_page_wait_table[bucket_idx];

        acquire_qspinlock(&bucket->lock);

        struct vmo_page_waiter* waiter;
        struct hlist_node* n;

        ht_for_each_entry_safe(waiter, n, &bucket->waiters, node) {
            if (waiter->vmo == vmo && waiter->offset == current_offset) {
                ht_remove(&waiter->node);

                thread_t* t = waiter->thread;
                acquire_qspinlock(&t->lock);

                if (t->state == THREAD_BLOCKED) {
                    t->state = THREAD_READY;
                    scheduler_add_thread(t);
                }

                release_qspinlock(&t->lock);
            }
        }

        release_qspinlock(&bucket->lock);
    }
}