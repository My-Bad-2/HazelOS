#include "sched/scheduler.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "arch.h"
#include "boot/boot.h"
#include "compiler.h"
#include "cpu/exception.h"
#include "cpu/gdt.h"
#include "cpu/registers.h"
#include "cpu/smp.h"
#include "drivers/arch_timer.h"
#include "drivers/timer.h"
#include "libs/list.h"
#include "libs/log.h"
#include "libs/spinlock.h"
#include "memory/heap.h"
#include "sched/process.h"

#define MLFQ_LEVELS           32
#define QUANTUM_MIN           5
#define QUANTUM_SCALE         32
#define BOOST_THRESHOLD       2000
#define LOAD_BALANCE_INTERVAL 1000

static process_t* kernel_proc   = nullptr;
static uint32_t cpu_count       = 0;
static uint32_t balance_counter = 0;
static struct list_node sleeping_list;
static bool initialized = false;

void arch_switch_context(switch_context_t** prev, switch_context_t* next);

static void idle_task_entry(void*) {
    arch_halt(true);
}

static inline int get_timer_slice(int priority) {
    return QUANTUM_MIN + (priority * QUANTUM_SCALE);
}

static inline int get_highest_priority_queue(uint32_t bitmap) {
    if (bitmap == 0) {
        return -1;
    }

    return ctz(bitmap);
}

static void sleep_callback(void* ctx) {
    thread_t* t = (thread_t*)ctx;

    if (t->state != THREAD_SLEEPING) {
        return;
    }

    scheduler_unblock(t);
}

void scheduler_init(void) {
    const size_t size = sizeof(struct list_node) * MLFQ_LEVELS;
    kernel_proc       = process_create(true);
    cpu_count         = (uint32_t)mp_request.response->cpu_count;

    if (!kernel_proc) {
        if (errno == 0) {
            errno = ENOMEM;
        }

        KLOG_ERROR("SCHED: failed to create kernel process errno=%d\n", errno);
        return;
    }

    for (uint32_t i = 0; i < cpu_count; ++i) {
        per_cpu_data_t* data = smp_get_core(i);

        acquire_interrupt_lock(&data->lock);

        data->active_queues_bitmap = 0;
        data->queues               = kmalloc(size);

        if (!data->queues) {
            errno = ENOMEM;
            KLOG_ERROR("SCHED: failed to allocate run queues cpu=%u errno=%d\n", i, errno);
            release_interrupt_lock(&data->lock);
            return;
        }

        memset(data->queues, 0, size);

        for (int q = 0; q < MLFQ_LEVELS; ++q) {
            list_init(&data->queues[q]);
        }

        thread_t* idle = thread_create(kernel_proc, idle_task_entry, nullptr);

        if (!idle) {
            int err = errno ? errno : EINVAL;
            KLOG_ERROR("SCHED: failed to create idle thread cpu=%u errno=%d\n", i, err);
            release_interrupt_lock(&data->lock);
            return;
        }

        data->idle_thread       = idle;
        data->curr_thread       = idle;
        data->thread_count      = 1;
        data->ticks_since_boost = 0;

        release_interrupt_lock(&data->lock);
    }

    timer_configure(TIMER_PERIODIC, IRQ_TIMER, 1);

    initialized = true;

    KLOG_INFO("SCHED: initialized cpus=%u levels=%d\n", cpu_count, MLFQ_LEVELS);
}

void scheduler_add_thread(thread_t* t) {
    if (!t) {
        errno = EINVAL;
        KLOG_WARN("SCHED: add_thread called with null thread\n");
        return;
    }

    uint32_t cpu    = t->tid % cpu_count;
    t->assigned_cpu = cpu;

    per_cpu_data_t* data = smp_get_core(cpu);

    acquire_interrupt_lock(&data->lock);

    t->priority        = 0;
    t->ticks_remaining = get_timer_slice(t->priority);
    t->state           = THREAD_READY;

    list_push_back(&data->queues[0], &t->sched_node);
    data->active_queues_bitmap |= (1 << 0);
    data->thread_count++;

    release_interrupt_lock(&data->lock);
}

void scheduler_remove_thread(thread_t* t) {
    if (!t) {
        errno = EINVAL;
        KLOG_WARN("SCHED: remove_thread called with null thread\n");
        return;
    }

    per_cpu_data_t* data = smp_get_core(t->assigned_cpu);
    int priority         = t->priority;

    acquire_interrupt_lock(&data->lock);

    if (t->state == THREAD_READY) {
        if (t->sched_node.next) {
            list_remove(&t->sched_node);

            t->sched_node.next = nullptr;
            t->sched_node.prev = nullptr;

            if (list_empty(&data->queues[priority])) {
                data->active_queues_bitmap &= ~(1u << priority);
            }
        }
    }

    data->thread_count--;
    t->state = THREAD_TERMINATED;

    release_interrupt_lock(&data->lock);
}

static void balance_load(void) {
    per_cpu_data_t* me     = smp_current_core();
    per_cpu_data_t* victim = nullptr;

    uint32_t max_threads = 0;

    for (uint32_t i = 0; i < cpu_count; ++i) {
        if (i == me->cpu_idx) {
            continue;
        }

        per_cpu_data_t* cpu = smp_get_core(i);

        if (cpu->thread_count > max_threads) {
            max_threads = cpu->thread_count;
            victim      = cpu;
        }
    }

    // Only steal if victim has more than 1 threads
    if (!victim || max_threads < 2) {
        return;
    }

    // Deadlock-free locking
    per_cpu_data_t* first  = (me->cpu_idx < victim->cpu_idx) ? me : victim;
    per_cpu_data_t* second = (me->cpu_idx < victim->cpu_idx) ? victim : me;

    acquire_interrupt_lock(&first->lock);
    acquire_interrupt_lock(&second->lock);

    // Steal from the tail of the lowest priority queue
    struct list_node* stolen_node = nullptr;

    for (int p = MLFQ_LEVELS - 1; p >= 0; --p) {
        if (!list_empty(&victim->queues[p])) {
            stolen_node = victim->queues[p].prev;

            // Don't steal if it's the only thread running there
            if (stolen_node == &victim->queues[p]) {
                continue;
            }

            if (stolen_node == &victim->curr_thread->sched_node) {
                continue;
            }

            // Detach from victim
            list_remove(stolen_node);

            if (list_empty(&victim->queues[p])) {
                victim->active_queues_bitmap &= ~(1u << p);
            }

            victim->thread_count--;
            break;
        }
    }

    if (stolen_node) {
        thread_t* t = container_of(stolen_node, thread_t, sched_node);

        t->assigned_cpu = me->cpu_idx;

        list_push_back(&me->queues[t->priority], &t->sched_node);
        me->active_queues_bitmap |= (1u << t->priority);

        me->thread_count++;

        KLOG_INFO(
            "SCHED: cpu %zu stole thread %zu from cpu %zu\n",
            me->cpu_idx,
            t->tid,
            victim->cpu_idx
        );
    }

    release_interrupt_lock(&second->lock);
    release_interrupt_lock(&first->lock);
}

static void
save_current_thread_state(per_cpu_data_t* cpu, thread_t* curr, interrupt_trapframe_t* tf) {
    if (curr && curr != cpu->idle_thread) {
        if (tf) {
            curr->tf = *tf;
        }

        if (curr->state == THREAD_RUNNING) {
            curr->ticks_remaining--;

            bool expired = (curr->ticks_remaining <= 0);

            if (expired) {
                int p = curr->priority;

                if (p < MLFQ_LEVELS - 1) {
                    curr->priority++;
                }

                curr->ticks_remaining = get_timer_slice(curr->priority);
            }

            curr->state = THREAD_READY;

            if (curr->priority >= MLFQ_LEVELS) {
                curr->priority = MLFQ_LEVELS - 1;
            }

            list_push_back(&cpu->queues[curr->priority], &curr->sched_node);
            cpu->active_queues_bitmap |= (1u << curr->priority);
        }
    }
}

static void boost_queues_if_needed(per_cpu_data_t* cpu) {
    cpu->ticks_since_boost++;

    if (cpu->ticks_since_boost >= BOOST_THRESHOLD) {
        cpu->ticks_since_boost = 0;

        uint32_t boost_mask = cpu->active_queues_bitmap & ~1u;

        while (boost_mask) {
            int p = ctz(boost_mask);

            struct list_node* src  = &cpu->queues[p];
            struct list_node* dest = &cpu->queues[0];

            while (!list_empty(src)) {
                struct list_node* node = src->next;
                list_remove(node);

                thread_t* t        = container_of(node, thread_t, sched_node);
                t->priority        = 0;
                t->ticks_remaining = get_timer_slice(0);

                list_push_back(dest, node);
            }

            boost_mask &= ~(1u << p);
            cpu->active_queues_bitmap &= ~(1u << p);
        }

        if (!list_empty(&cpu->queues[0])) {
            cpu->active_queues_bitmap |= 1u;
        }
    }
}

static void balance_load_if_needed(void) {
    if (++balance_counter >= LOAD_BALANCE_INTERVAL) {
        balance_counter = 0;
        balance_load();
    }
}

static thread_t* select_next_thread(per_cpu_data_t* cpu) {
    int next_q = get_highest_priority_queue(cpu->active_queues_bitmap);

    if (next_q == -1) {
        return nullptr;
    }

    struct list_node* node = cpu->queues[next_q].next;

    list_remove(node);
    node->next = nullptr;
    node->prev = nullptr;

    if (list_empty(&cpu->queues[next_q])) {
        cpu->active_queues_bitmap &= ~(1u << next_q);
    }

    return container_of(node, thread_t, sched_node);
}

static void
switch_to_thread(per_cpu_data_t* cpu, thread_t* curr, thread_t* next, interrupt_trapframe_t* tf) {
    if (!next) {
        next = cpu->idle_thread;
    }

    if (!next) {
        PANIC("SCHEDULER: No threads and no idle thread!");
    }

    if (curr == next) {
        curr->state = THREAD_RUNNING;

        release_interrupt_lock(&cpu->lock);
        return;
    }

    cpu->curr_thread = next;
    next->state      = THREAD_RUNNING;

    if (next->owner && next->owner->map.phys_root) {
        uintptr_t next_cr3 = next->owner->map.phys_root;

        if (read_cr3() != next_cr3) {
            write_cr3(next_cr3);
        }
    }

#ifdef __x86_64__
    update_tss_rsp0(&cpu->tss, next->kernel_stack_top);
#endif

    thread_save_fpu(curr);
    thread_restore_fpu(next);

    release_interrupt_lock(&cpu->lock);

    arch_switch_context(
        (switch_context_t**)&curr->context_rsp,
        (switch_context_t*)next->context_rsp
    );

    if (tf) {
        *tf = curr->tf;
    }
}

void scheduler_handler(interrupt_trapframe_t* tf) {
    per_cpu_data_t* cpu = smp_current_core();

    if (!cpu) {
        errno = ENODEV;
        KLOG_ERROR("SCHED: handler called with no CPU context\n");
        return;
    }

    acquire_interrupt_lock(&cpu->lock);

    balance_load_if_needed();
    thread_t* curr = cpu->curr_thread;

    save_current_thread_state(cpu, curr, tf);
    boost_queues_if_needed(cpu);

    thread_t* next = select_next_thread(cpu);

    switch_to_thread(cpu, curr, next, tf);
}

void scheduler_block(void) {
    per_cpu_data_t* cpu = smp_current_core();

    acquire_interrupt_lock(&cpu->lock);

    thread_t* curr = cpu->curr_thread;
    curr->state    = THREAD_BLOCKED;

    release_interrupt_lock(&cpu->lock);
    scheduler_yield();
}

void scheduler_unblock(thread_t* t) {
    per_cpu_data_t* cpu = smp_get_core(t->assigned_cpu);

    acquire_interrupt_lock(&cpu->lock);

    if (t->state == THREAD_BLOCKED || t->state == THREAD_SLEEPING) {
        t->state = THREAD_READY;

        list_push_back(&cpu->queues[t->priority], &t->sched_node);
        cpu->active_queues_bitmap |= (1u << t->priority);
    }

    release_interrupt_lock(&cpu->lock);
}

void scheduler_sleep(size_t ms) {
    per_cpu_data_t* cpu = smp_current_core();
    thread_t* curr      = cpu->curr_thread;

    timer_arm_oneshot(&cpu->timer_manager, &curr->sleep_timer, ms, sleep_callback, curr);

    acquire_interrupt_lock(&cpu->lock);
    curr->state = THREAD_SLEEPING;
    release_interrupt_lock(&cpu->lock);

    scheduler_yield();
}

bool scheduler_is_initialized(void) {
    return initialized;
}

process_t* get_kernel_process(void) {
    return kernel_proc;
}