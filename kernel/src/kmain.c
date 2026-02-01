#include "arch.h"
#include "cpu/smp.h"
#include "drivers/drivers.h"
#include "drivers/loader.h"
#include "drivers/timer.h"
#include "libs/log.h"
#include "memory/memory.h"
#include "sched/rcu.h"
#include "sched/scheduler.h"

static volatile bool srcu_reader_active = false;
static volatile bool qsbr_worker_active = false;
static volatile int callback_run_count  = 0;

static void test_callback_func(struct rcu_head*) {
    atomic_fetch_add((atomic_int*)&callback_run_count, 1);
    KLOG_INFO("TEST: Callback executed on CPU %u\n", smp_current_core()->cpu_idx);
}

static void srcu_reader_thread(void*) {
    KLOG_INFO("TEST: SRCU Reader starting...\n");

    int idx            = srcu_read_lock(&g_srcu);
    srcu_reader_active = true;

    KLOG_INFO("TEST: SRCU Reader holding lock for 1s...\n");
    scheduler_sleep(1000);

    srcu_reader_active = false;
    srcu_read_unlock(&g_srcu, idx);

    KLOG_INFO("TEST: SRCU Reader finished.\n");
}

static void test_srcu(void) {
    KLOG_INFO("TEST: --- Starting SRCU Grace Period Check ---\n");
    callback_run_count = 0;

    thread_create_args_t args = {
        .proc   = get_kernel_process(),
        .entry  = srcu_reader_thread,
        .arg    = nullptr,
        .policy = SCHED_NORMAL
    };

    thread_t* t = thread_create(&args);
    scheduler_add_thread(t);

    while (!srcu_reader_active) {
        scheduler_sleep(10);
    }

    static struct rcu_head cb_node;
    call_srcu(&cb_node, test_callback_func);

    uint64_t start = timer_get_time();

    KLOG_INFO("TEST: Main thread calling synchronize_srcu()...\n");
    synchronize_srcu(&g_srcu);

    uint64_t end     = timer_get_time();
    uint64_t elapsed = (end - start) / 1000 / 1000;

    KLOG_INFO("TEST: synchronize_srcu returned after %lu ms\n", elapsed);
}

static void qsbr_worker_thread(void*) {
    qsbr_enter(&g_qsbr);
    qsbr_worker_active = true;

    KLOG_INFO("TEST: QSBR Worker Online (Holding Epoch).\n");

    scheduler_sleep(1000);

    KLOG_INFO("TEST: QSBR Worker Checkpointing...\n");
    qsbr_checkpoint(&g_qsbr);

    scheduler_sleep(1000);

    qsbr_worker_active = false;
    qsbr_exit(&g_qsbr);
}

static void test_qsbr(void) {
    KLOG_INFO("TEST: --- Starting QSBR Grace Period Check ---\n");
    callback_run_count = 0;

    thread_create_args_t args = {
        .proc   = get_kernel_process(),
        .entry  = qsbr_worker_thread,
        .arg    = nullptr,
        .policy = SCHED_NORMAL
    };

    thread_t* t = thread_create(&args);
    scheduler_add_thread(t);

    while (!qsbr_worker_active) {
        scheduler_sleep(10);
    }

    static struct rcu_head cb_node;
    call_qsbr(&cb_node, test_callback_func);

    uint64_t start = timer_get_time();

    KLOG_INFO("TEST: Main thread calling synchronize_qsbr()...\n");
    synchronize_qsbr(&g_qsbr);

    uint64_t end     = timer_get_time();
    uint64_t elapsed = (end - start) / 1000 / 1000;

    KLOG_INFO("TEST: synchronize_qsbr returned after %lu ms\n", elapsed);
}

static void rcu_torture_test(void) {
    test_srcu();

    scheduler_sleep(500);

    test_qsbr();
}

// NOLINTNEXTLINE(misc-use-internal-linkage)
void kmain(void) {
    arch_serial_init();

    memory_init();
    smp_init();

    drivers_init();
    scheduler_init();

    KLOG_INFO("Hello, World!\n");
    rcu_torture_test();
    launch_user_init();

    arch_halt(true);
}