#include <uapi/linux/ptrace.h>
#define KBUILD_MODNAME "foo"
#include <linux/tcp.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>


// paramater
#define PARAM_PID 0
#define PARAM_SPORT 0
#define PARAM_DPORT 0
// #define PARAM_ENABLE_IPV6 0
#define PARAM_IPV4_SADDR 0x0
#define PARAM_IPV4_DADDR 0x0

#define FUNCTION_NAME_LEN 32



// 64 bytes
struct data_common {
    // struct data_common
    u32 type;
    u32 pid;
    u64 ts_us;
    char task[TASK_COMM_LEN]; // 16 
    char function[FUNCTION_NAME_LEN]; // 32
};



BPF_PERF_OUTPUT(tcp4_data_events);
BPF_STACK_TRACE(stack_traces, 8192);

static int process_data_common(struct pt_regs* ctx, const char* func)
{
    struct data_common data = {.type = 5};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts_us = bpf_ktime_get_ns() / 1000;
    bpf_get_current_comm(&data.task, sizeof(data.task));
    strcpy(data.function, func);

    tcp4_data_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}



struct net_tx_action_expire_data {
    // struct data_common
    u32 type;
    u32 pid;
    u64 ts_us;
    char task[TASK_COMM_LEN]; // 16 
    char function[FUNCTION_NAME_LEN]; // 32
    // struct qdisc_run_expire_data
    u64 cpu_id;
    // u64 expire_time;
    u64 last_us;
    u64 expire_us;
};

BPF_PERCPU_ARRAY(net_tx_action_expire_time, u64, 1);

int kprobe__net_tx_action(struct pt_regs * ctx,
        struct softirq_action *h)
{
    u64 cpu_id = bpf_get_smp_processor_id();
    u64 now_us = bpf_ktime_get_ns() / 1000;
    
    int index = 0;
    u64* last_us_p = net_tx_action_expire_time.lookup(&index);
    if  (last_us_p != 0)
    {
        u64 last_us = *last_us_p;
        u64 expire_us = now_us - last_us;

        // if  (last_us != 0 && expire_time > net_tx_action_expire_bound)
        {
            struct net_tx_action_expire_data data = {.type = 7};

            data.pid = bpf_get_current_pid_tgid() >> 32;
            data.ts_us = now_us;
            bpf_get_current_comm(&data.task, sizeof(data.task));
            strcpy(data.function, "kprobe:net_tx_action"); 

            data.cpu_id = cpu_id;
            data.last_us = last_us;
            data.expire_us = expire_us;

            tcp4_data_events.perf_submit(ctx, &data, sizeof(data));
        }
    }

    net_tx_action_expire_time.update(&index, &now_us);
    return 0;
}


// int kprobe__net_tx_action(struct pt_regs * ctx,
//         struct softirq_action *h)
// {
//     return process_data_common(ctx, "kprobe:net_tx_action");
// }