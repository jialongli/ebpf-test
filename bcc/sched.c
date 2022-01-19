#include <uapi/linux/ptrace.h>
#define KBUILD_MODNAME "foo"
#include <linux/tcp.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/netdevice.h>



// paramater
#define PARAM_PID 0
#define PARAM_TID 0

#define PARAM_SPORT 0
#define PARAM_DPORT 0

#define PARAM_DISABLE_IPV4 0
#define PARAM_IPV4_SADDR 0x0
#define PARAM_IPV4_DADDR 0x0

#define PARAM_ENABLE_IPV6 0
#define PARAM_IPV6_SADDR 0x0
#define PARAM_IPV6_DADDR 0x0



#define container_of_internal(ptr, type, member) ({          \
	const typeof(((type *)0)->member)*__mptr = (ptr);    \
		     (type *)((char *)__mptr - offsetof(type, member)); })

#define from_timer_internal(var, callback_timer, timer_fieldname) \
	container_of_internal(callback_timer, typeof(*var), timer_fieldname)


BPF_PERF_OUTPUT(output_events);
BPF_STACK_TRACE(stack_traces, 8192);

#define FUNCTION_NAME_LEN 48

// 64 + 32 = 96 bytes
struct data_common { // type = 1
    u32 type; 
    u32 blank;
    u64 ts_us;
    char task[TASK_COMM_LEN]; // 16 
    char function[FUNCTION_NAME_LEN]; // 48
    u32 pid;
    u32 tid;
    u32 cpu_id;
    u32 blank2;
};


#define MAX_SUPPORTED_CPUS 0x100
static u32 get_shift_tid()
{
    u32 tid = bpf_get_current_pid_tgid();

    if  (tid == 0)
        return bpf_get_smp_processor_id();
    else
        return tid + MAX_SUPPORTED_CPUS;
}



static int process_data_common(struct data_common* data, const char* func, bool check)
{
    data->ts_us = bpf_ktime_get_ns() / 1000;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data->pid = pid_tgid >> 32;
    data->tid = pid_tgid;

    data->cpu_id = bpf_get_smp_processor_id();
    if  (data->cpu_id != 0)
        return -1;

    if  (check && PARAM_PID != 0 && data->pid != PARAM_PID)
        return -1;

    if  (check && PARAM_TID != 0 && data->tid != PARAM_TID)
        return -1;

    bpf_get_current_comm(&data->task, sizeof(data->task));
    strcpy(data->function, func);

    return 0;
}

static int submit_data_common(struct pt_regs* ctx, const char* func)
{
    struct data_common data = {.type = 1};

    if  (process_data_common(&data, func, true) < 0)
        return -1;

    output_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


// union inet_addrs {
//     struct {
//         u32 saddr;
//         u32 daddr;
//     }ipv4;
//     struct {
//         u8 saddr[16];
//         u8 daddr[16];
//     }ipv6;
// };


// struct tcp_data { // type = 2
//     struct data_common common;
//     u16 sport;
//     u16 dport;   
//     short state;
//     short family;
//     union inet_addrs addrs;
// };


// static int process_tcp_data(struct sock* sk, struct tcp_data* data, const char* func)
// {
//     if  (process_data_common(&data->common, func, true) < 0)
//         return -1;

//     u16 sport = sk->__sk_common.skc_num;
//     u16 dport = sk->__sk_common.skc_dport;
//     dport = ntohs(dport);
    
//     if  (PARAM_SPORT != 0 && sport != PARAM_SPORT)
//         return -1;

//     if  (PARAM_DPORT != 0 && dport != PARAM_DPORT)
//         return -1;

//     data->sport = sport;
//     data->dport = dport;

    
//     u16 family = sk->__sk_common.skc_family;
//     data->family = family;

//     if  (family == AF_INET)
//     {
//         if  (PARAM_DISABLE_IPV4)
//             return -1;

//         u32 saddr = sk->__sk_common.skc_rcv_saddr;
//         u32 daddr = sk->__sk_common.skc_daddr;

//         if  (PARAM_IPV4_SADDR != 0 && saddr != PARAM_IPV4_SADDR)
//             return -1;

//         if  (PARAM_IPV4_DADDR != 0 && daddr != PARAM_IPV4_DADDR)
//             return -1;

//         data->addrs.ipv4.saddr = saddr;
//         data->addrs.ipv4.daddr = daddr;
//     }
//     else if  (family == AF_INET6)
//     {
//         if  (!PARAM_ENABLE_IPV6)
//             return -1;

//         // ipv6 addr has no filter now.
//         // bpf_probe_read_kernel(void *dst, int size, const void *src)
//         if  (bpf_probe_read(data->addrs.ipv6.saddr, 16, &sk->__sk_common.skc_v6_rcv_saddr) < 0)
//             return -1;

//         if  (bpf_probe_read(data->addrs.ipv6.daddr, 16, &sk->__sk_common.skc_v6_daddr) < 0)
//             return -1;
//     }
//     else 
//         return -1;
    

//     data->state = sk->__sk_common.skc_state;
//     return 0;
// }

// static int submit_tcp_data(struct sock* sk, struct pt_regs* ctx, const char* func)
// {
//     struct tcp_data data = {.common.type = 2};

//     if  (process_tcp_data(sk, &data, func) < 0)
//         return -1;
    
//     output_events.perf_submit(ctx, &data, sizeof(data));
//     return 0;
// }

// struct tcp_sock_data { // type = 3
//     struct tcp_data tcp_common; 
//     // 
//     u32 pred_flags;
//     u8  is_cwnd_limited_flag;
//     u8  blank;
//     u16 blank1;
//     u64 bytes_acked;
//     u64 bytes_received;
//     u32 snd_una;
//     u32 snd_nxt;
//     u32 snd_wnd;
//     u32 write_seq;
//     // u32 blank2;
//     u32 srtt_us;
//     u32 inflight_packets;
//     u32 snd_cwnd;
//     u32 copied_seq;
//     u32 rcv_nxt;
//     u32 rcv_wnd;
// };


// static int process_tcp_sock_data(struct sock* sk, struct tcp_sock_data* data, const char* func)
// {
//     if  (process_tcp_data(sk, &data->tcp_common, func) < 0)
//         return -1;

//     struct tcp_sock* tp = (struct tcp_sock*)sk;
//     data->pred_flags = tp->pred_flags;
//     data->is_cwnd_limited_flag = *((u8*)(&tp->repair_queue) + 1);
//     data->inflight_packets = tp->packets_out - (tp->sacked_out + tp->lost_out) + tp->retrans_out;
//     data->snd_cwnd = tp->snd_cwnd;
//     data->bytes_acked = tp->bytes_acked;
//     data->bytes_received = tp->bytes_received;
//     data->snd_una = tp->snd_una;
//     data->snd_nxt = tp->snd_nxt;
//     data->snd_wnd = tp->snd_wnd;
//     data->write_seq = tp->write_seq;
//     data->copied_seq = tp->copied_seq;
//     data->rcv_nxt = tp->rcv_nxt;
//     data->rcv_wnd = tp->rcv_wnd;
//     data->srtt_us = tp->srtt_us >> 3;

//     return 0;
// }

// static int submit_tcp_sock_data(struct sock* sk, struct pt_regs* ctx, const char* func)
// {
//     struct tcp_sock_data data = {.tcp_common.common.type = 3};

//     if  (process_tcp_sock_data(sk, &data, func) < 0)
//         return -1;

//     output_events.perf_submit(ctx, &data, sizeof(data));
//     return 0;
// }





// struct tcp_data_with_two_args { // type = 6
//     struct tcp_data tcp_common;
//     int arg1;
//     int arg2;
// };

// static int process_tcp_data_with_two_args(struct sock* sk, 
//         struct tcp_data_with_two_args* data, const char* func,
//         int arg1, int arg2)
// {
//     if  (process_tcp_data(sk, &data->tcp_common, func) < 0)
//         return -1;

//     data->arg1 = arg1;
//     data->arg2 = arg2;
//     return 0;
// }

// static int submit_tcp_data_with_two_args(struct sock* sk,
//         struct pt_regs* ctx, const char* func,
//         int arg1, int arg2)
// {
//     struct tcp_data_with_two_args data = {.tcp_common.common.type = 6};
    
//     if  (process_tcp_data_with_two_args(sk, &data, func, arg1, arg2) < 0)
//         return -1;

//     output_events.perf_submit(ctx, &data, sizeof(data));
//     return 0;
// }


// ----------------------------------------------------------------------------------


// TRACEPOINT_PROBE(irq_vectors, local_timer_entry)
// {
//     struct pt_regs *ctx = (struct pt_regs *)args;

//     submit_data_common(ctx, "trace:irq_vectors:local_timer_entry");

//     return 0;
// }


// TRACEPOINT_PROBE(irq_vectors, local_timer_exit)
// {
//     struct pt_regs *ctx = (struct pt_regs *)args;

//     submit_data_common(ctx, "trace:irq_vectors:local_timer_exit");

//     return 0;
// }





// kthread  ------------------------------------------------------

TRACEPOINT_PROBE(sched, sched_kthread_stop)
{
    struct pt_regs *ctx = (struct pt_regs *)args;

    submit_data_common(ctx, "trace:sched:sched_kthread_stop");

    return 0;
}


TRACEPOINT_PROBE(sched, sched_kthread_stop_ret)
{
    struct pt_regs *ctx = (struct pt_regs *)args;

    submit_data_common(ctx, "trace:sched:sched_kthread_stop_ret");

    return 0;
}




// process  ------------------------------------------------------

TRACEPOINT_PROBE(sched, sched_process_exec)
{
    struct pt_regs *ctx = (struct pt_regs *)args;

    submit_data_common(ctx, "trace:sched:sched_process_exec");

    return 0;
}


TRACEPOINT_PROBE(sched, sched_process_exit)
{
    struct pt_regs *ctx = (struct pt_regs *)args;

    submit_data_common(ctx, "trace:sched:sched_process_exit");

    return 0;
}


TRACEPOINT_PROBE(sched, sched_process_free)
{
    struct pt_regs *ctx = (struct pt_regs *)args;

    submit_data_common(ctx, "trace:sched:sched_process_free");

    return 0;
}


TRACEPOINT_PROBE(sched, sched_process_hang)
{
    struct pt_regs *ctx = (struct pt_regs *)args;

    submit_data_common(ctx, "trace:sched:sched_process_hang");

    return 0;
}


TRACEPOINT_PROBE(sched, sched_process_wait)
{
    struct pt_regs *ctx = (struct pt_regs *)args;

    submit_data_common(ctx, "trace:sched:sched_process_wait");

    return 0;
}



// stat ------------------------------------------------------

// TRACEPOINT_PROBE(sched, sched_stat_blocked)
// {
//     struct pt_regs *ctx = (struct pt_regs *)args;

//     submit_data_common(ctx, "trace:sched:sched_stat_blocked");

//     return 0;
// }


// TRACEPOINT_PROBE(sched, sched_stat_iowait)
// {
//     struct pt_regs *ctx = (struct pt_regs *)args;

//     submit_data_common(ctx, "trace:sched:sched_stat_iowait");

//     return 0;
// }


// TRACEPOINT_PROBE(sched, sched_stat_runtime)
// {
//     struct pt_regs *ctx = (struct pt_regs *)args;

//     submit_data_common(ctx, "trace:sched:sched_stat_runtime");

//     return 0;
// }


// TRACEPOINT_PROBE(sched, sched_stat_sleep)
// {
//     struct pt_regs *ctx = (struct pt_regs *)args;

//     submit_data_common(ctx, "trace:sched:sched_stat_sleep");

//     return 0;
// }


// TRACEPOINT_PROBE(sched, sched_stat_wait)
// {
//     struct pt_regs *ctx = (struct pt_regs *)args;

//     submit_data_common(ctx, "trace:sched:sched_stat_wait");

//     return 0;
// }








// numa  ------------------------------------------------

// TRACEPOINT_PROBE(sched, sched_move_numa)
// {
//     struct pt_regs *ctx = (struct pt_regs *)args;

//     submit_data_common(ctx, "trace:sched:sched_move_numa");

//     return 0;
// }


// TRACEPOINT_PROBE(sched, sched_stick_numa)
// {
//     struct pt_regs *ctx = (struct pt_regs *)args;

//     submit_data_common(ctx, "trace:sched:sched_stick_numa");

//     return 0;
// }


// TRACEPOINT_PROBE(sched, sched_swap_numa)
// {
//     struct pt_regs *ctx = (struct pt_regs *)args;

//     submit_data_common(ctx, "trace:sched:sched_swap_numa");

//     return 0;
// }




// migrate_task ------------------------------------------------

TRACEPOINT_PROBE(sched, sched_migrate_task)
{
    struct pt_regs *ctx = (struct pt_regs *)args;

    submit_data_common(ctx, "trace:sched:sched_migrate_task");

    return 0;
}


// switch  ------------------------------------------------


TRACEPOINT_PROBE(sched, sched_switch)
{
    struct pt_regs *ctx = (struct pt_regs *)args;

    submit_data_common(ctx, "trace:sched:sched_switch");

    return 0;
}

// wait_task  ------------------------------------------------

TRACEPOINT_PROBE(sched, sched_wait_task)
{
    struct pt_regs *ctx = (struct pt_regs *)args;

    submit_data_common(ctx, "trace:sched:sched_wait_task");

    return 0;
}


// wake  ------------------------------------------------

TRACEPOINT_PROBE(sched, sched_wake_idle_without_ipi)
{
    struct pt_regs *ctx = (struct pt_regs *)args;

    submit_data_common(ctx, "trace:sched:sched_wake_idle_without_ipi");

    return 0;
}


TRACEPOINT_PROBE(sched, sched_wakeup)
{
    struct pt_regs *ctx = (struct pt_regs *)args;

    submit_data_common(ctx, "trace:sched:sched_wakeup");

    return 0;
}


TRACEPOINT_PROBE(sched, sched_wakeup_new)
{
    struct pt_regs *ctx = (struct pt_regs *)args;

    submit_data_common(ctx, "trace:sched:sched_wakeup_new");

    return 0;
}

TRACEPOINT_PROBE(sched, sched_waking)
{
    struct pt_regs *ctx = (struct pt_regs *)args;

    submit_data_common(ctx, "trace:sched:sched_waking");

    return 0;
}






// sched_pi_setprio ----------------------------------------------

TRACEPOINT_PROBE(sched, sched_pi_setprio)
{
    struct pt_regs *ctx = (struct pt_regs *)args;

    submit_data_common(ctx, "trace:sched:ssched_pi_setprio");

    return 0;
}











// TRACEPOINT_PROBE(sched, sched_switch)
// {
//     struct pt_regs *ctx = (struct pt_regs *)args;

//     submit_data_common(ctx, "trace:sched:sched_switch");

//     return 0;
// }


