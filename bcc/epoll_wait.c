#include <uapi/linux/ptrace.h>
#define KBUILD_MODNAME "foo"
#include <linux/tcp.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>
// #include <linux/netdevice.h>
#include <linux/eventpoll.h>


// paramater
#define PARAM_PID 0
// #define PARAM_SPORT 0
// #define PARAM_DPORT 0
// #define PARAM_ENABLE_IPV6 0
// #define PARAM_IPV4_SADDR 0x0
// #define PARAM_IPV4_DADDR 0x0
#define PARAM_TID 0
#define PARAM_EPOLL_FD 0




BPF_PERF_OUTPUT(output_events);
BPF_STACK_TRACE(stack_traces, 8192);

#define FUNCTION_NAME_LEN 48

// 64 + 32 = 96 bytes
struct data_common {
    // struct data_common
    u32 type;
    u32 blank;
    u64 ts_us;
    char task[TASK_COMM_LEN]; // 16 
    char function[FUNCTION_NAME_LEN]; // 48
    u32 pid;
    u32 tid;
    u32 blank1;
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
        return 0;

    output_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}



struct epoll_wait_entry_data {
    int epfd;
    int blank;
    void* events;
    int maxevents;
    int timeout;
    u64 enter_time;
    u32 enter_ep_poll;
    u32 exit_ep_poll;
};

BPF_HASH(epoll_wait_current, u32, struct epoll_wait_entry_data);


struct epoll_wait_enter_output_data {
    struct data_common common;
    int epfd;
    int blank;
    void* events;
    int maxevents;
    int timeout;
};


// /sys/kernel/debug/tracing/events/syscalls/sys_enter_epoll_pwait
TRACEPOINT_PROBE(syscalls, sys_enter_epoll_pwait)
{
    u64 ts_us = bpf_ktime_get_ns() / 1000;
    struct pt_regs* ctx = (struct pt_regs*)args;
    int epfd = args->epfd;
    void* events = args->events;
    int maxevents = args->maxevents;
    int timeout = args->timeout;
    u32 shift_tid = get_shift_tid();
    

    struct epoll_wait_enter_output_data data = {.common.type = 3};
    if  (process_data_common((struct data_common*)&data, "syscalls:sys_enter_epoll_pwait", true) < 0)
        return 0;

    if  (PARAM_EPOLL_FD != 0 && epfd != PARAM_EPOLL_FD)
        return 0;

    data.epfd = epfd;
    data.events = events;
    data.maxevents = maxevents;
    data.timeout = timeout;

    output_events.perf_submit(ctx, &data, sizeof(data));

    struct epoll_wait_entry_data entry_data = {
        .epfd = epfd,
        .blank = 0,
        .events = events,
        .maxevents = maxevents,
        .timeout = timeout,
        .enter_time = ts_us,
        .enter_ep_poll = 0,
        .exit_ep_poll = 0,
    };

    epoll_wait_current.update(&shift_tid, &entry_data);

    return 0;
}



struct epoll_wait_exit_output_data {
    struct data_common common;

    // struct epoll_wait_output_data
    int epfd;
    int ret;
    void* events;
    int maxevents;
    int timeout;
    u64 enter_time;
    u64 exit_time;
    u32 enter_ep_poll;
    u32 exit_ep_poll;
};


TRACEPOINT_PROBE(syscalls, sys_exit_epoll_pwait)
{
    u64 ts_us = bpf_ktime_get_ns() / 1000;
    struct pt_regs* ctx = (struct pt_regs*)args;
    int ret = args->ret;
    // // return 
    // process_data_common(ctx, "syscalls:sys_exit_epoll_pwait");

    
    u32 shift_tid = get_shift_tid();
    struct epoll_wait_entry_data* entry_data = epoll_wait_current.lookup(&shift_tid);
    if  (entry_data)
    {
        struct epoll_wait_exit_output_data data = {.common.type = 4};
        if  (process_data_common(&data.common, "syscalls:sys_exit_epoll_pwait", true) < 0)
            return 0;

        if  (PARAM_EPOLL_FD != 0 && entry_data->epfd != PARAM_EPOLL_FD)
            return 0;

        data.epfd = entry_data->epfd;
        data.ret = ret;
        data.events = entry_data->events;
        data.maxevents = entry_data->maxevents;
        data.timeout = entry_data->timeout;
        data.enter_time = entry_data->enter_time;
        data.exit_time = ts_us;
        data.enter_ep_poll = entry_data->enter_ep_poll;
        data.exit_ep_poll = entry_data->exit_ep_poll;

        output_events.perf_submit(ctx, &data, sizeof(data));

        epoll_wait_current.delete(&shift_tid);
    }

    return 0;
}



static int process_epoll_wait_context(struct pt_regs* ctx, const char* func)
{
    u32 shift_tid = get_shift_tid();
    struct epoll_wait_entry_data* entry_data = epoll_wait_current.lookup(&shift_tid);
    if  (entry_data)
    {
        if  (PARAM_EPOLL_FD != 0 && entry_data->epfd != PARAM_EPOLL_FD)
            return 0;
        return submit_data_common(ctx, func);
    }

    return 0;

    // return submit_data_common(ctx, func);
}

int kprobe__ep_poll(struct pt_regs* ctx,
    struct eventpoll *ep, struct epoll_event __user *events,
	int maxevents, long timeout)
{
    // u32 shift_tid = get_shift_tid();
    // struct epoll_wait_entry_data* entry_data = epoll_wait_current.lookup(&shift_tid);
    // if  (entry_data)
    // {
    //     // return submit_data_common(ctx, func);
    //     entry_data->enter_ep_poll = 1;
    // }

    return process_epoll_wait_context(ctx, "kprobe:ep_poll");
}

// int kretprobe__ep_poll(struct pt_regs* ctx)
// {
//     // u32 shift_tid = get_shift_tid();
//     // struct epoll_wait_entry_data* entry_data = epoll_wait_current.lookup(&shift_tid);
//     // if  (entry_data)
//     // {
//     //     // return submit_data_common(ctx, func);
//     //     entry_data->exit_ep_poll = 1;
//     // }

//     return process_epoll_wait_context(ctx, "kretprobe:ep_poll");
// }


int kprobe__schedule_hrtimeout_range(struct pt_regs* ctx,
        ktime_t *expires, u64 delta, const enum hrtimer_mode mode)
{
    return process_epoll_wait_context(ctx, "kprobe:schedule_hrtimeout_range");    
}

// int kretprobe__schedule_hrtimeout_range(struct pt_regs* ctx)
// {
//     return process_epoll_wait_context(ctx, "kretprobe:schedule_hrtimeout_range");
// }


int kprobe__finish_task_switch(struct pt_regs* ctx, struct task_struct *prev)
{
    return process_epoll_wait_context(ctx, "kprobe:finish_task_switch");
}


// int kprobe__ep_scan_ready_list(struct pt_regs* ctx,
//         struct eventpoll *ep,
// 			      __poll_t (*sproc)(struct eventpoll *,
// 					   struct list_head *, void *),
// 			      void *priv, int depth, bool ep_locked)
// {
//     u64 ts_us = bpf_ktime_get_ns() / 1000;

//     u32 shift_tid = get_shift_tid();
//     struct epoll_wait_entry_data* entry_data = epoll_wait_current.lookup(&shift_tid);
//     if  (entry_data)
//     {
//         return submit_data_common(ctx, "kprobe:ep_scan_ready_list");
//     }

//     return 0;
// }


// int kretprobe__ep_scan_ready_list(struct pt_regs* ctx)
// {
//         u64 ts_us = bpf_ktime_get_ns() / 1000;

//     u32 shift_tid = get_shift_tid();
//     struct epoll_wait_entry_data* entry_data = epoll_wait_current.lookup(&shift_tid);
//     if  (entry_data)
//     {
//         return submit_data_common(ctx, "kprobe:ep_scan_ready_list");
//     }

//     return 0;

// }



int kprobe__ep_send_events_proc(struct pt_regs* ctx, struct eventpoll *ep, 
        struct list_head *head, void *priv)
{
    return process_epoll_wait_context(ctx, "kprobe:ep_send_events_proc");
}

struct ep_send_events_proc_exit_data {
    struct data_common common;
    int ret;
};

int kretprobe__ep_send_events_proc(struct pt_regs* ctx)
{
    int ret = PT_REGS_RC(ctx);
    u32 shift_tid = get_shift_tid();
    struct epoll_wait_entry_data* entry_data = epoll_wait_current.lookup(&shift_tid);
    if  (entry_data)
    {
        struct ep_send_events_proc_exit_data data = {.common.type = 5};
        if  (process_data_common(&data.common, "kretprobe:ep_send_events_proc", true) < 0)
            return 0;

        data.ret = ret;

        output_events.perf_submit(ctx, &data, sizeof(data));
    }

    return 0;
}


int kprobe__ep_read_events_proc(struct pt_regs* ctx, 
        struct eventpoll *ep, struct list_head *head, void *priv)
{
    return process_epoll_wait_context(ctx, "kprobe:ep_read_events_proc");
}

// int kretprobe__ep_read_events_proc(struct pt_regs* ctx)
// {
//     return process_epoll_wait_context(ctx, "kretprobe:ep_read_events_proc");
// }




