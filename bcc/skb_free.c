#include <uapi/linux/ptrace.h>
#define KBUILD_MODNAME "foo"
#include <linux/tcp.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>



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
        return -1;

    output_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


union inet_addrs {
    struct {
        u32 saddr;
        u32 daddr;
    }ipv4;
    struct {
        u8 saddr[16];
        u8 daddr[16];
    }ipv6;
};


struct sock_data { // type = 2
    struct data_common common;
    u16 sport;
    u16 dport;   
    short state;
    short family;
    union inet_addrs addrs;
};


static int process_sock_data(struct sock* sk, struct sock_data* data, const char* func)
{
    if  (process_data_common(&data->common, func, true) < 0)
        return -1;

    u16 sport = sk->__sk_common.skc_num;
    u16 dport = sk->__sk_common.skc_dport;
    dport = ntohs(dport);
    
    if  (PARAM_SPORT != 0 && sport != PARAM_SPORT)
        return -1;

    if  (PARAM_DPORT != 0 && dport != PARAM_DPORT)
        return -1;

    data->sport = sport;
    data->dport = dport;

    
    u16 family = sk->__sk_common.skc_family;
    data->family = family;

    if  (family == AF_INET)
    {
        if  (PARAM_DISABLE_IPV4)
            return -1;

        u32 saddr = sk->__sk_common.skc_rcv_saddr;
        u32 daddr = sk->__sk_common.skc_daddr;

        if  (PARAM_IPV4_SADDR != 0 && saddr != PARAM_IPV4_SADDR)
            return -1;

        if  (PARAM_IPV4_DADDR != 0 && daddr != PARAM_IPV4_DADDR)
            return -1;

        data->addrs.ipv4.saddr = saddr;
        data->addrs.ipv4.daddr = daddr;
    }
    else if  (family == AF_INET6)
    {
        if  (!PARAM_ENABLE_IPV6)
            return -1;

        // ipv6 addr has no filter now.
        // bpf_probe_read_kernel(void *dst, int size, const void *src)
        if  (bpf_probe_read(data->addrs.ipv6.saddr, 16, &sk->__sk_common.skc_v6_rcv_saddr) < 0)
            return -1;

        if  (bpf_probe_read(data->addrs.ipv6.daddr, 16, &sk->__sk_common.skc_v6_daddr) < 0)
            return -1;
    }
    else 
        return -1;
    

    data->state = sk->__sk_common.skc_state;
    return 0;
}

static int submit_sock_data(struct sock* sk, struct pt_regs* ctx, const char* func)
{
    struct sock_data data = {.common.type = 2};

    if  (process_sock_data(sk, &data, func) < 0)
        return -1;
    
    output_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


struct sock_data_with_stack {
    struct sock_data sock;
    u32 stack_id;
    u32 blank;
};

static int submit_sock_data_with_stack(struct sock* sk, struct pt_regs* ctx, const char* func)
{
    struct sock_data_with_stack data = {.sock.common.type = 10};

    if  (process_sock_data(sk, &data.sock, func) < 0)
        return -1;

    data.stack_id = stack_traces.get_stackid(ctx, 0);
    data.blank = 0;

    output_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}



int kprobe____kfree_skb(struct pt_regs* ctx, struct sk_buff *skb)
{
    struct sock* sk = skb->sk;
    submit_sock_data_with_stack(sk, ctx, "kprobe:__kfree_skb");
    
    return 0;
}
