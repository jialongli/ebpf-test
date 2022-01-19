#include <uapi/linux/ptrace.h>
#define KBUILD_MODNAME "foo"
#include <linux/tcp.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>
// #include <linux/netdevice.h>


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


struct sock_data_common {
    // struct data_common
    u32 type;
    u32 pid;
    u64 ts_us;
    char task[TASK_COMM_LEN];
    char function[FUNCTION_NAME_LEN];
    // struct sock_data_common
    u16 sport;
    u16 dport;
};

// separate data structs for ipv4 and ipv6
struct tcp4_data_t {
    // struct _data_common;
    u32 type;
    u32 pid;
    u64 ts_us;
    char task[TASK_COMM_LEN];
    char function[FUNCTION_NAME_LEN];
    // struct sock_data_common
    u16 sport;
    u16 dport;
    // tcp4_data_t
    u32 state;
    u32 saddr;
    u32 daddr;    
};
BPF_PERF_OUTPUT(tcp4_data_events);


struct tcp4_data_stack_t {
    // struct _data_common;
    u32 type;
    u32 pid;
    u64 ts_us;
    char task[TASK_COMM_LEN];
    char function[FUNCTION_NAME_LEN];
    // struct sock_data_common
    u16 sport;
    u16 dport;
    // tcp4_data_t
    u32 state;
    u32 saddr;
    u32 daddr;    
    // tcp4_data_stack_t
    u32 stack_id;
    u32 blank;
};

BPF_STACK_TRACE(stack_traces, 8192);

// struct ipv6_data_t {
//     u64 ts_us;
//     u32 pid;
//     u16 sport;
//     u16 dport;
//     char task[TASK_COMM_LEN];
//     char function[FUNCTION_NAME_LEN];
//     unsigned __int128 saddr;
//     unsigned __int128 daddr;
//     u32 state;
// };
// BPF_PERF_OUTPUT(ipv6_events);



static int process_sock_common(struct sock* sk, struct sock_data_common* data, const char* func)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if  (PARAM_PID != 0 && pid != PARAM_PID)
        return -1;

    if (sk == NULL)
        return -1;

    u16 family = 0, sport = 0, dport = 0;
    family = sk->__sk_common.skc_family;
    sport = sk->__sk_common.skc_num;
    dport = sk->__sk_common.skc_dport;
    dport = ntohs(dport);

    if  (PARAM_SPORT != 0 && sport != PARAM_SPORT)
        return -1;

    if  (PARAM_DPORT != 0 && dport != PARAM_DPORT)
        return -1;

    data->pid = pid;
    data->ts_us = bpf_ktime_get_ns() / 1000;
    
    data->sport = sport;
    data->dport = dport;


    bpf_get_current_comm(&data->task, sizeof(data->task));
    strcpy(data->function, func);


    return 0;
}


static int process_sock_v4_common(struct sock* sk, struct tcp4_data_t* data, const char* func)
{
    if  (process_sock_common(sk, (struct sock_data_common*)data, func) < 0)
        return -1;

    if  (sk->__sk_common.skc_family != AF_INET && sk->__sk_common.skc_family != AF_INET6) 
        return -1;

    data->saddr = sk->__sk_common.skc_rcv_saddr;
    data->daddr = sk->__sk_common.skc_daddr;
    
    if  (PARAM_IPV4_SADDR != 0 && data->saddr != PARAM_IPV4_SADDR)
        return -1;

    if  (PARAM_IPV4_DADDR != 0 && data->daddr != PARAM_IPV4_DADDR)
        return -1;

    data->state = sk->__sk_common.skc_state;
    // data->state = 10;

    return 0;
}


static int process_sock_v4(struct sock* sk, struct pt_regs *ctx, const char* func)
{
    struct tcp4_data_t data = {.type = 1};
    // memset(&data, 0, sizeof(data));

    if  (process_sock_v4_common(sk, &data, func) < 0)
        return 0;

    
    tcp4_data_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


static int process_sock_v4_stack(struct sock* sk, struct pt_regs *ctx, const char* func)
{
    struct tcp4_data_stack_t data = {.type = 4};
    // memset(&data, 0, sizeof(data));

    if  (process_sock_v4_common(sk, (struct tcp4_data_t*)&data, func) < 0)
        return 0;

    data.stack_id = stack_traces.get_stackid(ctx, 0);

    tcp4_data_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


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


#define MAX_SUPPORTED_CPUS 0x100
static u32 get_shifted_tid()
{
    u32 tid = bpf_get_current_pid_tgid();

    if  (tid == 0)
        return bpf_get_smp_processor_id();
    else
        return tid + MAX_SUPPORTED_CPUS;
}


// int kretprobe__inet_csk_accept(struct pt_regs *ctx)
// {
//     struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);

//     return process_sock_v4(newsk, ctx, "kretprobe:inet_csk_accept");
// }


// int kprobe__tcp_rcv_state_process(struct pt_regs *ctx, 
//         struct sock *sk, struct sk_buff *skb)
// {
//     return process_sock_v4(sk, ctx, "kprobe:tcp_rcv_state_process");
// }

// // // int kprobe__tcp_conn_request(struct pt_regs *ctx, struct request_sock_ops *rsk_ops,
// // // 		const struct tcp_request_sock_ops *af_ops, struct sock *sk, struct sk_buff *skb)
// // // {
// // //     return process_sock(sk, ctx, "kprobe:tcp_conn_request");
// // // }


// int kprobe__tcp_check_req(struct pt_regs *ctx, 
//         struct sock *sk, struct sk_buff *skb, struct request_sock *req, 
//         bool fastopen, bool *req_stolen)
// {
//     return process_sock_v4((struct sock*)req, ctx, "kprobe:tcp_check_req");
// }




// int kprobe__tcp_rcv_established(struct pt_regs *ctx, 
//         struct sock *sk, struct sk_buff *skb)
// {
//     return process_sock_v4(sk, ctx, "kprobe:tcp_rcv_established");
// }




// struct tcp4_rcv_established_t {
//     // struct data_common;
//     u32 type;
//     u32 pid;
//     u64 ts_us;
//     char task[TASK_COMM_LEN];
//     char function[FUNCTION_NAME_LEN];
//     // struct sock_data_common
//     u16 sport;
//     u16 dport;
//     // tcp4_data_t
//     u32 state;
//     u32 saddr;
//     u32 daddr;    
//     // tcp4_rcv_established_t, sock
//     u32 pred_flags;
//     // u64 bytes_sent;
//     u32 blank;
//     u64 bytes_acked;
//     u64 bytes_received;
//     u32 snd_una;
//     u32 snd_nxt;
//     u32 snd_wnd;
//     u32 copied_seq;
//     u32 rcv_nxt;
//     u32 rcv_wnd;
//     // tcp4_rcv_established_t, skb
//     u32 seg_seq;
//     u32 seg_len;
//     u32 seg_ack;
//     u16 seg_wnd;
//     u8 seg_doff;
//     u8 tcp_flags;
// };
// // BPF_PERF_OUTPUT(tcp4_rcv_established_events);


// BPF_HASH(tcp_rcv_established_current, u32, struct sock *);


// int kprobe__tcp_rcv_established(struct pt_regs *ctx, 
//         struct sock *sk, struct sk_buff *skb)
// {
//     struct tcp4_rcv_established_t data = {.type = 2};

//     if  (process_sock_v4_common(sk, (struct tcp4_data_t*)&data, "kprobe:tcp_rcv_established") < 0)
//         return 0;

//     struct tcp_sock* tp = (struct tcp_sock*)sk;
//     data.pred_flags = tp->pred_flags;
//     // data.bytes_sent = tp->bytes_sent;
//     // data.bytes_sent = 0;
//     data.bytes_acked = tp->bytes_acked;
//     data.bytes_received = tp->bytes_received;
//     data.snd_una = tp->snd_una;
//     data.snd_nxt = tp->snd_nxt;
//     data.snd_wnd = tp->snd_wnd;
//     data.copied_seq = tp->copied_seq;
//     data.rcv_nxt = tp->rcv_nxt;
//     data.rcv_wnd = tp->rcv_wnd;

//     struct tcphdr* th = (struct tcphdr*)skb->data;
//     u8* th_byte = (u8*)skb->data;
//     data.seg_doff = th_byte[12]  >> 4;
//     data.tcp_flags = th_byte[13];
//     data.seg_seq = th->seq;
//     data.seg_seq = ntohl(data.seg_seq);
//     data.seg_len = skb->len - (data.seg_doff << 2);
//     data.seg_ack = th->ack_seq;
//     data.seg_ack = ntohl(data.seg_ack);
//     data.seg_wnd = th->window;
//     data.seg_wnd = ntohs(data.seg_wnd);

//     u64 pid_tgid = bpf_get_current_pid_tgid();
//     u32 tid = pid_tgid;
//     tcp_rcv_established_current.update(&tid, &sk);

//     // tcp4_rcv_established_events.perf_submit(ctx, &data, sizeof(data));
//     tcp4_data_events.perf_submit(ctx, &data, sizeof(data));
//     return 0;
// }



// int kretprobe__tcp_rcv_established(struct pt_regs* ctx)
// {
//     int ret = PT_REGS_RC(ctx);
//     u64 pid_tgid = bpf_get_current_pid_tgid();
//     u32 tid = pid_tgid;

//     struct sock **skpp;
//     skpp = tcp_rcv_established_current.lookup(&tid);
//     if  (skpp == 0)
//         return 0;   // missed entry

//     struct sock* sk = *skpp;
//     tcp_rcv_established_current.delete(&tid);

//     return process_sock_v4(sk, ctx, "kretprobe:tcp_rcv_established");
// }




// int kprobe____tcp_transmit_skb(struct pt_regs *ctx,  
//         struct sock *sk, struct sk_buff *skb, int clone_it, 
//         gfp_t gfp_mask, u32 rcv_nxt)
// {
//     return process_sock_v4(sk, ctx, "kprobe:tcp_transmit_skb");
// }




// struct tcp4_transmit_skb_t {
//     // struct data_common;
//     u32 type;
//     u32 pid;
//     u64 ts_us;
//     char task[TASK_COMM_LEN];
//     char function[FUNCTION_NAME_LEN];
//     // struct sock_data_common
//     u16 sport;
//     u16 dport;
//     // tcp4_data_t
//     u32 state;
//     u32 saddr;
//     u32 daddr;
//     // tcp4_rcv_established_t, sock
//     u32 pred_flags;
//     u32 blank;
//     // u64 bytes_sent;
//     u64 bytes_acked;
//     u64 bytes_received;
//     u32 snd_una;
//     u32 snd_nxt;
//     u32 snd_wnd;
//     u32 copied_seq;
//     u32 rcv_nxt;
//     u32 rcv_wnd;
//     // tcp4_transmit_skb_t, skb
//     u32 seg_seq;
//     u32 seg_len;
//     u32 seg_ack;
//     u16 seg_wnd;
//     u8 clone_it;
//     u8 tcp_flags;
// };



// int kprobe____tcp_transmit_skb(struct pt_regs *ctx,  
//         struct sock *sk, struct sk_buff *skb,
// 		int clone_it, gfp_t gfp_mask, u32 rcv_nxt)
// {
//     struct tcp4_transmit_skb_t data = {.type = 3};

//     if  (process_sock_v4_common(sk, (struct tcp4_data_t*)&data, "kprobe:tcp_transmit_skb") < 0)
//         return 0;

//     struct tcp_sock* tp = (struct tcp_sock*)sk;
//     data.pred_flags = tp->pred_flags;
//     // data.bytes_sent = tp->bytes_sent;
//     // data.bytes_sent = 0;
//     data.bytes_acked = tp->bytes_acked;
//     data.bytes_received = tp->bytes_received;
//     data.snd_una = tp->snd_una;
//     data.snd_nxt = tp->snd_nxt;
//     data.snd_wnd = tp->snd_wnd;
//     data.copied_seq = tp->copied_seq;
//     data.rcv_nxt = tp->rcv_nxt;
//     data.rcv_wnd = tp->rcv_wnd;

//     struct tcp_skb_cb* tcb = (struct tcp_skb_cb*)skb->cb;
//     data.seg_seq = tcb->seq;
//     data.seg_len = skb->len;
//     data.seg_ack = rcv_nxt;
//     data.seg_wnd = 0;
//     data.clone_it = (u8)clone_it;
//     data.tcp_flags = tcb->tcp_flags;
    

//     tcp4_data_events.perf_submit(ctx, &data, sizeof(data));
//     return 0;
// }




// int kprobe__tcp_rate_skb_sent(struct pt_regs *ctx, 
//         struct sock *sk, struct sk_buff *skb)
// {
//     return process_sock_v4(sk, ctx, "kprobe:tcp_rate_skb_sent");
// }


// TRACEPOINT_PROBE(tcp, tcp_retransmit_skb)
// {
//     struct sock* sk = (struct sock*)args->skaddr;
//     struct sk_buff* skb = (struct sk_buff*)args->skbaddr;
//     struct pt_regs* ctx = (struct pt_regs*)args;


//     struct tcp4_transmit_skb_t data = {.type = 3};

//     if  (process_sock_v4_common(sk, (struct tcp4_data_t*)&data, "trace:tcp:tcp_retansmit_skb") < 0)
//         return 0;

//     struct tcp_sock* tp = (struct tcp_sock*)sk;
//     data.pred_flags = tp->pred_flags;
//     // data.bytes_sent = tp->bytes_sent;
//     // data.bytes_sent = 0;
//     data.bytes_acked = tp->bytes_acked;
//     data.bytes_received = tp->bytes_received;
//     data.snd_una = tp->snd_una;
//     data.snd_nxt = tp->snd_nxt;
//     data.snd_wnd = tp->snd_wnd;
//     data.copied_seq = tp->copied_seq;
//     data.rcv_nxt = tp->rcv_nxt;
//     data.rcv_wnd = tp->rcv_wnd;

//     struct tcp_skb_cb* tcb = (struct tcp_skb_cb*)skb->cb;
//     data.seg_seq = tcb->seq;
//     data.seg_len = skb->len;
//     // data.seg_ack = rcv_nxt;
//     data.seg_ack = 0;
//     data.seg_wnd = 0;
//     // data.clone_it = (u8)clone_it;
//     data.clone_it = 0;
//     data.tcp_flags = tcb->tcp_flags;
    

//     tcp4_data_events.perf_submit(ctx, &data, sizeof(data));
//     return 0;
// }


// int kprobe__tcp_recvmsg(struct pt_regs *ctx, 
//         struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
// 		int flags, int *addr_len)
// {
//     return process_sock_v4(sk, ctx, "kprobe:tcp_recvmsg");
// }



// TRACEPOINT_PROBE(tcp, tcp_recv_length)
// {
//     struct sock *sk = (struct sock *)args->sk;
//     struct pt_regs *ctx = (struct pt_regs *)args;

//     return process_sock_v4(sk, ctx, "trace:tcp:tcp_recv_length");
// }



// int kprobe__tcp_sendmsg(struct pt_regs *ctx, 
//         struct sock *sk, struct msghdr *msg, size_t size)
// {
//     return process_sock_v4(sk, ctx, "kprobe:tcp_sendmsg");
// }




// TRACEPOINT_PROBE(tcp, tcp_send_length)
// {
//     struct sock *sk = (struct sock *)args->sk;
//     struct pt_regs *ctx = (struct pt_regs *)args;

//     return process_sock_v4(sk, ctx, "trace:tcp:tcp_send_length");
// }







// int kprobe____ip_queue_xmit(struct pt_regs *ctx,
//         struct sock *sk, struct sk_buff *skb, struct flowi *fl, __u8 tos)
// {
//     return process_sock_v4(sk, ctx, "kprobe:__ip_queue_xmit");
// }


struct dev_queue_xmit_entry_data {
    // struct _data_common;
    u32 type;
    u32 pid;
    u64 ts_us;
    char task[TASK_COMM_LEN];
    char function[FUNCTION_NAME_LEN];
    // struct sock_data_common
    u16 sport;
    u16 dport;
    // tcp4_data_t
    u32 state;
    u32 saddr;
    u32 daddr;    
    // struct dev_queue_xmit_entry_data
    u32 skb_len;
    u32 cpu_id;
};


BPF_HASH(dev_queue_xmit_current, u32, struct sock*);
// BPF_HASH(dev_queue_xmit_call_qdisc_run, u32, u32);
BPF_HASH(dev_queue_xmit_call___qdisc_run, u32, u32);
BPF_HASH(dev_queue_xmit_call_pfifo_fast_dequeue, u32, u32);


int kprobe____dev_queue_xmit(struct pt_regs *ctx,
        struct sk_buff *skb, struct net_device *sb_dev)
{
    struct sock* sk = skb->sk;
    // u32 tid = bpf_get_current_pid_tgid();
    u32 shifted_tid = get_shifted_tid();
    // u32 tid = pid_tgid;
    // tcp_rcv_established_current.update(&tid, &sk);
    dev_queue_xmit_current.update(&shifted_tid, &sk);

    u32 val = 0;
    // dev_queue_xmit_call_qdisc_run.update(&tid, &val);
    dev_queue_xmit_call___qdisc_run.update(&shifted_tid, &val);
    dev_queue_xmit_call_pfifo_fast_dequeue.update(&shifted_tid, &val);


    // return process_sock_v4(skb->sk, ctx, "kprobe:__dev_queue_xmit");

    struct dev_queue_xmit_entry_data data = {.type = 10};

    if  (process_sock_v4_common(sk, (struct tcp4_data_t*)&data, "kprobe:__dev_queue_xmit") < 0)
        return 0;

    data.skb_len = skb->len;
    data.cpu_id = bpf_get_smp_processor_id();

    
    tcp4_data_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

struct dev_queue_xmit_ret_data {
    // struct _data_common;
    u32 type;
    u32 pid;
    u64 ts_us;
    char task[TASK_COMM_LEN];
    char function[FUNCTION_NAME_LEN];
    // struct sock_data_common
    u16 sport;
    u16 dport;
    // tcp4_data_t
    u32 state;
    u32 saddr;
    u32 daddr;    
    // struct dev_queue_xmit_ret_data
    u32 call___qdisc_run;
    u32 call_pfifo_fast_dequeue;
    u32 cpu_id;
    u32 blank;
};


int kretprobe____dev_queue_xmit(struct pt_regs* ctx)
{
    // u32 tid = bpf_get_current_pid_tgid();
    u32 shifted_tid = get_shifted_tid();
    u32* val_p;
    // u32 dev_queue_xmit_call_qdisc_run_val = 0;
    u32 dev_queue_xmit_call___qdisc_run_val = 0;
    u32 dev_queue_xmit_call_pfifo_fast_dequeue_val = 0;

    // val_p = dev_queue_xmit_call_qdisc_run.lookup(&tid);
    // if  (val_p)
    // {   dev_queue_xmit_call_qdisc_run_val = *val_p;
    //     dev_queue_xmit_call_qdisc_run.delete(&tid);
    // }

    val_p = dev_queue_xmit_call___qdisc_run.lookup(&shifted_tid);
    if  (val_p)
    {   dev_queue_xmit_call___qdisc_run_val = *val_p;
        dev_queue_xmit_call___qdisc_run.delete(&shifted_tid);
    }

    val_p = dev_queue_xmit_call_pfifo_fast_dequeue.lookup(&shifted_tid);
    if  (val_p)
    {   dev_queue_xmit_call_pfifo_fast_dequeue_val = *val_p;
        dev_queue_xmit_call_pfifo_fast_dequeue.delete(&shifted_tid);
    }




    struct sock** skpp = dev_queue_xmit_current.lookup(&shifted_tid);
    if  (skpp)
    {
        struct sock* sk = *skpp;
        struct dev_queue_xmit_ret_data data = {.type = 9};

        if  (process_sock_v4_common(sk, (struct tcp4_data_t*)&data, "kretprobe:__dev_queue_xmit") < 0)
            return 0;

        data.call___qdisc_run = dev_queue_xmit_call___qdisc_run_val;
        data.call_pfifo_fast_dequeue = dev_queue_xmit_call_pfifo_fast_dequeue_val;
        data.cpu_id = bpf_get_smp_processor_id();
        data.blank = 0;
    
        tcp4_data_events.perf_submit(ctx, &data, sizeof(data));
        // return process_sock_v4(sk, ctx, "kretprobe:__dev_queue_xmit");
    }

    return 0;
}


// TRACEPOINT_PROBE(net, net_dev_queue)
// {
//     struct pt_regs *ctx = (struct pt_regs *)args;
//     struct sk_buff* skb = (struct sk_buff*)args->skbaddr;
//     struct sock* sk = skb->sk;

//     // return process_sock_v4(sk, ctx, "trace:net:net_dev_queue");
// } 

struct pfifo_fast_enqueue_entry_data {
    // struct _data_common;
    u32 type;
    u32 pid;
    u64 ts_us;
    char task[TASK_COMM_LEN];
    char function[FUNCTION_NAME_LEN];
    // struct sock_data_common
    u16 sport;
    u16 dport;
    // tcp4_data_t
    u32 state;
    u32 saddr;
    u32 daddr; 
    // 
    void* qdisc;
};

int kprobe__pfifo_fast_enqueue(struct pt_regs* ctx,
        struct sk_buff *skb, struct Qdisc *qdisc, struct sk_buff **to_free)
{
    struct pfifo_fast_enqueue_entry_data data = {.type = 12};

    // return process_sock_v4(skb->sk, ctx, "kprobe:pfifo_fast_enqueue");
    if  (process_sock_v4_common(skb->sk, (struct tcp4_data_t*)&data, "kprobe:pfifo_fast_enqueue") < 0)
        return 0;

    data.qdisc = qdisc;
    
    tcp4_data_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}



struct qdisc_run_expire_data {
    // struct data_common
    u32 type;
    u32 pid;
    u64 ts_us;
    char task[TASK_COMM_LEN]; // 16 
    char function[FUNCTION_NAME_LEN]; // 32
    // struct qdisc_run_expire_data
    void* qdisc;
    u64 expire_time;
};



BPF_HASH(qdisc_run_time, struct Qdisc*, u64);
#define qdisc_run_expire_time (100 * 1000)

int kprobe____qdisc_run(struct pt_regs * ctx,
        struct Qdisc *q)
{
    u64 now_us = bpf_ktime_get_ns() / 1000;
    // u32 tid = bpf_get_current_pid_tgid();
    u32 shifted_tid = get_shifted_tid();

    u32 val = 1;
    dev_queue_xmit_call___qdisc_run.update(&shifted_tid, &val);



    const struct netdev_queue *txq = q->dev_queue;
    u64 stopped = txq->state & QUEUE_STATE_ANY_XOFF_OR_FROZEN;
    if  (stopped)
        process_data_common(ctx, "kprobe:__qdisc_run, stopped");

    u64* last_us_p = qdisc_run_time.lookup(&q);
    if  (last_us_p)
    {
        u64 expire = now_us - *last_us_p;
        if  (expire > qdisc_run_expire_time)
        {
            struct qdisc_run_expire_data data = {.type = 6};

            data.pid = bpf_get_current_pid_tgid() >> 32;
            data.ts_us = now_us;
            bpf_get_current_comm(&data.task, sizeof(data.task));
            strcpy(data.function, "kprobe:__qdisc_run"); 
            data.qdisc = q;
            data.expire_time = expire;

            tcp4_data_events.perf_submit(ctx, &data, sizeof(data));
        }
    }

    qdisc_run_time.update(&q, &now_us);
    return 0;
}

// int kprobe____qdisc_run(struct pt_regs * ctx,
//         struct Qdisc *q)
// {
//     return process_data_common(ctx, "kprobe:__qdisc_run");
// }


// int kretprobe__dequeue_skb(struct pt_regs* ctx)
// {
//     struct sk_buff* skb = (struct sk_buff*)PT_REGS_RC(ctx);

//     if  (!skb)
//         return process_data_common(ctx, "kretprobe:dequeue_skb");

//     return 0;
// }

// int kprobe__dequeue_skb(struct pt_regs* ctx, 
//         struct Qdisc *q, bool *validate, int *packets)
// {
//     return 0;
// }


int kretprobe__pfifo_fast_dequeue(struct pt_regs* ctx)
{
    struct sk_buff* skb = (struct sk_buff*)PT_REGS_RC(ctx);

    // u32 tid = bpf_get_current_pid_tgid();
    u32 shifted_tid = get_shifted_tid();
    u32 val = 1;
    dev_queue_xmit_call_pfifo_fast_dequeue.update(&shifted_tid, &val);

    return process_sock_v4(skb->sk, ctx, "kretprobe:pfifo_fast_dequeue");
    // return 0;
}

// TRACEPOINT_PROBE(qdisc, qdisc_dequeue)
// {
//     struct pt_regs *ctx = (struct pt_regs *)args;
//     struct sk_buff* skb = (struct sk_buff*)args->skbaddr;
//     struct sock* sk = skb->sk;

//     return process_sock_v4(sk, ctx, "trace:qdisc:qdisc_dequeue");
// }


// int kprobe__sch_direct_xmit(struct pt_regs * ctx,
//         struct sk_buff *skb, struct Qdisc *q, struct net_device *dev, 
//         struct netdev_queue *txq, spinlock_t *root_lock, bool validate)
// {
//     return process_sock_v4(skb->sk, ctx, "kprobe:sch_direct_xmit");
// }

// int kretprobe__sch_direct_xmit(struct pt_regs * ctx)
// {
//     bool ret = PT_REGS_RC(ctx);

//     if  (!ret)
//         return process_data_common(ctx, "kretprobe:sch_direct_xmit");

//     return 0;
// }

// int kprobe__dev_hard_start_xmit(struct pt_regs *ctx,
//         struct sk_buff *first, struct net_device *dev, struct netdev_queue *txq, int *ret)
// {
//     return process_sock_v4(first->sk, ctx, "kprobe:dev_hard_start_xmit");
// }



// TRACEPOINT_PROBE(net, net_dev_start_xmit)
// {
//     struct pt_regs *ctx = (struct pt_regs *)args;
//     struct sk_buff* skb = (struct sk_buff*)args->skbaddr;
//     struct sock* sk = skb->sk;

//     return process_sock_v4(sk, ctx, "trace:net:net_dev_start_xmit");
// }

struct net_dev_xmit_ret_data {
    // struct _data_common;
    u32 type;
    u32 pid;
    u64 ts_us;
    char task[TASK_COMM_LEN];
    char function[FUNCTION_NAME_LEN];
    // struct sock_data_common
    u16 sport;
    u16 dport;
    // tcp4_data_t
    u32 state;
    u32 saddr;
    u32 daddr;    
    // net_dev_xmit_ret_data
    u32 len;
    int rc;
};


TRACEPOINT_PROBE(net, net_dev_xmit)
{
    struct pt_regs *ctx = (struct pt_regs *)args;
    struct sk_buff* skb = (struct sk_buff*)args->skbaddr;
    int len = args->len;
    int rc = args->rc;
    struct sock* sk = skb->sk;

    // return process_sock_v4_stack(sk, ctx, "trace:net:net_dev_xmit");
    // return process_sock_v4(sk, ctx, "trace:net:net_dev_xmit");
    // if  (rc != 0)
    //     return process_data_common(ctx, "trace:net:net_dev_xmit, rc != 0");

    struct net_dev_xmit_ret_data data = {.type = 11};

    if  (process_sock_v4_common(sk, (struct tcp4_data_t*)&data, "trace:net:net_dev_xmit") < 0)
        return 0;

    data.len = len;
    data.rc = rc;
    
    tcp4_data_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}



// struct qdisc_data {
//     // struct data_common
//     u32 type;
//     u32 pid;
//     u64 ts_us;
//     char task[TASK_COMM_LEN]; // 16 
//     char function[FUNCTION_NAME_LEN]; // 32
//     // struct qdisc_data
//     void* qdisc;
// };


// static void assign_data_common(struct data_common* data, const char* func)
// {
//     data->pid = bpf_get_current_pid_tgid() >> 32;
//     data->ts_us = bpf_ktime_get_ns() / 1000;
//     bpf_get_current_comm(&data->task, sizeof(data->task));
//     strcpy(data->function, func); 
// }

// int kprobe____netif_schedule(struct pt_regs* ctx,
//         struct Qdisc *q)
// {
//     struct qdisc_data data = {.type = 8};

//     assign_data_common((struct data_common*)&data, "kprobe:__netif_schedule");

//     data.qdisc = q;

//     tcp4_data_events.perf_submit(ctx, &data, sizeof(data));

//     return 0;
// }




// struct net_tx_action_expire_data {
//     // struct data_common
//     u32 type;
//     u32 pid;
//     u64 ts_us;
//     char task[TASK_COMM_LEN]; // 16 
//     char function[FUNCTION_NAME_LEN]; // 32
//     // struct qdisc_run_expire_data
//     u64 cpu_id;
//     // u64 expire_time;
//     u64 last_us;
//     u64 expire_us;
// };

// BPF_PERCPU_ARRAY(net_tx_action_expire_time, u64, 1);

// int kprobe__net_tx_action(struct pt_regs * ctx,
//         struct softirq_action *h)
// {
//     u64 cpu_id = bpf_get_smp_processor_id();
//     u64 now_us = bpf_ktime_get_ns() / 1000;
    
//     int index = 0;
//     u64* last_us_p = net_tx_action_expire_time.lookup(&index);
//     if  (last_us_p != 0)
//     {
//         u64 last_us = *last_us_p;
//         u64 expire_us = now_us - last_us;

//         // if  (last_us != 0 && expire_time > net_tx_action_expire_bound)
//         {
//             struct net_tx_action_expire_data data = {.type = 7};

//             data.pid = bpf_get_current_pid_tgid() >> 32;
//             data.ts_us = now_us;
//             bpf_get_current_comm(&data.task, sizeof(data.task));
//             strcpy(data.function, "kprobe:net_tx_action"); 

//             data.cpu_id = cpu_id;
//             data.last_us = last_us;
//             data.expire_us = expire_us;

//             tcp4_data_events.perf_submit(ctx, &data, sizeof(data));
//         }
//     }

//     net_tx_action_expire_time.update(&index, &now_us);
//     return 0;
// }


// int kprobe__net_tx_action(struct pt_regs * ctx,
//         struct softirq_action *h)
// {
//     return process_data_common(ctx, "kprobe:net_tx_action");
// }


// BPF_HASH(mlx5e_xmit_current, u32, struct sock*);

// int kprobe__mlx5e_xmit(struct pt_regs* ctx,
//         struct sk_buff *skb, struct net_device *dev)
// {


// }

// int kretprobe__mlx5e_xmit(struct pt_regs* ctx)
// {

// }