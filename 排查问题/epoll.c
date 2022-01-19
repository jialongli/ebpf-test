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


struct tcp_data { // type = 2
    struct data_common common;
    u16 sport;
    u16 dport;
    short state;
    short family;
    union inet_addrs addrs;
};


static int process_tcp_data(struct sock* sk, struct tcp_data* data, const char* func)
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

        if  (PARAM_IPV4_DADDR != 0 && daddr != PARAM_IPV4_DADDR && saddr != PARAM_IPV4_DADDR)
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

static int submit_tcp_data(struct sock* sk, struct pt_regs* ctx, const char* func)
{
    struct tcp_data data = {.common.type = 2};

    if  (process_tcp_data(sk, &data, func) < 0)
        return -1;

    output_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

struct tcp_sock_data { // type = 3
    struct tcp_data tcp_common;
    //
    u32 pred_flags;
    u8  is_cwnd_limited_flag;
    u8  blank;
    u16 blank1;
    u64 bytes_acked;
    u64 bytes_received;
    u32 snd_una;
    u32 snd_nxt;
    u32 snd_wnd;
    u32 write_seq;
    // u32 blank2;
    u32 srtt_us;
    u32 inflight_packets;
    u32 snd_cwnd;
    u32 copied_seq;
    u32 rcv_nxt;
    u32 rcv_wnd;
};


static int process_tcp_sock_data(struct sock* sk, struct tcp_sock_data* data, const char* func)
{
    if  (process_tcp_data(sk, &data->tcp_common, func) < 0)
        return -1;

    struct tcp_sock* tp = (struct tcp_sock*)sk;
    data->pred_flags = tp->pred_flags;
    data->is_cwnd_limited_flag = *((u8*)(&tp->repair_queue) + 1);
    data->inflight_packets = tp->packets_out - (tp->sacked_out + tp->lost_out) + tp->retrans_out;
    data->snd_cwnd = tp->snd_cwnd;
    data->bytes_acked = tp->bytes_acked;
    data->bytes_received = tp->bytes_received;
    data->snd_una = tp->snd_una;
    data->snd_nxt = tp->snd_nxt;
    data->snd_wnd = tp->snd_wnd;
    data->write_seq = tp->write_seq;
    data->copied_seq = tp->copied_seq;
    data->rcv_nxt = tp->rcv_nxt;
    data->rcv_wnd = tp->rcv_wnd;
    data->srtt_us = tp->srtt_us >> 3;

    return 0;
}

static int submit_tcp_sock_data(struct sock* sk, struct pt_regs* ctx, const char* func)
{
    struct tcp_sock_data data = {.tcp_common.common.type = 3};

    if  (process_tcp_sock_data(sk, &data, func) < 0)
        return -1;

    output_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}





struct tcp_data_with_two_args { // type = 6
    struct tcp_data tcp_common;
    int arg1;
    int arg2;
};

static int process_tcp_data_with_two_args(struct sock* sk,
        struct tcp_data_with_two_args* data, const char* func,
        int arg1, int arg2)
{
    if  (process_tcp_data(sk, &data->tcp_common, func) < 0)
        return -1;

    data->arg1 = arg1;
    data->arg2 = arg2;
    return 0;
}

static int submit_tcp_data_with_two_args(struct sock* sk,
        struct pt_regs* ctx, const char* func,
        int arg1, int arg2)
{
    struct tcp_data_with_two_args data = {.tcp_common.common.type = 6};

    if  (process_tcp_data_with_two_args(sk, &data, func, arg1, arg2) < 0)
        return -1;

    output_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}



// // tcp_accept -------------------------------------------------------------------------------------------------------



int kprobe__tcp_rcv_state_process(struct pt_regs *ctx,
        struct sock *sk, struct sk_buff *skb)
{
    return submit_tcp_data(sk, ctx, "kprobe:tcp_rcv_state_process");
}

int kprobe__tcp_conn_request(struct pt_regs *ctx, struct request_sock_ops *rsk_ops,
		const struct tcp_request_sock_ops *af_ops, struct sock *sk, struct sk_buff *skb)
{
    return submit_tcp_data(sk, ctx, "kprobe:tcp_conn_request");
}

int kprobe__tcp_v4_send_synack(struct pt_regs* ctx,
        const struct sock *sk, struct dst_entry *dst, struct flowi *fl,
		struct request_sock *req, struct tcp_fastopen_cookie *foc,
		enum tcp_synack_type synack_type)
{
   return submit_tcp_data((struct sock*)req, ctx, "kprobe:tcp_v4_send_synack");
}


int kprobe__tcp_check_req(struct pt_regs *ctx,
        struct sock *sk, struct sk_buff *skb, struct request_sock *req,
        bool fastopen, bool *req_stolen)
{
    return submit_tcp_data((struct sock*)req, ctx, "kprobe:tcp_check_req");
}

int kprobe__tcp_v4_syn_recv_sock(struct pt_regs* ctx,
        const struct sock *sk, struct sk_buff *skb, struct request_sock *req,
	    struct dst_entry *dst, struct request_sock *req_unhash, bool *own_req)
{
    return submit_tcp_data((struct sock*)req, ctx, "kprobe:tcp_v4_syn_recv_sock");
}


int kretprobe__inet_csk_accept(struct pt_regs *ctx)
{
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);

    return submit_tcp_data(newsk, ctx, "kretprobe:inet_csk_accept");
}





int kprobe__tcp_connect(struct pt_regs* ctx, struct sock *sk)
{
    return submit_tcp_data(sk, ctx, "kprobe:tcp_connect");
}

// // // could not probe, looks inline
// // int kprobe__tcp_rcv_synsent_state_process(struct pt_regs* ctx,
// //         struct sock *sk, struct sk_buff *skb, const struct tcphdr *th)
// // {
// //     return submit_tcp_data(sk, ctx, "kprobe:tcp_rcv_synsent_state_process");
// // }

int kprobe__tcp_finish_connect(struct pt_regs* ctx, struct sock *sk, struct sk_buff *skb)
{
    return submit_tcp_data(sk, ctx, "kprobe:tcp_finish_connect");
}

// // // not normal path
// // int kprobe__tcp_send_synack(struct pt_regs* ctx, struct sock *sk)
// // {
// //     return submit_tcp_data(sk, ctx, "kprobe:tcp_send_synack");
// // }





// // tcp_close ----------------------------------------------------------------------------------------



int kprobe__tcp_close(struct pt_regs* ctx,
        struct sock *sk, long timeout)
{
    return submit_tcp_data(sk, ctx, "kprobe:tcp_close");
}


int kprobe__tcp_fin(struct pt_regs* ctx, struct sock *sk)
{
    return submit_tcp_data(sk, ctx, "kprobe:tcp_fin");
}


int kprobe__tcp_time_wait(struct pt_regs* ctx, struct sock *sk, int state, int timeo)
{
    return submit_tcp_data(sk, ctx, "kprobe:tcp_time_wait");
}

int kprobe__inet_twsk_kill(struct pt_regs* ctx, struct inet_timewait_sock *tw)
{
    return submit_tcp_data((struct sock*)tw, ctx, "kprobe:inet_twsk_kill");
}

int kprobe__tcp_timewait_state_process(struct pt_regs* ctx,
        struct inet_timewait_sock *tw, struct sk_buff *skb, const struct tcphdr *th)
{
    return submit_tcp_data((struct sock*)tw, ctx, "kprobe:tcp_time_wait_state_process");
}



int kprobe__tcp_done(struct pt_regs* ctx, struct sock *sk)
{
    return submit_tcp_data(sk, ctx, "kprobe:tcp_done");
}

// // int kprobe__inet_csk_destroy_sock(struct pt_regs* ctx, struct sock *sk)
// // {
// //     return submit_tcp_data(sk, ctx, "kprobe:inet_csk_destroy_sock");
// // }



int kprobe__tcp_set_state(struct pt_regs* ctx,
        struct sock *sk, int state)
{
    // submit_tcp_data_with_two_args(sk, ctx, "kprobe:tcp_set_state", sk->__sk_common.skc_state, state);
    struct tcp_data_with_two_args data = {.tcp_common.common.type = 8};
    if  (process_tcp_data(sk, &data.tcp_common, "kprobe:tcp_set_state") < 0)
        return 0;

    data.arg1 = sk->__sk_common.skc_state;
    data.arg2 = state;

    output_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}




// // tcp_recv_established-------------------------------------------------------------------------------------------------



struct tcp_rcv_established_data { // type = 4
    struct tcp_sock_data tcp_sock;
    u32 seg_seq;
    u32 seg_len;
    u32 seg_ack;
    u16 seg_wnd;
    u8 seg_doff;
    u8 tcp_flags;
};


BPF_HASH(tcp_rcv_established_current, u32, struct sock *);


int kprobe__tcp_rcv_established(struct pt_regs *ctx,
        struct sock *sk, struct sk_buff *skb)
{
    struct tcp_rcv_established_data data = {.tcp_sock.tcp_common.common.type = 4};

    if  (process_tcp_sock_data(sk, &data.tcp_sock, "kprobe:tcp_rcv_established") < 0)
        return 0;

    struct tcphdr* th = (struct tcphdr*)skb->data;
    u8* th_byte = (u8*)skb->data;
    data.seg_doff = th_byte[12]  >> 4;
    data.tcp_flags = th_byte[13];
    data.seg_seq = th->seq;
    data.seg_seq = ntohl(data.seg_seq);
    data.seg_len = skb->len - (data.seg_doff << 2);
    data.seg_ack = th->ack_seq;
    data.seg_ack = ntohl(data.seg_ack);
    data.seg_wnd = th->window;
    data.seg_wnd = ntohs(data.seg_wnd);


    output_events.perf_submit(ctx, &data, sizeof(data));

    u32 shift_tid = get_shift_tid();
    tcp_rcv_established_current.update(&shift_tid, &sk);

    return 0;
}



int kretprobe__tcp_rcv_established(struct pt_regs* ctx)
{
    int ret = PT_REGS_RC(ctx);
    u32 shift_tid = get_shift_tid();
    struct sock **skpp = tcp_rcv_established_current.lookup(&shift_tid);

    if  (skpp)
    {
        struct sock* sk = *skpp;
        submit_tcp_sock_data(sk, ctx, "kretprobe:tcp_rcv_established");

        tcp_rcv_established_current.delete(&shift_tid);
    }
    return 0;
}



// // int kprobe__tcp_rcv_established(struct pt_regs *ctx,
// //         struct sock *sk, struct sk_buff *skb)
// // {
// //     return submit_tcp_data(sk, ctx, "kprobe:tcp_rcv_established");
// // }





struct tcp_transmit_skb_data { // type = 5
    struct tcp_sock_data tcp_sock;
    u32 seg_seq;
    u32 seg_len;
    u32 seg_ack;
    u16 seg_wnd;
    u8 clone_it;
    u8 tcp_flags;
};

BPF_HASH(tcp_transmit_skb_current, u32, struct sock *);

int kprobe____tcp_transmit_skb(struct pt_regs *ctx,
        struct sock *sk, struct sk_buff *skb,
		int clone_it, gfp_t gfp_mask, u32 rcv_nxt)
{
    struct tcp_transmit_skb_data data = {.tcp_sock.tcp_common.common.type = 5};

    if  (process_tcp_sock_data(sk, &data.tcp_sock, "kprobe:tcp_transmit_skb") < 0)
        return 0;

    struct tcp_skb_cb* tcb = (struct tcp_skb_cb*)skb->cb;
    data.seg_seq = tcb->seq;
    data.seg_len = skb->len;
    data.seg_ack = rcv_nxt;
    data.seg_wnd = 0;
    data.clone_it = (u8)clone_it;
    data.tcp_flags = tcb->tcp_flags;


    output_events.perf_submit(ctx, &data, sizeof(data));

    u32 shift_tid = get_shift_tid();
    tcp_transmit_skb_current.update(&shift_tid, &sk);

    return 0;
}


int kretprobe____tcp_transmit_skb(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    u32 shift_tid = get_shift_tid();
    struct sock **skpp = tcp_transmit_skb_current.lookup(&shift_tid);

    if  (skpp)
    {
        struct sock* sk = *skpp;
        submit_tcp_data(sk, ctx, "kretprobe:__tcp_transmit_skb");

        tcp_transmit_skb_current.delete(&shift_tid);
    }
    return 0;
}


// // int kprobe____tcp_transmit_skb(struct pt_regs *ctx,
// //         struct sock *sk, struct sk_buff *skb, int clone_it,
// //         gfp_t gfp_mask, u32 rcv_nxt)
// // {
// //     return submit_tcp_data(sk, ctx, "kprobe:tcp_transmit_skb");
// // }


// // int kprobe__tcp_rate_skb_sent(struct pt_regs *ctx,
// //         struct sock *sk, struct sk_buff *skb)
// // {
// //     return submit_tcp_data(sk, ctx, "kprobe:tcp_rate_skb_sent");
// // }


// tcp_write_xmit

BPF_HASH(tcp_write_xmit_current, u32, struct sock*);

int kprobe__tcp_write_xmit(struct pt_regs* ctx,
        struct sock *sk, unsigned int mss_now, int nonagle, int push_one, gfp_t gfp)
{
    // struct tcp_sock_data data = {.tcp_common.common.type = 3};
    // if  (process_tcp_sock_data(sk, &data, "kprobe:tcp_write_xmit") < 0)
    if  (submit_tcp_sock_data(sk, ctx, "kprobe:tcp_write_xmit") < 0)
        return 0;

    u32 shift_tid = get_shift_tid();
    tcp_write_xmit_current.update(&shift_tid, &sk);

    return 0;
}

int kretprobe__tcp_write_xmit(struct pt_regs* ctx)
{
    u32 shift_tid = get_shift_tid();
    struct sock** skpp = tcp_write_xmit_current.lookup(&shift_tid);
    if  (skpp)
    {
        struct sock* sk = *skpp;
        submit_tcp_sock_data(sk, ctx, "kretprobe:tcp_write_xmit");
        tcp_write_xmit_current.delete(&shift_tid);
    }

    return 0;
}


// tcp_recvmsg --------------------------------------------------------------------------------------------------




// // int kprobe__tcp_recvmsg(struct pt_regs *ctx,
// //         struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
// // 		int flags, int *addr_len)
// // {
// //     return submit_tcp_data(sk, ctx, "kprobe:tcp_recvmsg");
// // }



// // TRACEPOINT_PROBE(tcp, tcp_recv_length)
// // {
// //     struct sock *sk = (struct sock *)args->sk;
// //     struct pt_regs *ctx = (struct pt_regs *)args;

// //     return submit_tcp_data(sk, ctx, "trace:tcp:tcp_recv_length");
// // }




BPF_HASH(tcp_recvmsg_current, u32, struct sock*);

int kprobe__tcp_recvmsg(struct pt_regs *ctx,
        struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
		int flags, int *addr_len)
{
    if  (submit_tcp_data(sk, ctx, "kprobe:tcp_recvmsg") < 0)
        return 0;

    u32 shift_tid = get_shift_tid();
    tcp_recvmsg_current.update(&shift_tid, &sk);

    return 0;
}


int kretprobe__tcp_recvmsg(struct pt_regs* ctx)
{
    int ret = PT_REGS_RC(ctx);
    u32 shift_tid = get_shift_tid();
    struct sock** skpp = tcp_recvmsg_current.lookup(&shift_tid);
    if  (skpp)
    {
        struct sock* sk = *skpp;
        submit_tcp_data_with_two_args(sk, ctx, "kretprobe:tcp_recvmsg", ret, 0);

        tcp_recvmsg_current.delete(&shift_tid);
    }
    return 0;
}



// // int kprobe__tcp_sendmsg(struct pt_regs *ctx,
// //         struct sock *sk, struct msghdr *msg, size_t size)
// // {
// //     return submit_tcp_data(sk, ctx, "kprobe:tcp_sendmsg");
// // }


// // TRACEPOINT_PROBE(tcp, tcp_send_length)
// // {
// //     struct sock *sk = (struct sock *)args->sk;
// //     struct pt_regs *ctx = (struct pt_regs *)args;

// //     return submit_tcp_data(sk, ctx, "trace:tcp:tcp_send_length");
// // }


BPF_HASH(tcp_sendmsg_current, u32, struct sock*);

int kprobe__tcp_sendmsg(struct pt_regs *ctx,
        struct sock *sk, struct msghdr *msg, size_t size)
{
    if  (submit_tcp_data(sk, ctx, "kprobe:tcp_sendmsg") < 0)
        return 0;

    u32 shift_tid = get_shift_tid();
    tcp_sendmsg_current.update(&shift_tid, &sk);

    return 0;
}

int kretprobe__tcp_sendmsg(struct pt_regs* ctx)
{
    int ret = PT_REGS_RC(ctx);
    u32 shift_tid = get_shift_tid();
    struct sock** skpp = tcp_sendmsg_current.lookup(&shift_tid);
    if  (skpp)
    {
        struct sock* sk = *skpp;
        submit_tcp_data_with_two_args(sk, ctx, "kretprobe:tcp_sendmsg", ret, 0);

        tcp_sendmsg_current.delete(&shift_tid);
    }
    return 0;
}



BPF_HASH(sk_stream_wait_memory_current, u32, struct sock*);

int kprobe__sk_stream_wait_memory(struct pt_regs* ctx,
        struct sock *sk, long *timeo_p)
{
    if  (submit_tcp_data(sk, ctx, "kprobe:sk_stream_wait_memory") < 0)
        return 0;

    u32 shift_tid = get_shift_tid();
    sk_stream_wait_memory_current.update(&shift_tid, &sk);

    return 0;

}

int kretprobe__sk_stream_wait_memory(struct pt_regs* ctx)
{
    int ret = PT_REGS_RC(ctx);
    u32 shift_tid = get_shift_tid();
    struct sock** skpp = sk_stream_wait_memory_current.lookup(&shift_tid);
    if  (skpp)
    {
        struct sock* sk = *skpp;
        submit_tcp_data_with_two_args(sk, ctx, "kretprobe:sk_stream_wait_memory", ret, 0);

        sk_stream_wait_memory_current.delete(&shift_tid);
    }
    return 0;
}

// BPF_HASH(sk_stream_alloc_skb_current, u32, struct sock*);

// int kprobe__sk_stream_alloc_skb(struct pt_regs* ctx,
//         struct sock *sk, int size, gfp_t gfp, bool force_schedule)
// {
//     if  (submit_tcp_data(sk, ctx, "kprobe:sk_stream_alloc_skb") < 0)
//         return 0;

//     u32 shift_tid = get_shift_tid();
//     sk_stream_alloc_skb_current.update(&shift_tid, &sk);

//     return 0;
// }

// int kretprobe__sk_stream_alloc_skb(struct pt_regs* ctx)
// {
//     struct sk_buff* skb = (struct sk_buff*)PT_REGS_RC(ctx);
//     // int skb_size = skb->true_size;

//     u32 shift_tid = get_shift_tid();
//     struct sock** skpp = sk_stream_alloc_skb_current.lookup(&shift_tid);
//     if  (skpp)
//     {
//         struct sock* sk = *skpp;
//         submit_tcp_data_with_two_args(sk, ctx, "kretprobe:sk_stream_alloc_skb", skb->truesize, 0);

//         sk_stream_alloc_skb_current.delete(&shift_tid);
//     }
//     return 0;

// }

// BPF_HASH(tcp_clean_rtx_queue_current, u32, struct sock*);

// int kprobe__tcp_clean_rtx_queue(struct pt_regs* ctx,
//         struct sock *sk, u32 prior_fack, u32 prior_snd_una, struct tcp_sacktag_state *sack)
// {
//     if  (submit_tcp_data(sk, ctx, "kprobe:tcp_clean_rtx_queue") < 0)
//         return 0;

//     u32 shift_tid = get_shift_tid();
//     tcp_clean_rtx_queue_current.update(&shift_tid, &sk);

//     return 0;
// }

// int kprobe__tcp_ack(struct pt_regs* ctx,
//         struct sock *sk, const struct sk_buff *skb, int flag)
// {
//     submit_tcp_data(sk, ctx, "kprobe:tcp_ack");
//     return 0;
// }



// int kprobe__tcp_ack(struct pt_regs* ctx,
//         struct sock *sk, const struct sk_buff *skb, int flag)
// {
//     submit_tcp_data(sk, ctx, "kprobe:tcp_ack");
//     return 0;
// }

// BPF_HASH(tcp_ack_current, u32, struct sock*);

// int kprobe__tcp_ack(struct pt_regs* ctx,
//         struct sock *sk, const struct sk_buff *skb, int flag)
// {
//     if  (submit_tcp_data(sk, ctx, "kprobe:tcp_ack") < 0)
//         return 0;

//     u32 shift_tid = get_shift_tid();
//     tcp_ack_current.update(&shift_tid, &sk);

//     return 0;
// }

// int kretprobe__tcp_ack(struct pt_regs* ctx)
// {
//     u32 shift_tid = get_shift_tid();
//     struct sock** skpp = tcp_ack_current.lookup(&shift_tid);
//     if  (skpp)
//     {
//         struct sock* sk = *skpp;
//         submit_tcp_data(sk, ctx, "kretprobe:tcp_ack");

//         tcp_ack_current.delete(&shift_tid);
//     }
//     return 0;
// }




// int kprobe____kfree_skb(struct pt_regs* ctx, struct sk_buff *skb)
// {
//     // struct sock* sk = skb->sk;
//     u32 shift_tid = get_shift_tid();
//     struct sock** skpp = tcp_ack_current.lookup(&shift_tid);
//     if  (skpp)
//     {
//         struct sock* sk = *skpp;
//         submit_tcp_data_with_two_args(sk, ctx, "kprobe:__kfree_skb", skb->truesize, skb->len);
//     }

//     return 0;
// }


// tcp_poll ----------------------------------------------------------------------------------------------------


struct tcp_data_with_poll_event {
    struct tcp_data tcp_common; // type = 7
    u32 event;
    u32 blank;
};

static int process_tcp_data_with_poll_event(struct sock* sk,
        struct tcp_data_with_poll_event* data, const char* func, u32 event)
{
    if  (process_tcp_data(sk, &data->tcp_common, func) < 0)
        return -1;

    data->event = event;
    return 0;
}

static int submit_tcp_data_with_poll_event(struct sock* sk,
        struct pt_regs* ctx, const char* func, u32 event)
{
    struct tcp_data_with_poll_event data = {.tcp_common.common.type = 7};

    if  (process_tcp_data_with_poll_event(sk, &data, func, event) < 0)
        return -1;

    output_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}


// // int kprobe__tcp_poll(struct pt_regs* ctx,
// //     struct file *file, struct socket *sock, poll_table *wait)
// // {
// //     struct sock* sk = sock->sk;
// //     return submit_tcp_data(sk, ctx, "kprobe:tcp_poll");
// // }

BPF_HASH(tcp_poll_current, u32, struct sock*);

int kprobe__tcp_poll(struct pt_regs* ctx,
    struct file *file, struct socket *sock, poll_table *wait)
{
    struct sock* sk = sock->sk;

    if  (submit_tcp_data(sk, ctx, "kprobe:tcp_poll") < 0)
        return -1;

    u32 shift_tid = get_shift_tid();
    tcp_poll_current.update(&shift_tid, &sk);

    return 0;
}



int kretprobe__tcp_poll(struct pt_regs* ctx)
{
    int ret = PT_REGS_RC(ctx);
    u32 shift_tid = get_shift_tid();
    struct sock** skpp = tcp_poll_current.lookup(&shift_tid);
    if  (skpp)
    {
        struct sock* sk = *skpp;
        submit_tcp_data_with_poll_event(sk, ctx, "kretprobe:tcp_poll", ret);

        tcp_poll_current.delete(&shift_tid);
    }
    return 0;
}


// static void sock_def_wakeup(struct sock *sk)
int kprobe__sock_def_wakeup(struct pt_regs* ctx, struct sock *sk)
{
    submit_tcp_data(sk, ctx, "kprobe:sock_def_wakeup");
    return 0;
}

int kprobe__sock_def_readable(struct pt_regs* ctx, struct sock *sk)
{
    submit_tcp_data(sk, ctx, "kprobe:sock_def_readable");
    return 0;
}


int kprobe__sock_def_write_space(struct pt_regs* ctx, struct sock *sk)
{
    submit_tcp_data(sk, ctx, "kprobe:sock_def_write_space");
    return 0;
}


// // int kprobe__tcp_check_space(struct pt_regs* ctx, struct sock *sk)
// // {
// //     return submit_tcp_data(sk, ctx, "kprobe:tcp_check_space");
// // }


// // int kprobe__tcp_new_space(struct pt_regs* ctx, struct sock *sk)
// // {
// //     return submit_tcp_data(sk, ctx, "kprobe:tcp_new_space");
// // }


int kprobe__sk_stream_write_space(struct pt_regs* ctx, struct sock *sk)
{
    submit_tcp_data(sk, ctx, "kprobe:sk_stream_write_space");
    return 0;
}


// BPF_HASH(sk_stream_write_space_current, u32, struct sock*);

// int kprobe__sk_stream_write_space(struct pt_regs* ctx,
//         struct sock *sk, long *timeo_p)
// {
//     if  (submit_tcp_data(sk, ctx, "kprobe:sk_stream_write_space") < 0)
//         return -1;
//     // struct tcp_data data = {.common.type = 2};

//     // if  (process_tcp_data(sk, &data, "kprobe:sk_stream_write_space") < 0)
//     //     return 0;

//     u32 shift_tid = get_shift_tid();
//     sk_stream_write_space_current.update(&shift_tid, &sk);

//     // output_events.perf_submit(ctx, &data, sizeof(data));
//     return 0;

// }

// int kretprobe__sk_stream_write_space(struct pt_regs* ctx)
// {
//     // int ret = PT_REGS_RC(ctx);
//     u32 shift_tid = get_shift_tid();
//     struct sock** skpp = sk_stream_write_space_current.lookup(&shift_tid);
//     if  (skpp)
//     {
//         struct sock* sk = *skpp;
//         submit_tcp_data(sk, ctx, "kretprobe:sk_stream_write_space");

//         // struct tcp_recvmsg_exit_data data = {.tcp_common.common.type = 8};

//         // if  (process_tcp_data(sk, &data.tcp_common, "kretprobe:sk_stream_write_space") < 0)
//         //     return 0;
//         // data.ret = 0;
//         // data.blank = 0;
//         // output_events.perf_submit(ctx, &data, sizeof(data));

//         sk_stream_write_space_current.delete(&shift_tid);
//     }
//     return 0;
// }



int kprobe__ep_poll_callback(struct pt_regs* ctx,
        wait_queue_entry_t *wait, unsigned mode, int sync, void *key)
{
    u32 shift_tid = get_shift_tid();
    submit_data_common(ctx, "kprobe__ep_poll_callback");

    // struct sock** skpp = sk_stream_write_space_current.lookup(&shift_tid);
    struct sock** skpp = tcp_rcv_established_current.lookup(&shift_tid);

    if  (skpp)
    {
        struct sock* sk = *skpp;
        submit_tcp_data_with_poll_event(sk, ctx, "kprobe:ep_poll_callback", (u32)key);
    }
    return 0;
}




// // int kprobe__tcp_chrono_start(struct pt_regs* ctx,
// //         struct sock *sk, const enum tcp_chrono type)
// // {
// //     // if  (type == TCP_CHRONO_RWND_LIMITED)
// //     {
// //         submit_tcp_data(sk, ctx, "kprobe:tcp_chrono_start:RWND_LIM");
// //     }
// //     return 0;
// // }

// // // could not attach
// // int kprobe__tcp_cwnd_validate(struct pt_regs* ctx,
// //         struct sock *sk, bool is_cwnd_limited)
// // {
// //     return submit_tcp_data(sk, ctx, "kprobe:tcp_cwnd_validate");
// // }


// // tcp_retrans -------------------------------------------------------------------------------------------


int kprobe__tcp_write_timer(struct pt_regs* ctx, struct timer_list *t)
{
    struct inet_connection_sock *icsk = from_timer_internal(icsk, t, icsk_retransmit_timer);
	struct sock *sk = &icsk->icsk_inet.sk;

    submit_tcp_data(sk, ctx, "kprobe:tcp_write_timer");
    return 0;
}


int kprobe__tcp_delack_timer(struct pt_regs* ctx, struct timer_list *t)
{
    struct inet_connection_sock *icsk = from_timer_internal(icsk, t, icsk_delack_timer);
	struct sock *sk = &icsk->icsk_inet.sk;

    submit_tcp_data(sk, ctx, "kprobe:tcp_delack_timer");
    return 0;
}

int kprobe__tcp_keepalive_timer(struct pt_regs* ctx, struct timer_list *t)
{
    struct inet_connection_sock *icsk =	from_timer_internal(icsk, t, icsk_delack_timer);
    struct sock *sk = &icsk->icsk_inet.sk;

    submit_tcp_data(sk, ctx, "kprobe:tcp_keepalive_timer");
    return 0;
}


// int kprobe__tcp_pace_kick(struct pt_regs* ctx, struct hrtimer *timer)
// {
//     struct tcp_sock *tp = container_of_internal(timer, struct tcp_sock, pacing_timer);
// 	struct sock *sk = (struct sock *)tp;

//     submit_tcp_data(sk, ctx, "kprobe:tcp_pace_kick");
//     return 0;
// }

// int kprobe__tcp_tsq_handler(struct pt_regs* ctx, struct sock *sk)
// {
//     submit_tcp_data(sk, ctx, "kprobe:tcp_tsq_handler");
//     return 0;
// }

// int kprobe__tcp_compressed_ack_kick(struct pt_regs* ctx, struct hrtimer *timer)
// {
//     struct tcp_sock *tp = container_of_internal(timer, struct tcp_sock, compressed_ack_timer);
// 	struct sock *sk = (struct sock *)tp;

//     submit_tcp_data(sk, ctx, "kprobe:tcp_compressed_ack_kick");
//     return 0;
// }



// // TRACEPOINT_PROBE(tcp, tcp_retransmit_skb)
// // {
// //     struct sock* sk = (struct sock*)args->skaddr;
// //     struct sk_buff* skb = (struct sk_buff*)args->skbaddr;
// //     struct pt_regs* ctx = (struct pt_regs*)args;


// //     struct tcp_transmit_skb_data data = {.tcp_sock.tcp_common.common.type = 5};

// //     if  (process_tcp_sock_data(sk, &data.tcp_sock, "trace:tcp:tcp_retransmit_skb") < 0)
// //         return 0;

// //     struct tcp_skb_cb* tcb = (struct tcp_skb_cb*)skb->cb;
// //     data.seg_seq = tcb->seq;
// //     data.seg_len = skb->len;
// //     data.seg_ack = tcb->ack_seq;
// //     data.seg_wnd = 0;
// //     data.clone_it = 0;
// //     data.tcp_flags = tcb->tcp_flags;

// //     output_events.perf_submit(ctx, &data, sizeof(data));
// //     return 0;
// // }


int kprobe__tcp_retransmit_skb(struct pt_regs* ctx, struct sock *sk, struct sk_buff *skb, int segs)
{
    submit_tcp_data(sk, ctx, "kprobe:tcp_retransmit_skb");
    return 0;
}

// // TRACEPOINT_PROBE(tcp, tcp_retransmit_skb)
// // {
// //     struct sock *sk = (struct sock *)args->skaddr;
// //     struct pt_regs *ctx = (struct pt_regs *)args;

// //     return submit_tcp_data(sk, ctx, "trace:tcp:tcp_retransmit_skb");
// // }

// // TRACEPOINT_PROBE(tcp, tcp_retransmit_synack)
// // {
// //     struct sock *sk = (struct sock *)args->skaddr;
// //     struct pt_regs *ctx = (struct pt_regs *)args;

// //     return submit_tcp_data(sk, ctx, "trace:tcp_retransmit_synack");
// // }

int kprobe__tcp_drop(struct pt_regs* ctx, struct sock *sk, struct sk_buff *skb)
{
    submit_tcp_data(sk, ctx, "trace:tcp:tcp_drop");
    return 0;
}

int kprobe__tcp_reset(struct pt_regs* ctx, struct sock *sk)
{
    submit_tcp_data(sk, ctx, "trace:tcp:tcp_reset");
    return 0;
}

// // TRACEPOINT_PROBE(tcp, tcp_receive_reset)
// // {
// //     struct pt_regs* ctx = (struct pt_regs*)args;
// //     struct sock* sk = (struct sock*)args->skaddr;

// //     return submit_tcp_data(sk, ctx, "trace:tcp:tcp_receive_reset");
// // }


// // TRACEPOINT_PROBE(tcp, tcp_send_reset)
// // {
// //     struct pt_regs* ctx = (struct pt_regs*)args;
// //     struct sock* sk = (struct sock*)args->skaddr;

// //     return submit_tcp_data(sk, ctx, "trace:tcp:tcp_send_reset");
// // }


// // TRACEPOINT_PROBE(tcp, tcp_destroy_sock)
// // {
// //     struct sock *sk = (struct sock *)args->skaddr;
// //     struct pt_regs *ctx = (struct pt_regs *)args;

// //     return submit_tcp_data(sk, ctx, "trace:tcp:tcp_destroy_sock");
// // }





