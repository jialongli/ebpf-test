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





// -----------------------------------------------------------

// TRACEPOINT_PROBE(syscalls, sys_enter_epoll_wait)
// {
//     struct pt_regs* ctx = (struct pt_regs*)args;

//     submit_data_common(ctx, "tracepoint:syscalls:sys_enter_epoll_wait");
//     return 0;
// }

// TRACEPOINT_PROBE(syscalls, sys_exit_epoll_wait)
// {
//     struct pt_regs* ctx = (struct pt_regs*)args;

//     submit_data_common(ctx, "tracepoint:syscalls:sys_exit_epoll_wait");
//     return 0;
// }


TRACEPOINT_PROBE(syscalls, sys_enter_socket)
{
    struct pt_regs* ctx = (struct pt_regs*)args;

    submit_data_common(ctx, "tracepoint:syscalls:sys_enter_socket");
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_socket)
{
    struct pt_regs* ctx = (struct pt_regs*)args;

    submit_data_common(ctx, "tracepoint:syscalls:sys_exit_socket");
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_bind)
{
    struct pt_regs* ctx = (struct pt_regs*)args;

    submit_data_common(ctx, "tracepoint:syscalls:sys_enter_bind");
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_bind)
{
    struct pt_regs* ctx = (struct pt_regs*)args;

    submit_data_common(ctx, "tracepoint:syscalls:sys_exit_bind");
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_listen)
{
    struct pt_regs* ctx = (struct pt_regs*)args;

    submit_data_common(ctx, "tracepoint:syscalls:sys_enter_listen");
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_listen)
{
    struct pt_regs* ctx = (struct pt_regs*)args;

    submit_data_common(ctx, "tracepoint:syscalls:sys_exit_listen");
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_accept)
{
    struct pt_regs* ctx = (struct pt_regs*)args;

    submit_data_common(ctx, "tracepoint:syscalls:sys_enter_accept");
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_accept)
{
    struct pt_regs* ctx = (struct pt_regs*)args;

    submit_data_common(ctx, "tracepoint:syscalls:sys_exit_accept");
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_accept4)
{
    struct pt_regs* ctx = (struct pt_regs*)args;

    submit_data_common(ctx, "tracepoint:syscalls:sys_enter_accept4");
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_accept4)
{
    struct pt_regs* ctx = (struct pt_regs*)args;

    submit_data_common(ctx, "tracepoint:syscalls:sys_exit_accept4");
    return 0;
}

int kprobe__inet_accept(struct pt_regs* ctx,
        struct socket *sock, struct socket *newsock, int flags, bool kern)
{
    submit_data_common(ctx, "kprobe:inet_accept");
    return 0;
}

int kprobe__inet_csk_accept(struct pt_regs* ctx,
        struct sock *sk, int flags, int *err, bool kern)
{
    submit_data_common(ctx, "kprobe:inet_csk_accept");
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect)
{
    struct pt_regs* ctx = (struct pt_regs*)args;

    submit_data_common(ctx, "tracepoint:syscalls:sys_enter_connect");
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_connect)
{
    struct pt_regs* ctx = (struct pt_regs*)args;

    submit_data_common(ctx, "tracepoint:syscalls:sys_exit_connect");
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_sendto)
{
    struct pt_regs* ctx = (struct pt_regs*)args;

    submit_data_common(ctx, "tracepoint:syscalls:sys_enter_sendto");
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_sendto)
{
    struct pt_regs* ctx = (struct pt_regs*)args;

    submit_data_common(ctx, "tracepoint:syscalls:sys_exit_sendto");
    return 0;
}

int kprobe__sock_sendmsg(struct pt_regs* ctx,
        struct socket *sock, struct msghdr *msg)
{
    submit_data_common(ctx, "kprobe:sock_sendmsg");
    return 0;
}


int kprobe__sock_from_file(struct pt_regs* ctx,
        struct file *file, int *err)
{
    submit_data_common(ctx, "kprobe:sock_from_file");
    return 0;
}

int kprobe__sockfd_lookup_light(struct pt_regs* ctx,
        int fd, int *err, int *fput_needed)
{
    submit_data_common(ctx, "kprobe:sockfd_lookup_light");
    return 0;
}

int kprobe____fdget(struct pt_regs* ctx,
        unsigned int fd)
{
    submit_data_common(ctx, "kprobe:__fdget");
    return 0;
}


int kprobe____fget(struct pt_regs* ctx,
        unsigned int fd, fmode_t mask)
{
    submit_data_common(ctx, "kprobe:__fget");
    return 0;
}

int kprobe__fput(struct pt_regs* ctx,
        struct file *file)
{
    submit_data_common(ctx, "kprobe:fput");
    return 0;
}


int kprobe____close_fd(struct pt_regs* ctx,
        struct files_struct *files, unsigned fd)
{
    submit_data_common(ctx, "kprobe:__close_fd");
    return 0;
}

int kprobe__filp_close(struct pt_regs* ctx,
        struct file *filp, fl_owner_t id)
{
    submit_data_common(ctx, "kprobe:filp_close");
    return 0;
}

int kprobe__dnotify_flush(struct pt_regs* ctx,
        struct file *filp, fl_owner_t id)
{
    submit_data_common(ctx, "kprobe:dnotify_flush");
    return 0;
}

int kprobe__locks_remove_posix(struct pt_regs* ctx,
        struct file *filp, fl_owner_t owner)
{
    submit_data_common(ctx, "kprobe:locks_remove_posix");
    return 0;
}


int kprobe____fput(struct pt_regs* ctx,
        struct file *file)
{
    submit_data_common(ctx, "kprobe:__fput");
    return 0;
}


int kprobe__delayed_fput(struct pt_regs* ctx,
        struct work_struct *unused)
{
    submit_data_common(ctx, "kprobe:delayed_fput");
    return 0;
}

int kprobe______fput(struct pt_regs* ctx,
        struct callback_head *work)
{
    submit_data_common(ctx, "kprobe:____fput");
    return 0;
}


int kprobe__inet_sendmsg(struct pt_regs* ctx,
        struct socket *sock, struct msghdr *msg, size_t size)
{
    submit_data_common(ctx, "kprobe:inet_sendmsg");
    return 0;
}

int kprobe__tcp_sendmsg(struct pt_regs* ctx,
        struct sock *sk, struct msghdr *msg, size_t size)
{
    submit_data_common(ctx, "kprobe:tcp_sendmsg");
    return 0;
}


TRACEPOINT_PROBE(syscalls, sys_enter_recvfrom)
{
    struct pt_regs* ctx = (struct pt_regs*)args;

    submit_data_common(ctx, "tracepoint:syscalls:sys_enter_recvfrom");
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_recvfrom)
{
    struct pt_regs* ctx = (struct pt_regs*)args;

    submit_data_common(ctx, "tracepoint:syscalls:sys_exit_recvfrom");
    return 0;
}

int kprobe__sock_recvmsg(struct pt_regs* ctx,
        struct socket *sock, struct msghdr *msg)
{
    submit_data_common(ctx, "kprobe:sock_recvmsg");
    return 0;
}

int kprobe__inet_recvmsg(struct pt_regs* ctx,
        struct socket *sock, struct msghdr *msg, size_t size, int flags)
{
    submit_data_common(ctx, "kprobe:inet_recvmsg");
    return 0;
}


int kprobe__tcp_recvmsg(struct pt_regs* ctx,
        struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
		int flags, int *addr_len)
{
    submit_data_common(ctx, "kprobe:tcp_recvmsg");
    return 0;
}

// TRACEPOINT_PROBE(syscalls, sys_enter_read)
// {
//     struct pt_regs* ctx = (struct pt_regs*)args;

//     submit_data_common(ctx, "tracepoint:syscalls:sys_enter_read");
//     return 0;
// }

// TRACEPOINT_PROBE(syscalls, sys_exit_read)
// {
//     struct pt_regs* ctx = (struct pt_regs*)args;

//     submit_data_common(ctx, "tracepoint:syscalls:sys_exit_read");
//     return 0;
// }


// TRACEPOINT_PROBE(syscalls, sys_enter_write)
// {
//     struct pt_regs* ctx = (struct pt_regs*)args;

//     submit_data_common(ctx, "tracepoint:syscalls:sys_enter_write");
//     return 0;
// }

// TRACEPOINT_PROBE(syscalls, sys_exit_write)
// {
//     struct pt_regs* ctx = (struct pt_regs*)args;

//     submit_data_common(ctx, "tracepoint:syscalls:sys_exit_write");
//     return 0;
// }





TRACEPOINT_PROBE(syscalls, sys_enter_close)
{
    struct pt_regs* ctx = (struct pt_regs*)args;

    submit_data_common(ctx, "tracepoint:syscalls:sys_enter_close");
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_close)
{
    struct pt_regs* ctx = (struct pt_regs*)args;

    submit_data_common(ctx, "tracepoint:syscalls:sys_exit_close");
    return 0;
}

int kprobe__sock_close(struct pt_regs* ctx,
        struct inode *inode, struct file *filp)
{
    submit_data_common(ctx, "kprobe:sock_close");
    return 0;
}


int krpobe__sock_release(struct pt_regs* ctx,
        struct socket *sock)
{
    submit_data_common(ctx, "kprobe:sock_release");
    return 0;
}

int kprobe__inet_release(struct pt_regs* ctx,
        struct socket *sock)
{
    submit_data_common(ctx, "kprobe:inet_release");
    return 0;
}

int kprobe__tcp_close(struct pt_regs* ctx,
        struct sock *sk, long timeout)
{
    submit_data_common(ctx, "kprobe:tcp_close");
    return 0;
}



int kprobe__sock_destroy_inode(struct pt_regs* ctx,
        struct inode *inode)
{
    submit_data_common(ctx, "kprobe:tcp_close");
    return 0;
}



// // // tcp_accept -------------------------------------------------------------------------------------------------------



// int kprobe__tcp_rcv_state_process(struct pt_regs *ctx, 
//         struct sock *sk, struct sk_buff *skb)
// {
//     return submit_tcp_data(sk, ctx, "kprobe:tcp_rcv_state_process");
// }



// int kprobe__tcp_set_state(struct pt_regs* ctx,
//         struct sock *sk, int state)
// {
//     // submit_tcp_data_with_two_args(sk, ctx, "kprobe:tcp_set_state", sk->__sk_common.skc_state, state);
//     struct tcp_data_with_two_args data = {.tcp_common.common.type = 8};
//     if  (process_tcp_data(sk, &data.tcp_common, "kprobe:tcp_set_state") < 0)
//         return 0;

//     data.arg1 = sk->__sk_common.skc_state;
//     data.arg2 = state;

//     output_events.perf_submit(ctx, &data, sizeof(data));
//     return 0;
// }







// int kprobe__tcp_conn_request(struct pt_regs *ctx, struct request_sock_ops *rsk_ops,
// 		const struct tcp_request_sock_ops *af_ops, struct sock *sk, struct sk_buff *skb)
// {
//     return submit_tcp_data(sk, ctx, "kprobe:tcp_conn_request");
// }

// int kprobe__tcp_v4_send_synack(struct pt_regs* ctx, 
//         const struct sock *sk, struct dst_entry *dst, struct flowi *fl,
// 		struct request_sock *req, struct tcp_fastopen_cookie *foc,
// 		enum tcp_synack_type synack_type)
// {
//    return submit_tcp_data((struct sock*)req, ctx, "kprobe:tcp_v4_send_synack"); 
// }


// int kprobe__tcp_check_req(struct pt_regs *ctx, 
//         struct sock *sk, struct sk_buff *skb, struct request_sock *req, 
//         bool fastopen, bool *req_stolen)
// {
//     return submit_tcp_data((struct sock*)req, ctx, "kprobe:tcp_check_req");
// }

// int kprobe__tcp_v4_syn_recv_sock(struct pt_regs* ctx, 
//         const struct sock *sk, struct sk_buff *skb, struct request_sock *req,
// 	    struct dst_entry *dst, struct request_sock *req_unhash, bool *own_req)
// {
//     return submit_tcp_data((struct sock*)req, ctx, "kprobe:tcp_v4_syn_recv_sock");
// }


// int kretprobe__inet_csk_accept(struct pt_regs *ctx)
// {
//     struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);

//     return submit_tcp_data(newsk, ctx, "kretprobe:inet_csk_accept");
// }





// int kprobe__tcp_connect(struct pt_regs* ctx, struct sock *sk)
// {
//     return submit_tcp_data(sk, ctx, "kprobe:tcp_connect");
// }

// // // // could not probe, looks inline
// // // int kprobe__tcp_rcv_synsent_state_process(struct pt_regs* ctx, 
// // //         struct sock *sk, struct sk_buff *skb, const struct tcphdr *th)
// // // {
// // //     return submit_tcp_data(sk, ctx, "kprobe:tcp_rcv_synsent_state_process");
// // // }

// int kprobe__tcp_finish_connect(struct pt_regs* ctx, struct sock *sk, struct sk_buff *skb)
// {
//     return submit_tcp_data(sk, ctx, "kprobe:tcp_finish_connect");
// }

// // // // not normal path
// // // int kprobe__tcp_send_synack(struct pt_regs* ctx, struct sock *sk)
// // // {
// // //     return submit_tcp_data(sk, ctx, "kprobe:tcp_send_synack");
// // // }





// // // tcp_close ----------------------------------------------------------------------------------------



// int kprobe__tcp_close(struct pt_regs* ctx, 
//         struct sock *sk, long timeout)
// {
//     return submit_tcp_data(sk, ctx, "kprobe:tcp_close");
// }

// int kprobe__tcp_send_fin(struct pt_regs* ctx, 
//         struct sock *sk)
// {
//     submit_tcp_data(sk, ctx, "kprobe:tcp_send_fin");
//     return 0;

// }



// int kprobe__tcp_fin(struct pt_regs* ctx, struct sock *sk)
// {
//     return submit_tcp_data(sk, ctx, "kprobe:tcp_fin");
// }


// int kprobe__tcp_time_wait(struct pt_regs* ctx, struct sock *sk, int state, int timeo)
// {
//     return submit_tcp_data(sk, ctx, "kprobe:tcp_time_wait");
// }


// int kprobe__tcp_done(struct pt_regs* ctx, struct sock *sk)
// {
//     return submit_tcp_data(sk, ctx, "kprobe:tcp_done");
// }

// int kprobe__inet_csk_destroy_sock(struct pt_regs* ctx, struct sock *sk)
// {
//     return submit_tcp_data(sk, ctx, "kprobe:inet_csk_destroy_sock");
// }

// int kprobe__tcp_v4_destroy_sock(struct pt_regs* ctx, struct sock *sk)
// {
//     return submit_tcp_data(sk, ctx, "kprobe:tcp_v4_destroy_sock");
// }

// TRACEPOINT_PROBE(tcp, tcp_destroy_sock)
// {
//     struct pt_regs* ctx = (struct pt_regs*)args;
//     struct sock* sk = (struct sock*)args->skaddr;

//     return submit_tcp_data(sk, ctx, "trace:tcp:tcp_destroy_sock");
// }



// int kprobe__inet_twsk_kill(struct pt_regs* ctx, struct inet_timewait_sock *tw)
// {
//     return submit_tcp_data((struct sock*)tw, ctx, "kprobe:inet_twsk_kill");
// }

// int kprobe__tcp_timewait_state_process(struct pt_regs* ctx, 
//         struct inet_timewait_sock *tw, struct sk_buff *skb, const struct tcphdr *th)
// {
//     return submit_tcp_data((struct sock*)tw, ctx, "kprobe:tcp_time_wait_state_process");
// }




// int kprobe__tcp_disconnect(struct pt_regs* ctx, 
//         struct sock *sk, int flags)
// {
//     submit_tcp_data(sk, ctx, "kprobe:tcp_disconnect");
//     return 0;
// }





// // reset

// int kprobe__tcp_reset(struct pt_regs* ctx, struct sock *sk)
// {
//     submit_tcp_data(sk, ctx, "kprobe:tcp_reset");
//     return 0;
// }



// TRACEPOINT_PROBE(tcp, tcp_receive_reset)
// {
//     struct pt_regs* ctx = (struct pt_regs*)args;
//     struct sock* sk = (struct sock*)args->skaddr;

//     return submit_tcp_data(sk, ctx, "trace:tcp:tcp_receive_reset");
// }




// int kprobe__tcp_v4_send_reset(struct pt_regs* ctx, 
//         const struct sock *sk, struct sk_buff *skb)
// {
//     submit_tcp_data(sk, ctx, "kprobe:tcp_v4_send_reset");
//     return 0;
// }


// // after unhash, the port of sk have been set to 0.
// int kprobe__tcp_send_active_reset(struct pt_regs* ctx, 
//         struct sock *sk, gfp_t priority)
// {
//     submit_tcp_data(sk, ctx, "kprobe:tcp_send_active_reset");
//     return 0;
// }

// TRACEPOINT_PROBE(tcp, tcp_send_reset)
// {
//     struct pt_regs* ctx = (struct pt_regs*)args;
//     struct sock* sk = (struct sock*)args->skaddr;

//     return submit_tcp_data(sk, ctx, "trace:tcp:tcp_send_reset");
// }





// // error

// int kprobe__tcp_v4_err(struct pt_regs* ctx,
//         struct sk_buff *icmp_skb, u32 info)
// {
//     submit_data_common(ctx, "kprobe:tcp_v4_err");
//     return 0;
// }


// int kprobe__tcp_write_err(struct pt_regs* ctx,
//         struct sock *sk)
// {
//     submit_tcp_data(sk, ctx, "kprobe:tcp_write_err");
//     return 0;
// }

// int kprobe__tcp_out_of_resources(struct pt_regs* ctx,
//         struct sock *sk, bool do_reset)
// {
//     submit_tcp_data(sk, ctx, "kprobe:tcp_out_of_resources");
//     return 0;
// }



// int kprobe__tcp_abort(struct pt_regs* ctx,
//         struct sock *sk, int err)
// {
//     submit_tcp_data(sk, ctx, "kprobe:tcp_abort");
//     return 0;
// }






// // timer

// int kprobe__tcp_keepalive_timer (struct pt_regs* ctx,
//         struct timer_list *t)
// {
//     struct sock *sk = from_timer_internal(sk, t, sk_timer);
//     submit_tcp_data(sk, ctx, "kprobe:tcp_keepalive_timer");
//     return 0;
// }


// // int kprobe__tcp_retransmit_timer(struct pt_regs* ctx,
// //         struct sock *sk)
// // {
// //     submit_tcp_data(sk, ctx, "kprobe:tcp_retransmit_timer");
// //     return 0;
// // }

// // int kprobe__tcp_fastopen_synack_timer(struct pt_regs* ctx,
// //         struct sock *sk)
// // {
// //     submit_tcp_data(sk, ctx, "kprobe:tcp_fastopen_synack_timer");
// //     return 0;
// // }

// // int kprobe__tcp_probe_timer(struct pt_regs* ctx,
// //         struct sock *sk)
// // {
// //     submit_tcp_data(sk, ctx, "kprobe:tcp_probe_timer");
// //     return 0;
// // }

// // int kprobe__tcp_write_timeout(struct pt_regs* ctx,
// //         struct sock *sk)
// // {
// //     submit_tcp_data(sk, ctx, "kprobe:tcp_write_timeout");
// //     return 0;
// // }


// TRACEPOINT_PROBE(tcp, tcp_send_reset)
// {
//     struct pt_regs* ctx = (struct pt_regs*)args;
//     struct sock* sk = (struct sock*)args->skaddr;

//     return submit_tcp_data(sk, ctx, "trace:tcp:tcp_send_reset");
// }
