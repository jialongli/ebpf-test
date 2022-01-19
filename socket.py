#!/usr/bin/python

from __future__ import print_function

import argparse
import ctypes as ct
from struct import pack
from time import strftime

from bcc import BPF

import socket
from socket import inet_ntop, AF_INET
import struct

# arguments
examples = """examples:
    ./tcpaccept           # trace all TCP accept()s
    ./tcpaccept -p 181    # only trace PID 181
    ./tcpaccept -s 80     # only trace sport 80
    ./tcpaccept -d 1111   # only trace dport 1111
"""

parser = argparse.ArgumentParser(
    description="Trace TCP accepts",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)

parser.add_argument("-p", "--pid",
                    help="trace this PID only")
parser.add_argument("-t", "--tid",
                    help="trace this TID only")
parser.add_argument("-s", "--sport",
                    help="comma-separated list of local port to trace")
parser.add_argument("-d", "--dport",
                    help="comma-separated list of remote port to trace")
parser.add_argument("-S", "--saddr",
                    help="comma-separated list of local addr to trace")
parser.add_argument("-D", "--daddr",
                    help="comma-separated list of remote addr to trace")
parser.add_argument("-B", "--baddr",
                    help="comma-separated list of black addr to trace")
parser.add_argument("--ebpf", action="store_true",
                    help=argparse.SUPPRESS)

args = parser.parse_args()
debug = 0

# define BPF program
# bpf_file = open("tcp_snd_wnd.c")
# bpf_text = bpf_file.read()
bpf_text = """
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
// #define PARAM_ENABLE_IPV6 0
#define PARAM_IPV4_SADDR 0x0
#define PARAM_IPV4_DADDR 0x0
#define PARAM_IPV4_BADDR 0x0



BPF_PERF_OUTPUT(output_events);
BPF_STACK_TRACE(stack_traces, 8192);

#define FUNCTION_NAME_LEN 48

// 64 + 32 = 96 bytes
struct data_common { // type = 1
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
        return -1;

    output_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}




// separate data structs for ipv4 and ipv6
struct tcp_data { // type = 2
    struct data_common common;
    u16 sport;
    u16 dport;
    int state;
    u32 saddr;
    u32 daddr;    
};


static int process_tcp_data(struct sock* sk, struct tcp_data* data, const char* func)
{
    if  (process_data_common(&data->common, func, true) < 0)
        return -1;


    u16 family = 0, sport = 0, dport = 0;
    family = sk->__sk_common.skc_family;
    sport = sk->__sk_common.skc_num;
    dport = sk->__sk_common.skc_dport;
    dport = ntohs(dport);

    if  (sk->__sk_common.skc_family != AF_INET && sk->__sk_common.skc_family != AF_INET6) 
        return -1;

    if  (PARAM_SPORT != 0 && sport != PARAM_SPORT)
        return -1;

    if  (PARAM_DPORT != 0 && dport == PARAM_DPORT)
        return -1;

    data->sport = sport;
    data->dport = dport;
    data->saddr = sk->__sk_common.skc_rcv_saddr;
    data->daddr = sk->__sk_common.skc_daddr;

    if  (PARAM_IPV4_SADDR != 0 && data->saddr != PARAM_IPV4_SADDR)
        return -1;

    if  (PARAM_IPV4_DADDR != 0 && data->daddr != PARAM_IPV4_DADDR && data->saddr != PARAM_IPV4_DADDR)
        return -1;

 if  (PARAM_IPV4_BADDR != 0 && (data->daddr == PARAM_IPV4_BADDR || data->saddr == PARAM_IPV4_BADDR))
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
    // u32 blank;
    u8  is_cwnd_limited_flag;
    u8  blank;
    u16 blank1;
    u64 bytes_acked;
    u64 bytes_received;
    u32 snd_una;
    u32 snd_nxt;
    u32 snd_wnd;
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
    data->copied_seq = tp->copied_seq;
    data->rcv_nxt = tp->rcv_nxt;
    data->rcv_wnd = tp->rcv_wnd;

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


// tcp_rcv_established

BPF_HASH(tcp_rcv_established_current, u32, struct sock*);

int kprobe__tcp_rcv_established(struct pt_regs *ctx, 
        struct sock *sk, struct sk_buff *skb)
{
    // if  (submit_tcp_sock_data(sk, ctx, "kprobe:tcp_rcv_established") < 0)
    struct tcp_sock_data data = {.tcp_common.common.type = 3};
    if  (process_tcp_sock_data(sk, &data, "kprobe:tcp_rcv_established") < 0)
        return 0;

    u32 shift_tid = get_shift_tid();
    tcp_rcv_established_current.update(&shift_tid, &sk);

    return 0;
}


int kretprobe__tcp_rcv_established(struct pt_regs* ctx)
{
    u32 shift_tid = get_shift_tid();
    struct sock** skpp = tcp_rcv_established_current.lookup(&shift_tid);
    if  (skpp)
    {
        struct sock* sk = *skpp;
        submit_tcp_sock_data(sk, ctx, "kretprobe:tcp_rcv_established");
        tcp_rcv_established_current.delete(&shift_tid);
    }

    return 0;
}


// tcp_write_xmit

BPF_HASH(tcp_write_xmit_current, u32, struct sock*);

int kprobe__tcp_write_xmit(struct pt_regs* ctx,
        struct sock *sk, unsigned int mss_now, int nonagle, int push_one, gfp_t gfp)
{
    // if  (submit_tcp_sock_data(sk, ctx, "kprobe:tcp_write_xmit") < 0)
    struct tcp_sock_data data = {.tcp_common.common.type = 3};
    if  (process_tcp_sock_data(sk, &data, "kprobe:tcp_write_xmit") < 0)
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
//===epoll====
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

int kprobe__tcp_retransmit_skb(struct pt_regs* ctx, struct sock *sk, struct sk_buff *skb, int segs)
{
    submit_tcp_data(sk, ctx, "kprobe:tcp_retransmit_skb");
    return 0;
}

int kprobe__ep_poll_callback(struct pt_regs* ctx,
        wait_queue_entry_t *wait, unsigned mode, int sync, void *key)
{
    u32 shift_tid = get_shift_tid();
    submit_data_common(ctx, "kprobe__ep_poll_callback");
    return 0;
}
"""

# set paramater

if args.pid:
    bpf_text = bpf_text.replace('#define PARAM_PID 0',
                                '#define PARAM_PID %s' % args.pid)

if args.tid:
    bpf_text = bpf_text.replace('#define PARAM_TID 0',
                                '#define PARAM_TID %s' % args.tid)

if args.sport:
    bpf_text = bpf_text.replace('#define PARAM_SPORT 0',
                                '#define PARAM_SPORT %s' % args.sport)

if args.dport:
    bpf_text = bpf_text.replace('#define PARAM_DPORT 0',
                                '#define PARAM_DPORT %s' % args.dport)

if args.saddr:
    bpf_text = bpf_text.replace('#define PARAM_IPV4_SADDR 0x0',
                                '#define PARAM_IPV4_SADDR 0x%x' % (struct.unpack("I", socket.inet_aton(args.saddr))[0]))

if args.daddr:
    bpf_text = bpf_text.replace('#define PARAM_IPV4_DADDR 0x0',
                                '#define PARAM_IPV4_DADDR 0x%x' % (struct.unpack("I", socket.inet_aton(args.daddr))[0]))

if args.baddr:
    bpf_text = bpf_text.replace('#define PARAM_IPV4_BADDR 0x0',
                                '#define PARAM_IPV4_BADDR 0x%x' % (struct.unpack("I", socket.inet_aton(args.baddr))[0]))

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# --------------------------------------------------------------------------


tcp_states = {
    0: "INVALID",
    1: "ESTABLISHED",
    2: "SYN_SENT",
    3: "SYN_RECV",
    4: "FIN_WAIT1",
    5: "FIN_WAIT2",
    6: "TIME_WAIT",
    7: "CLOSE",
    8: "CLOSE_WAIT",
    9: "LAST_ACK",
    10: "LISTEN",
    11: "CLOSING",
    12: "NEW_SYN_RECV",
}

# event data
TASK_COMM_LEN = 16  # linux/sched.h
FUNCTION_NAME_LEN = 48


class data_common(ct.Structure):
    _fields_ = [
        ("type", ct.c_uint),
        ("blank", ct.c_uint),
        ("ts_us", ct.c_ulonglong),
        ("task", ct.c_char * TASK_COMM_LEN),
        ("function", ct.c_char * FUNCTION_NAME_LEN),
        ("pid", ct.c_uint),
        ("tid", ct.c_uint),
        ("blank1", ct.c_uint),
        ("blank2", ct.c_uint),
    ]

    def print(self):
        print("%-8s %-9.6f  %7d %7d %-15.15s %-32s " % (
            strftime("%H:%M:%S"), float(self.ts_us) / 1e6,
            self.pid, self.tid, self.task, self.function),
              end=""
              )


class tcp_data(ct.Structure):
    _fields_ = [
        ("common", data_common),
        ("sport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("state", ct.c_int),
        ("saddr", ct.c_uint),
        ("daddr", ct.c_uint),
    ]

    def print(self):
        self.common.print()
        print("%-24s %5d  %-24s %5d %-12s " % (
            inet_ntop(AF_INET, pack("I", self.saddr)).encode(),
            self.sport,
            inet_ntop(AF_INET, pack("I", self.daddr)).encode(),
            self.dport,
            tcp_states[self.state]),
              end=""
              )


class tcp_sock_data(ct.Structure):
    _fields_ = [
        ("tcp_common", tcp_data),
        ("pred_flags", ct.c_uint),
        # ("blank",            ct.c_uint),
        ("is_cwnd_limited_flag", ct.c_ubyte),
        ("blank", ct.c_ubyte),
        ("blank1", ct.c_ushort),
        ("bytes_acked", ct.c_ulonglong),
        ("bytes_received", ct.c_ulonglong),
        ("snd_una", ct.c_uint),
        ("snd_nxt", ct.c_uint),
        ("snd_wnd", ct.c_uint),
        ("inflight_packets", ct.c_uint),
        ("snd_cwnd", ct.c_uint),
        ("copied_seq", ct.c_uint),
        ("rcv_nxt", ct.c_uint),
        ("rcv_wnd", ct.c_uint),
    ]

    def print(self):
        self.tcp_common.print()
        print()

        print("    bytes_acked:      0x%08Lx" % self.bytes_acked)
        print("    snd_una:          0x%08x" % self.snd_una)
        print("    snd_nxt:          0x%08x" % self.snd_nxt)
        print("    inflight_bytes:   0x%08x" % (self.snd_nxt - self.snd_una))
        print("    snd_wnd:          0x%08x" % self.snd_wnd)
        print("    is_cwnd_limited_flag:   0x%02x" % self.is_cwnd_limited_flag)
        print("    inflight_packets: 0x%08x" % self.inflight_packets)
        print("    snd_cwnd:         0x%08x" % self.snd_cwnd)
        # print("")

        # print("    bytes_recevied:   0x%08Lx" % self.bytes_received)
        # print("    copied_seq:       0x%08x" % self.copied_seq)
        # print("    rcv_nxt:          0x%08x" % self.rcv_nxt)
        # print("    rcv_not_copied:   0x%08x" % (self.rcv_nxt - self.copied_seq))
        # print("    rcv_wnd:          0x%08x" % self.rcv_wnd)


def print_data_event(cpu, event, size):
    # print()
    common = ct.cast(event, ct.POINTER(data_common)).contents
    type = common.type

    if type == 1:
        ct.cast(event, ct.POINTER(data_common)).contents.print()
    elif type == 2:
        ct.cast(event, ct.POINTER(tcp_data)).contents.print()
    elif type == 3:
        ct.cast(event, ct.POINTER(tcp_sock_data)).contents.print()

    print()


# -------------------------------------------------------------------------

# initialize BPF
b = BPF(text=bpf_text)

# header

# print("%-15s" % ("TIME(s)"), end="")

# print("%7s %-15s %-30s %-24s %5s  %-24s %5s" % ("PID", "COMMAND", "FUNCTION", "LADDR",
#     "SPORT", "RADDR", "RPORT"))

# start_ts = 0


# read events
b["output_events"].open_perf_buffer(print_data_event)
stack_traces = b.get_table("stack_traces")

while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
