#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# tcpaccept Trace TCP accept()s.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpaccept [-h] [-T] [-t] [-p PID] [-P PORTS]
#
# This uses dynamic tracing of the kernel inet_csk_accept() socket function
# (from tcp_prot.accept), and will need to be modified to match kernel changes.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 13-Oct-2015   Brendan Gregg   Created this.
# 14-Feb-2016      "      "     Switch to bpf_perf_output.


from __future__ import print_function
from ctypes import c_ulonglong
from bcc import BPF
from socket import inet_ntop, inet_pton, AF_INET, AF_INET6
import socket
from struct import pack
import struct
import argparse
from bcc.utils import printb
from time import strftime
import ctypes as ct


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
parser.add_argument("-s", "--sport",
    help="comma-separated list of local port to trace")
parser.add_argument("-d", "--dport",
    help="comma-separated list of remote port to trace")
parser.add_argument("-S", "--saddr",
    help="comma-separated list of local addr to trace")
parser.add_argument("-D", "--daddr",
    help="comma-separated list of remote addr to trace")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)

args = parser.parse_args()
debug = 0



# def addr2dec(addr):
#     items = [int(x) for x in addr.split(".")]
#     return sum([items[i] << [24, 16, 8, 0][i] for i in range(4)])
 
# def dec2addr(dec):
#     return ".".join([str(dec >> x & 0xff) for x in [24, 16, 8, 0]])



# define BPF program
bpf_file = open("net_tx_action.c")
bpf_text = bpf_file.read()


# set paramater

if args.pid:
    bpf_text = bpf_text.replace('#define PARAM_PID 0',
        '#define PARAM_PID %s' % args.pid)


if args.sport:
    bpf_text = bpf_text.replace('#define PARAM_SPORT 0',
        '#define PARAM_SPORT %s' % args.sport)

if args.dport:
    bpf_text = bpf_text.replace('#define PARAM_DPORT 0',
        '#define PARAM_DPORT %s' % args.dport)

if  args.saddr:
    bpf_text = bpf_text.replace('#define PARAM_IPV4_SADDR 0x0',
        '#define PARAM_IPV4_SADDR 0x%x' % (struct.unpack("I",socket.inet_aton(args.saddr))[0]))

if  args.daddr:
    bpf_text = bpf_text.replace('#define PARAM_IPV4_DADDR 0x0',
        '#define PARAM_IPV4_DADDR 0x%x' % (struct.unpack("I",socket.inet_aton(args.daddr))[0]))

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()


# --------------------------------------------------------------------------


tcp_states = {
    0 : "INVALID",
    1 : "ESTABLISHED",
    2 : "SYN_SENT",
    3 : "SYN_RECV",
    4 : "FIN_WAIT1",
    5 : "FIN_WAIT2",
    6 : "TIME_WAIT",
    7 : "CLOSE",
    8 : "CLOSE_WAIT",
    9 : "LAST_ACK",
    10 : "LISTEN",
    11 : "CLOSING",
    12 : "NEW_SYN_RECV",
}

# event data
TASK_COMM_LEN = 16      # linux/sched.h
FUNCTION_NAME_LEN = 32



class data_common(ct.Structure):
     _fields_ = [
        #
        ("type",  ct.c_uint),
        ("pid",   ct.c_uint),
        ("ts_us", ct.c_ulonglong),
        ("task",  ct.c_char * TASK_COMM_LEN),
        ("function", ct.c_char * FUNCTION_NAME_LEN),
    ]

def print_data_common(event):
    
    print("%-8s %-9.6f  %7d %-15.15s %-30s " % (
        strftime("%H:%M:%S"), float(event.ts_us) / 1e6, event.pid, event.task, event.function), 
        end="")


class tcp4_data(ct.Structure):
    _fields_ = [
        #
        ("type",  ct.c_uint),
        ("pid",   ct.c_uint),
        ("ts_us", ct.c_ulonglong),
        ("task",  ct.c_char * TASK_COMM_LEN),
        ("function", ct.c_char * FUNCTION_NAME_LEN),
        #
        ("sport", ct.c_ushort),
        ("dport", ct.c_ushort),
        #
        ("state", ct.c_uint),
        ("saddr", ct.c_uint),
        ("daddr", ct.c_uint),
        
    ]

def print_tcp4_data(event):
    # printb(b"" % (), nl="")
    
    print("%-8s %-9.6f  %7d %-15.15s %-30s %-24s %5d  %-24s %5d %-10s %d" % (
        strftime("%H:%M:%S"), float(event.ts_us) / 1e6, event.pid, event.task, event.function,

        inet_ntop(AF_INET, pack("I", event.saddr)).encode(),
        event.sport,

        inet_ntop(AF_INET, pack("I", event.daddr)).encode(),
        event.dport,

        tcp_states[event.state],
        event.type
    ))

def print_tcp4_sock(event):

    print_tcp4_data(event)

    # printb(b"    bytes_sent:       0x%08Lx" % event.bytes_sent)
    print("    bytes_acked:      0x%08Lx" % event.bytes_acked)
    print("    snd_una:          0x%08x" % event.snd_una)
    print("    snd_nxt:          0x%08x" % event.snd_nxt)
    print("    snd_wnd:          0x%08x" % event.snd_wnd)
    print("")

    print("    bytes_recevied:   0x%08Lx" % event.bytes_received)
    print("    copied_seq:       0x%08x" % event.copied_seq)
    print("    rcv_nxt:          0x%08x" % event.rcv_nxt)
    print("    rcv_wnd:          0x%08x" % event.rcv_wnd)
    print("")



class tcp4_rcv_established(ct.Structure):
    _fields_ = [
        #
        ("type",  ct.c_uint),
        ("pid",   ct.c_uint),
        ("ts_us", ct.c_ulonglong),
        ("task",  ct.c_char * TASK_COMM_LEN),
        ("function", ct.c_char * FUNCTION_NAME_LEN),
        #
        ("sport", ct.c_ushort),
        ("dport", ct.c_ushort),
        #
        ("state", ct.c_uint),
        ("saddr", ct.c_uint),
        ("daddr", ct.c_uint),
        #tcp4_sock
        ("pred_flags", ct.c_uint),
        ("blank", ct.c_uint),
        # ("bytes_sent", ct.c_ulonglong),
        ("bytes_acked", ct.c_ulonglong),
        ("bytes_received", ct.c_ulonglong),
        ("snd_una", ct.c_uint),
        ("snd_nxt", ct.c_uint),
        ("snd_wnd", ct.c_uint),
        ("copied_seq", ct.c_uint),
        ("rcv_nxt", ct.c_uint),
        ("rcv_wnd", ct.c_uint),
        #
        ("seg_seq", ct.c_uint),
        ("seg_len", ct.c_uint),
        ("seg_ack", ct.c_uint),
        ("seg_wnd", ct.c_ushort),
        ("seg_doff", ct.c_ubyte),
        ("tcp_flags", ct.c_ubyte),
    ]

def print_tcp4_rcv_established(event):
    
    # event = b["ipv4_events"].event(data)
    # event = ct.cast(data, ct.POINTER(Tcp4_rcv_established_t)).contents

    print_tcp4_sock(event)

    print("    pred_flags:       0x%08x" % event.pred_flags)
    print("    seg_doff:         0x%08x" % event.seg_doff)
    print("    tcp_flags:        0x%08x" % event.tcp_flags)
    print("")

  
    print("    seg_seq:          0x%08x" % event.seg_seq)
    print("    seg_len:          0x%08x" % event.seg_len)
    print("    seg_ack:          0x%08x" % event.seg_ack)
    print("    seg_wnd:          0x%08x" % event.seg_wnd)
    print("")



class tcp4_transmit_skb(ct.Structure):
    _fields_ = [
        #
        ("type",     ct.c_uint),
        ("pid",      ct.c_uint),
        ("ts_us",    ct.c_ulonglong),
        ("task",     ct.c_char * TASK_COMM_LEN),
        ("function", ct.c_char * FUNCTION_NAME_LEN),
        #
        ("sport",    ct.c_ushort),
        ("dport",    ct.c_ushort),
        #
        ("state",    ct.c_uint),
        ("saddr",    ct.c_uint),
        ("daddr",    ct.c_uint),
        #
        ("pred_flags", ct.c_uint),
        ("blank",    ct.c_uint),
        # ("bytes_sent", ct.c_ulonglong),
        ("bytes_acked", ct.c_ulonglong),
        ("bytes_received", ct.c_ulonglong),
        ("snd_una",  ct.c_uint),
        ("snd_nxt",  ct.c_uint),
        ("snd_wnd",  ct.c_uint),
        ("copied_seq", ct.c_uint),
        ("rcv_nxt",  ct.c_uint),
        ("rcv_wnd",  ct.c_uint),
        #
        ("seg_seq",  ct.c_uint),
        ("seg_len",  ct.c_uint),
        ("seg_ack",  ct.c_uint),
        ("seg_wnd",  ct.c_ushort),
        ("clone_it", ct.c_ubyte),
        ("tcp_flags", ct.c_ubyte),
    ]


def print_tcp4_transmit_skb(event):
    
    # event = b["ipv4_events"].event(data)
    # event = ct.cast(data, ct.POINTER(Tcp4_transmit_skb_t)).contents

    # print_tcp4_data(event)

    # # printb(b"    bytes_sent:       0x%08Lx" % event.bytes_sent)
    # print("    bytes_acked:      0x%08Lx" % event.bytes_acked)
    # print("    snd_una:          0x%08x" % event.snd_una)
    # print("    snd_nxt:          0x%08x" % event.snd_nxt)
    # print("    snd_wnd:          0x%08x" % event.snd_wnd)
    # print("")

    # print("    bytes_recevied:   0x%08Lx" % event.bytes_received)
    # print("    copied_seq:       0x%08x" % event.copied_seq)
    # print("    rcv_nxt:          0x%08x" % event.rcv_nxt)
    # print("    rcv_wnd:          0x%08x" % event.rcv_wnd)
    # print("")

    print_tcp4_sock(event)

    # print("    pred_flags:       0x%08Lx" % event.pred_flags)
    print("    clone_it:         0x%08x" % event.clone_it)
    print("    tcp_flags:        0x%08x" % event.tcp_flags)
    print("")

    
    
    print("    snd_seq:          0x%08x" % event.seg_seq)
    print("    snd_len:          0x%08x" % event.seg_len)
    print("    rcv_nxt:          0x%08x" % event.seg_ack)
    
    print("")


class tcp4_data_stack(ct.Structure):
    _fields_ = [
        #
        ("type",  ct.c_uint),
        ("pid",   ct.c_uint),
        ("ts_us", ct.c_ulonglong),
        ("task",  ct.c_char * TASK_COMM_LEN),
        ("function", ct.c_char * FUNCTION_NAME_LEN),
        #
        ("sport", ct.c_ushort),
        ("dport", ct.c_ushort),
        #
        ("state", ct.c_uint),
        ("saddr", ct.c_uint),
        ("daddr", ct.c_uint),
        #
        ("stack_id", ct.c_uint),
        ("blank", ct.c_uint),
    ]

def print_tcp4_data_stack(event):

    print_tcp4_data(event)
    
    # print("stack_id: %d" % event.stack_id)
    
    if event.stack_id != 0:
        for addr in stack_traces.walk(event.stack_id):
            sym = b.ksym(addr, show_offset=True)
            print("\t%s" % sym)
        print("")

class qdisc_run_expire_data(ct.Structure):
     _fields_ = [
        #
        ("type",  ct.c_uint),
        ("pid",   ct.c_uint),
        ("ts_us", ct.c_ulonglong),
        ("task",  ct.c_char * TASK_COMM_LEN),
        ("function", ct.c_char * FUNCTION_NAME_LEN),
        #
        ("qdisc", ct.c_ulonglong),
        ("expire_time", ct.c_ulonglong),
    ]

def print_qdisc_run_expire_data(event):
    print_data_common(event)

    print("    qdisc:  0x%08Lx, expire_time: %ld" % (event.qdisc, event.expire_time))

class net_tx_action_expire_data(ct.Structure):
     _fields_ = [
        #
        ("type",  ct.c_uint),
        ("pid",   ct.c_uint),
        ("ts_us", ct.c_ulonglong),
        ("task",  ct.c_char * TASK_COMM_LEN),
        ("function", ct.c_char * FUNCTION_NAME_LEN),
        #
        ("cpu_id", ct.c_ulonglong),
        ("last_us", ct.c_ulonglong),
        ("expire_us", ct.c_ulonglong),
    ]

def print_net_tx_action_expire_data(event):
    print_data_common(event)
    print("    cpu_id: %2ld, last_us: %16ld, now_us: %16ld, expire_us: %16ld" % ( event.cpu_id, event.last_us, event.ts_us, event.expire_us))

# process event
def print_tcp4_data_event(cpu, event, size):
    
    # event = b["ipv4_events"].event(data)
    common = ct.cast(event, ct.POINTER(data_common)).contents

    if  common.type == 1:
        data = ct.cast(event, ct.POINTER(tcp4_data)).contents
        print_tcp4_data(data)
    elif common.type == 2:
        # print("get type 2")
        data = ct.cast(event, ct.POINTER(tcp4_rcv_established)).contents
        print_tcp4_rcv_established(data)
    elif common.type == 3:
        data = ct.cast(event, ct.POINTER(tcp4_transmit_skb)).contents
        print_tcp4_transmit_skb(data)
    elif common.type == 4:
        data = ct.cast(event, ct.POINTER(tcp4_data_stack)).contents
        print_tcp4_data_stack(data)
    elif common.type == 5:
        data = ct.cast(event, ct.POINTER(data_common)).contents
        print_data_common(data)
    elif common.type == 6:
        data = ct.cast(event, ct.POINTER(qdisc_run_expire_data)).contents
        print_qdisc_run_expire_data(data)
    elif common.type == 7:
        data = ct.cast(event, ct.POINTER(net_tx_action_expire_data)).contents
        print_net_tx_action_expire_data(data)





# -------------------------------------------------------------------------

# initialize BPF
b = BPF(text=bpf_text)


# header

print("%-15s" % ("TIME(s)"), end="")

print("%7s %-15s %-30s %-24s %5s  %-24s %5s" % ("PID", "COMMAND", "FUNCTION", "LADDR",
    "SPORT", "RADDR", "RPORT"))

start_ts = 0


# read events
b["tcp4_data_events"].open_perf_buffer(print_tcp4_data_event)
# b["tcp4_rcv_established_events"].open_perf_buffer(print_tcp4_rcv_established_event)
# b["tcp4_transmit_skb_events"].open_perf_buffer(print_tcp4_transmit_skb_event)
stack_traces = b.get_table("stack_traces")


while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
