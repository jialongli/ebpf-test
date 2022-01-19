#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from ctypes import c_int, c_ubyte, c_uint, c_ulonglong, c_ushort
import ctypes as ct
from socket import inet_ntop, inet_pton, AF_INET, AF_INET6
import socket
import argparse
from time import strftime
from struct import pack
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
parser.add_argument("--enable_ipv6", action="store_true",
    help="enable ipv6")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)

args = parser.parse_args()
debug = 0





# define BPF program
bpf_file = open("tcp_accept.c")
bpf_text = bpf_file.read()


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

if  args.saddr:
    bpf_text = bpf_text.replace('#define PARAM_IPV4_SADDR 0x0',
        '#define PARAM_IPV4_SADDR 0x%x' % (struct.unpack("I",socket.inet_aton(args.saddr))[0]))

if  args.daddr:
    bpf_text = bpf_text.replace('#define PARAM_IPV4_DADDR 0x0',
        '#define PARAM_IPV4_DADDR 0x%x' % (struct.unpack("I",socket.inet_aton(args.daddr))[0]))

if  args.enable_ipv6:
    bpf_text = bpf_text.replace('#define PARAM_ENABLE_IPV6 0',
        '#define PARAM_ENABLE_IPV6 1')


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
FUNCTION_NAME_LEN = 48



class data_common(ct.Structure):
    _fields_ = [
        ("type",     ct.c_uint),
        ("blank",    ct.c_uint),
        ("ts_us",    ct.c_ulonglong),
        ("task",     ct.c_char * TASK_COMM_LEN),
        ("function", ct.c_char * FUNCTION_NAME_LEN),
        ("pid",      ct.c_uint),
        ("tid",      ct.c_uint),
        ("blank1",   ct.c_uint),
        ("blank2",   ct.c_uint),
    ]
    def print(self):
        print("%-8s %-9.6f  %7d %7d %-15.15s %-30s " % (
                # self.type, 
                strftime("%H:%M:%S"), float(self.ts_us) / 1e6, 
                self.pid, self.tid, self.task, self.function),
            end=""
        )



class two_ipv4_addrs(ct.Structure):
    _fields_ = [
        ("saddr", ct.c_uint),
        ("daddr", ct.c_uint),
    ]

class two_ipv6_addrs(ct.Structure):
    _fields_ = [
        ("saddr", ct.c_ubyte * 16),
        ("daddr", ct.c_ubyte * 16),
    ]

class inet_addrs(ct.Union):
    _fields_ = [
        ("ipv4", two_ipv4_addrs),
        ("ipv6", two_ipv6_addrs),
    ]

class tcp_data(ct.Structure):
    _fields_ = [
        ("common", data_common),
        ("sport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("state", ct.c_ushort),
        ("family", ct.c_ushort),
        ("addrs", inet_addrs),
    ]
    def print(self):
        self.common.print()
        if  (self.family == AF_INET):
            print("%-21s %5d  %-21s %5d " % (
                    inet_ntop(AF_INET, pack("I", self.addrs.ipv4.saddr)).encode(),
                    self.sport,
                    inet_ntop(AF_INET, pack("I", self.addrs.ipv4.daddr)).encode(),
                    self.dport),
                end=""
            )
            # print("no ipv4 now")

        elif (self.family == AF_INET6):
            # print("no ipv6 now", end="")
            print("%-24s %5d  %-24s %5d " % (
                    inet_ntop(AF_INET6, self.addrs.ipv6.saddr).encode(),
                    self.sport,
                    inet_ntop(AF_INET6, self.addrs.ipv6.daddr).encode(),
                    self.dport),
                end=""
            )

        print("%-12s " % tcp_states[self.state], end="")


class tcp_sock_data(ct.Structure):
    _fields_ = [
        ("tcp_common",       tcp_data),
        ("pred_flags",       ct.c_uint),
        ("is_cwnd_limited_flag", ct.c_ubyte),
        ("blank",            ct.c_ubyte),
        ("blank1",           ct.c_ushort),
        ("bytes_acked",      ct.c_ulonglong),
        ("bytes_received",   ct.c_ulonglong),
        ("snd_una",          ct.c_uint),
        ("snd_nxt",          ct.c_uint),
        ("snd_wnd",          ct.c_uint),
        ("write_seq",        ct.c_uint),
        # ("blank2",            ct.c_uint),
        ("srtt_us",          ct.c_uint),
        ("inflight_packets", ct.c_uint),
        ("snd_cwnd",         ct.c_uint),
        ("copied_seq",       ct.c_uint),
        ("rcv_nxt",          ct.c_uint),
        ("rcv_wnd",          ct.c_uint),
    ]
    def print(self):
        self.tcp_common.print()
        print()

        print("    bytes_acked:          0x%08Lx" % self.bytes_acked)
        print("    snd_una:              0x%08x" % self.snd_una)
        print("    snd_nxt:              0x%08x" % self.snd_nxt)
        print("    write_seq:            0x%08x" % self.write_seq)
        print("    inflight_bytes:       0x%08x" % (self.snd_nxt - self.snd_una))
        print("    snd_wnd:              0x%08x" % self.snd_wnd)
        print("    is_cwnd_limited_flag:       0x%02x" % self.is_cwnd_limited_flag)
        print("    inflight_packets:     0x%08x" % self.inflight_packets)
        print("    snd_cwnd:             0x%08x" % self.snd_cwnd)
        print("    write_seq - snd_nxt:  0x%08x" % (self.write_seq - self.snd_nxt))
        print("    write_seq - snd_una:  0x%08x" % (self.write_seq - self.snd_una))
        print("    srtt_us:              %10d" % self.srtt_us)
        print("")

        print("    bytes_recevied:       0x%08Lx" % self.bytes_received)
        print("    copied_seq:           0x%08x" % self.copied_seq)
        print("    rcv_nxt:              0x%08x" % self.rcv_nxt)
        print("    rcv_not_copied:       0x%08x" % (self.rcv_nxt - self.copied_seq))
        print("    rcv_wnd:              0x%08x" % self.rcv_wnd)
    


class tcp_rcv_established_data(ct.Structure):
    _fields_ = [
        ("tcp_sock",  tcp_sock_data),
        ("seg_seq",   ct.c_uint),
        ("seg_len",   ct.c_uint),
        ("seg_ack",   ct.c_uint),
        ("seg_wnd",   ct.c_ushort),
        ("seg_doff",  ct.c_ubyte),
        ("tcp_flags", ct.c_ubyte),
    ]
    def print(self):
        self.tcp_sock.print()
        print()

        # print("    pred_flags:       0x%08x" % self.pred_flags)
        print("    seg_doff:             0x%08x" % self.seg_doff)
        print("    tcp_flags:            0x%08x" % self.tcp_flags)
        print("")

        print("    rcv_seq:              0x%08x" % self.seg_seq)
        print("    rcv_len:              0x%08x" % self.seg_len)
        print("    rcv_ack:              0x%08x" % self.seg_ack)
        print("    rcv_wnd:              0x%08x" % self.seg_wnd)


class tcp_transmit_skb_data(ct.Structure):
    _fields_ = [
        ("tcp_sock",  tcp_sock_data),
        ("seg_seq",   ct.c_uint),
        ("seg_len",   ct.c_uint),
        ("seg_ack",   ct.c_uint),
        ("seg_wnd",   ct.c_ushort),
        ("clone_it",  ct.c_ubyte),
        ("tcp_flags", ct.c_ubyte),
    ]
    def print(self):
        self.tcp_sock.print()
        print()

        print("    clone_it:             0x%08x" % self.clone_it)
        print("    tcp_flags:            0x%08x" % self.tcp_flags)
        print()

        print("    snd_seq:              0x%08x" % self.seg_seq)
        print("    snd_len:              0x%08x" % self.seg_len)
        print("    snd_ack:              0x%08x" % self.seg_ack)


class tcp_data_with_two_args(ct.Structure):
    _fields_ = [
        ("tcp_common", tcp_data),
        ("arg1", ct.c_int),
        ("arg2", ct.c_int),
    ]
    def print(self):
        self.tcp_common.print()
        print("arg1: %d, arg2: %d " % (self.arg1, self.arg2), end="")


class tcp_data_with_poll_event(ct.Structure):
    _fields_ = [
        ("tcp_common", tcp_data),
        ("event", ct.c_uint),
        ("blank", ct.c_uint),
    ]
    def print(self):
        self.tcp_common.print()
        
        print("event: 0x%08x, POLLIN: %d, POLLOUT: %d, POLLERR: %d, POLLHUP: %d" % (
                self.event,
                (self.event & 0x0001) == 0x0001,
                (self.event & 0x0004) == 0x0004,
                (self.event & 0x0008) == 0x0008,
                (self.event & 0x0010) == 0x0010), 
            end=""
        )

class tcp_data_with_state_trans(ct.Structure):
    _fields_ = [
        ("tcp_common", tcp_data),
        ("arg1", ct.c_int),
        ("arg2", ct.c_int),
    ]
    def print(self):
        self.tcp_common.print()
        print("%s -> %s" % (tcp_states[self.arg1], tcp_states[self.arg2]), end="")




def print_data_event(cpu, event, size):
    common = ct.cast(event, ct.POINTER(data_common)).contents
    type = common.type

    if  type == 1:
        ct.cast(event, ct.POINTER(data_common)).contents.print()
    elif type == 2:
        ct.cast(event, ct.POINTER(tcp_data)).contents.print()
    elif type == 3:
        ct.cast(event, ct.POINTER(tcp_sock_data)).contents.print()
    elif type == 4:
        ct.cast(event, ct.POINTER(tcp_rcv_established_data)).contents.print()
    elif type == 5:
        ct.cast(event, ct.POINTER(tcp_transmit_skb_data)).contents.print()
    elif type == 6:
        ct.cast(event, ct.POINTER(tcp_data_with_two_args)).contents.print()
    elif type == 7:
        ct.cast(event, ct.POINTER(tcp_data_with_poll_event)).contents.print()
    elif type == 8:
        ct.cast(event, ct.POINTER(tcp_data_with_state_trans)).contents.print()



    print()



# -------------------------------------------------------------------------

# initialize BPF
b = BPF(text=bpf_text)



# header

print("hello world")

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




