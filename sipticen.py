#!/usr/bin/env python2
# -*- encoding: utf-8 -*-
# main.py

'''
Final project for Data Communication 1 & 2.
Copyright (C) 2015 - Matías A. Ré Medina
UNICEN Systems Engineering student.
'''

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from TopologyParser import TopologyParser as TpScan
from scapy.all import *
from glob import glob
import subprocess
import shlex
import argparse
import pyshark
import socket
import sys

# Protos
ICMP = "icmp"
TCP = "tcp"
UDP = "udp"
PROTOS = [ICMP, TCP, UDP]

# Formatting
UDP_FORMAT = "[UDP: %s], Src Port: %s, Dst Port: %s\n"
TCP_FORMAT = "[TCP: %s], Src Port: %s, Dst Port: %s, Seq: %s, Ack: %s, Len: %s\n"
ICMP_FORMAT_1 = "[ICMP] Id: %s, Type: %s, Code: %s, Seq: %s\n"
ICMP_FORMAT_2 = "[ICMP] type: %s, code: %s\n"
IP_FORMAT = "[IP] id: %s, ttl: %s\n" 
IFACE_FORMAT = "[Interface %s] (%s -> %s)\n"
PKT_FORMAT = "[Packet #%d][%s/%s]\n"
SEPARATOR_FORMAT = "--------------------------------------------\n"
IP_TRACE_FORMAT = "[IP #%s] Trace: begin -> "
TRACE_FORMAT_ARROW = "%s -> "
TRACE_END_FORMAT = "end\n"

def getParserArgs():
    """Parser setup for launcher arguments.
    """

    parser = argparse.ArgumentParser(
        description="Matt's final project for CDD I & II.",
        fromfile_prefix_chars='@')

    parser_merge = parser.add_argument_group('merge')
    parser_merge.add_argument('-m', '--merge', 
        action='store_true',
        default=False,
        help='Enables merge option.')
    parser_merge.add_argument('-r', '--pread', 
        action='store',
        help='--r *.pcap (only wildcards)')
    parser_merge.add_argument('-w', '--pwrite', 
        action='store',
        help='--w all.pcap')

    parser_merge = parser.add_argument_group('parse')
    parser_merge.add_argument('--parse', 
        action='store',
        default=None,
        help='--parse file.xml. Parses a Core XML topology.')

    parser_search = parser.add_argument_group('search')
    parser_search.add_argument('--search',
        action='store_true',
        default=False,
        help='Enables search option.')
    parser_search.add_argument('-f', '--file',
        action='store',
        default=None,
        help='PcapNG file.')
    parser_search.add_argument('-s', '--src',
        action='store',
        help='Source IPv4 address.')
    parser_search.add_argument('-d', '--dst', 
        action='store',
        help='Destination IPv4 address.')
    parser_search.add_argument('-i', '--ip-id', 
        action='store',
        default=None,
        help='IP identification number.')
    parser_search.add_argument('-t', '--trace', 
        action='store_true',
        default=False,
        help='Prints packet\'s trace through the topology')
    parser_search.add_argument('--hide-bcast', 
        action='store_true',
        default=False,
        help='Hides broadcast emulated interfaces packets.')
    parser_search.add_argument('--print-readable', 
        action='store_true',
        default=False,
        help='Prints packets in a readable format. Warning: Flooding.')

    parser_icmp = parser.add_argument_group('icmp')
    parser_icmp.add_argument('--icmp',
        action='store_true',
        default=None,
        help='Enables ICMP protocol.')
    parser_icmp.add_argument('--icmp-ident',
        action='store',
        default=None,
        help='Filter by ICMP ident.')

    parser_tcp = parser.add_argument_group('tcp')
    parser_tcp.add_argument('--tcp',
        action='store_true',
        default=False,
        help='Enables search over TCP protocol.')
    parser_tcp.add_argument("--tcp-port",
        action='store',
        default=None,
        help="80, 22, 21, 23, etc")
    parser_tcp.add_argument("--tcp-proto",
        action='store',
        default=None,
        help="HTTP, SSH, FTP, etc")


    parser_udp = parser.add_argument_group('udp')
    parser_udp.add_argument('--udp',
        action='store_true',
        default=None,
        help='Enables search over UDP protocol.')
    parser_udp.add_argument("--udp-port",
        action='store',
        default=None,
        help="53, 67, 68, 69, etc")    
    parser_udp.add_argument("--udp-proto",
        action='store',
        default=None,
        help="DNS, DHCP, NTP, etc")

    return parser.parse_args()


def get_frame_interface(pkt):
    """Returns current frame interface id alias.
    """
    iface_raw = pkt.frame_info._all_fields['frame.interface_id'].showname_value
    ifname = ".".join(iface_raw.split()[1][1:-1].split(".")[:2])
    return ifname

def get_icmp_type(pkt):
    """Returns current layer's icmp type.
    """
    icmp_raw = pkt.icmp._all_fields['icmp.type'].showname_value
    icmp_type = icmp_raw[icmp_raw.index(" ")+1:]
    return icmp_type

def get_icmp_code(pkt):
    """Returns current layer's icmp code.
    """
    try:
        icmp_raw = pkt.icmp._all_fields['icmp.code'].showname_value
        icmp_code = icmp_raw[icmp_raw.index(" ")+1:]
        return icmp_code
    except:
        return 0

def get_proto_by_name(name):
    """Returns protocol name based on protocol number.
    """
    return str(socket.getprotobyname(name))

def mfilter(pkt):
    """Boolean function that returns True whether the pkt matches the designated
        criteria.
    """
    opts = (args.tcp, args.icmp, args.udp, bool(args.ip_id)).count(True)
    if opts == 0:
        sys.exit("[!] Exiting: Must specify at least one protocol ICMP/TCP/UDP"
        " for the filter or the IP identification number.\n")

    protos = (args.tcp, args.icmp, args.udp).count(True)
    if protos > 1:
        sys.exit("[!] Exiting: Only one protocol can be selected. ICMP/TCP/UDP.")

    try:
        current = (pkt.ip.src == args.src and pkt.ip.dst == args.dst)
        if args.ip_id:
            current = (current and pkt.ip.id == args.ip_id)
        if args.icmp:
            proto = get_proto_by_name(ICMP)
            current = (current and pkt.ip.proto == proto)
            if args.icmp_ident:
                return (current and pkt[ICMP].ident == args.icmp_ident)
            return current

        if args.tcp:
            proto = get_proto_by_name(TCP)
            current = (current and pkt.ip.proto == proto)
            if args.tcp_port:
                current = (current and pkt[TCP].dstport == args.tcp_port)
            if args.tcp_proto:
                current = (current and pkt.highest_layer == args.tcp_proto)
            return current

        if args.udp:
            proto = get_proto_by_name(UDP)
            current = (current and pkt.ip.proto == proto)
            if args.udp_port:
                current = (current and pkt[UDP].dstport == args.udp_port)
            if args.udp_proto:
                current = (current and pkt.highest_layer == args.udp_proto)
            return current

        return current
    except:
        return False

def get_proto_name(hl):
    """Returns protocol name based on highest_layer.
    """
    try:
        return PROTOS[(args.icmp, args.tcp, args.udp).index(True)]
    except:
        return hl.upper()

def get_epoch_time(pkt):
    """Returns frame epoch time.
    """
    return pkt.frame_info.time_epoch

def epoch_sort(pkts):
    """Returns a list of sorted packets by epoch time.
    """
    return sorted(pkts, key=lambda p: p.get('epoch'))

def print_trace(selection):
    """Prints the packet trace based on it's flow through
    the network's topology.
    """
    for iid in selection:
        sys.stdout.write(IP_TRACE_FORMAT % iid,)
        for pkt in epoch_sort(selection.get(iid)):
            sys.stdout.write(TRACE_FORMAT_ARROW % pkt.get('iface'),)
        sys.stdout.write(TRACE_END_FORMAT)

def print_readable(selection):
    """Pretty print front end for each selected packet.
    """
    for iid in selection:
        for pkt in epoch_sort(selection.get(iid)): 
            pkt.get('data').pretty_print()

def search(pcapng):
    """Looks through a pcapng file for certain packets, applying filters taken from user
    input and finally displays them.
    """
    capture_ng = pyshark.FileCapture(pcapng, keep_packets=False)
    # pcap = pcapify(pcapng)
    # capture = rdpcap(pcap)

    filtered = [pkt for pkt in capture_ng if mfilter(pkt)]

    pktn = 0
    # selection = []
    selection_ng = {}
    for pkt in filtered:        
        ifname = get_frame_interface(pkt)
        hl = pkt.highest_layer
        proto_name = get_proto_name(hl)
        epoch_time = get_epoch_time(pkt)
        # selection.append(capture[pktn])

        if not selection_ng.has_key(pkt.ip.id):
            selection_ng.update({pkt.ip.id :[]})
        if args.hide_bcast and ifname.startswith('b.'):
            continue
        selection_ng.get(pkt.ip.id).append({"iface": ifname, "epoch": epoch_time, "data" : pkt})
        

        sys.stdout.write(PKT_FORMAT % (pktn, proto_name.upper(), hl))
        sys.stdout.write(IFACE_FORMAT % (ifname, pkt.ip.src, pkt.ip.dst))
        sys.stdout.write(IP_FORMAT % (pkt.ip.id, pkt.ip.ttl))
        
        if proto_name == ICMP:
            icmp = pkt.icmp
            icmp_type = get_icmp_type(pkt)
            icmp_code = get_icmp_code(pkt)
            try:
                sys.stdout.write(ICMP_FORMAT_1 % (icmp.ident, icmp_type, icmp_code, icmp.seq))
            except:
                sys.stdout.write(ICMP_FORMAT_2 % (icmp_type, icmp_code))
        elif proto_name == TCP:
            tcp = pkt.tcp
            sys.stdout.write(TCP_FORMAT % (hl, tcp.srcport, tcp.dstport, tcp.seq, tcp.ack, tcp.len))
        elif proto_name == UDP:
            udp = pkt.udp
            sys.stdout.write(UDP_FORMAT % (hl, udp.srcport, udp.dstport))
        sys.stdout.write(SEPARATOR_FORMAT)

        pktn += 1

    if args.trace:
        print_trace(selection_ng)

    if args.print_readable:
        print_readable(selection_ng)
    # save_pkts_pcap(selection, pcap)

def save_pkts_pcap(pkts, outfile):
    """Save selected packets to outfile using Scapy.
    """
    wrpcap(outfile, pkts)

def pcapify(pcapng):
    """Transforms a pcapng packet to a pcap format file.
    """
    try:
        fname = pcapng[:pcapng.rindex(".pcapng")]
        pcap = "%s.pcap" % fname
        subprocess.call(["editcap", pcapng, pcap, "-F", "pcap"])
        return pcap
    except:
        sys.stderr("[!] Must specify a .pcapng file.")

def merge(pr, pw):
    """Merges pcap files into a single one.
    """
    files = " ".join(glob(pr))
    cmd = "mergecap %s -w %s -F pcap" % (files, pw)
    subprocess.call(shlex.split(cmd))

def parseTop(xml):
    """Parses and print a CORE XML network configuration file and shows
        information for each node.
    """
    ts = TpScan(xml)
    ts.printInfo()

if __name__ == '__main__':
    args = getParserArgs()
    if args.merge:
        merge(args.pread, args.pwrite)
        
    if args.search:
        if args.file:
            search(args.file)
        else:
            sys.exit("[!] No input capture detected.")

    if args.parse:
        parseTop(args.parse)