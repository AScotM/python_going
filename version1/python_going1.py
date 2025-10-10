#!/usr/bin/env python3

import argparse
import json
import logging
import os
import platform
import re
import signal
import sys
import time
import glob
from typing import List, NamedTuple
from queue import Queue
from threading import Thread
import ipaddress

logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')

class Socket(NamedTuple):
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    process: str

TCP_STATES = {
    1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1",
    5: "FIN_WAIT2", 6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT",
    9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING", 12: "NEW_SYN_RECV",
}

STATE_COLORS = {
    "ESTABLISHED": "\033[32m{}\033[0m",
    "LISTEN": "\033[34m{}\033[0m",
    "CLOSE": "\033[31m{}\033[0m",
    "TIME_WAIT": "\033[33m{}\033[0m",
    "SYN_SENT": "\033[36m{}\033[0m",
    "SYN_RECV": "\033[36m{}\033[0m",
    "FIN_WAIT1": "\033[35m{}\033[0m",
    "FIN_WAIT2": "\033[35m{}\033[0m",
    "CLOSE_WAIT": "\033[31m{}\033[0m",
    "LAST_ACK": "\033[31m{}\033[0m",
    "CLOSING": "\033[31m{}\033[0m",
    "NEW_SYN_RECV": "\033[36m{}\033[0m",
}

PROCESS_CACHE = {}
CACHE_TTL = 300
CACHE_TIMESTAMPS = {}

def parse_hex_ip_port(hex_str: str) -> tuple[str, int]:
    try:
        ip_part, port_part = hex_str.split(':')
        ip_bytes = bytes.fromhex(ip_part)
        
        if len(ip_bytes) == 4:
            ip = str(ipaddress.IPv4Address(ip_bytes[::-1]))
        elif len(ip_bytes) == 16:
            ip = str(ipaddress.IPv6Address(ip_bytes))
        else:
            raise ValueError(f"Invalid IP length: {len(ip_bytes)}")
        
        port = int(port_part, 16)
        return ip, port
    except ValueError as e:
        raise ValueError(f"Invalid format: {hex_str}, error: {e}")

def get_process_name(inode: str) -> str:
    current_time = time.time()
    
    if inode in PROCESS_CACHE:
        cached_time = CACHE_TIMESTAMPS.get(inode, 0)
        if current_time - cached_time < CACHE_TTL:
            return PROCESS_CACHE[inode]
    
    for pid_dir in glob.glob("/proc/[0-9]*/fd/*"):
        try:
            if os.path.islink(pid_dir) and os.readlink(pid_dir).endswith(f"socket:[{inode}]"):
                pid = pid_dir.split("/")[2]
                with open(f"/proc/{pid}/comm", "r") as f:
                    process_name = f"{f.read().strip()} ({pid})"
                    PROCESS_CACHE[inode] = process_name
                    CACHE_TIMESTAMPS[inode] = current_time
                    return process_name
        except (IOError, OSError):
            continue
    
    PROCESS_CACHE[inode] = "Unknown"
    CACHE_TIMESTAMPS[inode] = current_time
    return "Unknown"

def read_tcp_connections(file_path: str, verbose: bool) -> List[Socket]:
    sockets = []
    if not os.path.exists(file_path):
        return sockets
    if not os.access(file_path, os.R_OK):
        logging.error(f"No read permission for {file_path}")
        return sockets

    try:
        with open(file_path, 'r') as f:
            f.readline()
            for line in f:
                fields = re.split(r'\s+', line.strip())
                if len(fields) < 10:
                    continue
                
                try:
                    local = parse_hex_ip_port(fields[1])
                    remote = parse_hex_ip_port(fields[2])
                    state_code = int(fields[3], 16)
                    inode = fields[9]
                    
                    state = TCP_STATES.get(state_code, f"UNKNOWN({state_code})")
                    process = get_process_name(inode)
                    
                    sockets.append(Socket(
                        local_ip=local[0],
                        local_port=local[1],
                        remote_ip=remote[0],
                        remote_port=remote[1],
                        state=state,
                        process=process
                    ))
                except ValueError:
                    continue
        return sockets
    except IOError as e:
        logging.error(f"Error reading {file_path}: {e}")
        return []

def read_all_connections(tcp_file: str, tcp6_file: str, verbose: bool) -> List[Socket]:
    sockets = []
    sockets.extend(read_tcp_connections(tcp_file, verbose))
    sockets.extend(read_tcp_connections(tcp6_file, verbose))
    return sockets

def check_permissions(file_paths: List[str]) -> None:
    if os.geteuid() != 0:
        for path in file_paths:
            if os.path.exists(path) and not os.access(path, os.R_OK):
                logging.error(f"Need root privileges to read {path}")
                exit(1)

def filter_sockets(sockets: List[Socket], args) -> List[Socket]:
    filtered = sockets
    if args.state:
        state = args.state.upper()
        if state not in TCP_STATES.values():
            logging.error(f"Invalid state: {args.state}")
            exit(1)
        filtered = [s for s in filtered if s.state == state]
    if args.local_ip:
        try:
            local_net = ipaddress.ip_network(args.local_ip, strict=False)
            filtered = [s for s in filtered if ipaddress.ip_address(s.local_ip) in local_net]
        except ValueError as e:
            logging.error(f"Invalid local IP: {args.local_ip}")
            return []
    if args.remote_ip:
        try:
            remote_net = ipaddress.ip_network(args.remote_ip, strict=False)
            filtered = [s for s in filtered if ipaddress.ip_address(s.remote_ip) in remote_net]
        except ValueError as e:
            logging.error(f"Invalid remote IP: {args.remote_ip}")
            return []
    if args.port:
        filtered = [s for s in filtered if s.local_port == args.port or s.remote_port == args.port]
    if args.process:
        filtered = [s for s in filtered if args.process.lower() in s.process.lower()]
    return filtered

def sort_sockets(sockets: List[Socket], sort_by: str) -> List[Socket]:
    if sort_by == "state":
        return sorted(sockets, key=lambda s: s.state)
    elif sort_by == "local_ip":
        return sorted(sockets, key=lambda s: ipaddress.ip_address(s.local_ip))
    elif sort_by == "remote_ip":
        return sorted(sockets, key=lambda s: ipaddress.ip_address(s.remote_ip))
    elif sort_by == "port":
        return sorted(sockets, key=lambda s: (s.local_port, s.remote_port))
    elif sort_by == "process":
        return sorted(sockets, key=lambda s: s.process)
    return sockets

def print_statistics(sockets: List[Socket]):
    if not sockets:
        return
    
    states = {}
    for s in sockets:
        states[s.state] = states.get(s.state, 0) + 1
    
    print("\nCONNECTION STATISTICS:")
    for state, count in sorted(states.items()):
        print(f"  {state}: {count}")

def clear_screen():
    print("\033c", end="")

def display_connections(sockets: List[Socket], output_format: str = "table", no_color: bool = False, 
                       compact_json: bool = False, show_stats: bool = False) -> None:
    if not sockets:
        print("No active TCP connections found")
        return
    
    if output_format == "json":
        indent = None if compact_json else 2
        print(json.dumps([s._asdict() for s in sockets], indent=indent))
        if show_stats:
            print_statistics(sockets)
        return
    
    max_addr_len = max(len("Local Address"), len("Remote Address"))
    max_process_len = len("Process")
    for s in sockets:
        local_addr = f"{s.local_ip}:{s.local_port}"
        remote_addr = f"{s.remote_ip}:{s.remote_port}"
        max_addr_len = max(max_addr_len, len(local_addr), len(remote_addr))
        max_process_len = max(max_process_len, len(s.process))
    
    print("\nACTIVE TCP CONNECTIONS:")
    header = f"{'State':<15} {'Local Address':<{max_addr_len}} {'Remote Address':<{max_addr_len}} {'Process':<{max_process_len}}"
    print(header)
    print("-" * len(header))
    
    for s in sockets:
        local_addr = f"{s.local_ip}:{s.local_port}"
        remote_addr = f"{s.remote_ip}:{s.remote_port}"
        state = s.state if no_color or not sys.stdout.isatty() else STATE_COLORS.get(s.state, "{}").format(s.state)
        print(f"{state:<15} {local_addr:<{max_addr_len}} {remote_addr:<{max_addr_len}} {s.process:<{max_process_len}}")
    
    if show_stats:
        print_statistics(sockets)

def handle_sigint(sig, frame):
    print("\nStopped monitoring")
    exit(0)

def validate_args(args):
    if args.watch < 0:
        raise ValueError("Watch interval must be non-negative")
    if args.port and (args.port < 1 or args.port > 65535):
        raise ValueError("Port must be between 1 and 65535")

def main():
    if platform.system() != "Linux":
        logging.error("This script requires Linux")
        exit(1)
    
    parser = argparse.ArgumentParser(description="TCP Connection Monitor")
    parser.add_argument("--tcp-file", default="/proc/net/tcp", help="Path to TCP file")
    parser.add_argument("--tcp6-file", default="/proc/net/tcp6", help="Path to TCP6 file")
    parser.add_argument("--watch", type=float, default=0, help="Refresh interval in seconds")
    parser.add_argument("--state", help="Filter by connection state")
    parser.add_argument("--local-ip", help="Filter by local IP or subnet")
    parser.add_argument("--remote-ip", help="Filter by remote IP or subnet")
    parser.add_argument("--port", type=int, help="Filter by local or remote port")
    parser.add_argument("--process", help="Filter by process name or PID")
    parser.add_argument("--sort", choices=["state", "local_ip", "remote_ip", "port", "process"], 
                       default="state", help="Sort by field")
    parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    parser.add_argument("--compact-json", action="store_true", help="Use compact JSON output")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--stats", action="store_true", help="Show connection statistics")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)

    try:
        validate_args(args)
    except ValueError as e:
        logging.error(f"Argument error: {e}")
        exit(1)

    check_permissions([args.tcp_file, args.tcp6_file])

    if args.watch > 0:
        signal.signal(signal.SIGINT, handle_sigint)

    if args.watch > 0:
        while True:
            sockets = read_all_connections(args.tcp_file, args.tcp6_file, args.verbose)
            sockets = filter_sockets(sockets, args)
            sockets = sort_sockets(sockets, args.sort)
            clear_screen()
            display_connections(sockets, args.format, args.no_color, args.compact_json, args.stats)
            time.sleep(args.watch)
    else:
        sockets = read_all_connections(args.tcp_file, args.tcp6_file, args.verbose)
        sockets = filter_sockets(sockets, args)
        sockets = sort_sockets(sockets, args.sort)
        display_connections(sockets, args.format, args.no_color, args.compact_json, args.stats)

if __name__ == "__main__":
    main()
