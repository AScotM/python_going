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
from collections import defaultdict, Counter
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
import ipaddress
from pathlib import Path

logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')

@dataclass(frozen=True)
class Socket:
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    process: str
    protocol: str
    inode: str

TCP_STATES = {
    1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1",
    5: "FIN_WAIT2", 6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT",
    9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING", 12: "NEW_SYN_RECV",
}

STATE_COLORS = {
    "ESTABLISHED": "\033[32m", "LISTEN": "\033[34m", "CLOSE": "\033[31m",
    "TIME_WAIT": "\033[33m", "SYN_SENT": "\033[36m", "SYN_RECV": "\033[36m",
    "FIN_WAIT1": "\033[35m", "FIN_WAIT2": "\033[35m", "CLOSE_WAIT": "\033[31m",
    "LAST_ACK": "\033[31m", "CLOSING": "\033[31m", "NEW_SYN_RECV": "\033[36m",
}

class ProcessCache:
    def __init__(self, ttl: int = 300):
        self.cache = {}
        self.timestamps = {}
        self.ttl = ttl
    
    def get(self, inode: str) -> Optional[str]:
        if inode in self.cache:
            if time.time() - self.timestamps[inode] < self.ttl:
                return self.cache[inode]
            else:
                del self.cache[inode]
                del self.timestamps[inode]
        return None
    
    def set(self, inode: str, value: str):
        self.cache[inode] = value
        self.timestamps[inode] = time.time()
    
    def clear(self):
        self.cache.clear()
        self.timestamps.clear()

PROCESS_CACHE = ProcessCache()

class NetworkMonitor:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.start_time = time.time()
    
    def parse_hex_ip_port(self, hex_str: str) -> Tuple[str, int]:
        try:
            ip_part, port_part = hex_str.split(':')
            ip_bytes = bytes.fromhex(ip_part)
            
            if len(ip_bytes) == 4:
                ip = '.'.join(str(b) for b in ip_bytes[::-1])
            elif len(ip_bytes) == 16:
                ip = ':'.join(f'{ip_bytes[i]:02x}{ip_bytes[i+1]:02x}' for i in range(0, 16, 2))
                ip = ipaddress.IPv6Address(ip).compressed
            else:
                raise ValueError(f"Invalid IP length: {len(ip_bytes)}")
            
            port = int(port_part, 16)
            return ip, port
        except ValueError as e:
            if self.verbose:
                logging.debug(f"Failed to parse {hex_str}: {e}")
            raise

    def get_process_info(self, inode: str) -> str:
        cached = PROCESS_CACHE.get(inode)
        if cached:
            return cached
        
        try:
            for pid_dir in Path("/proc").glob("[0-9]*/fd/*"):
                try:
                    if pid_dir.is_symlink() and f"socket:[{inode}]" in str(pid_dir.readlink()):
                        pid = pid_dir.parent.parent.name
                        comm_file = Path(f"/proc/{pid}/comm")
                        if comm_file.exists():
                            process_name = f"{comm_file.read_text().strip()} ({pid})"
                            PROCESS_CACHE.set(inode, process_name)
                            return process_name
                except (OSError, IOError):
                    continue
        except Exception as e:
            if self.verbose:
                logging.debug(f"Process lookup failed for inode {inode}: {e}")
        
        PROCESS_CACHE.set(inode, "Unknown")
        return "Unknown"

    def read_proc_net_file(self, file_path: Path, protocol: str) -> List[Socket]:
        sockets = []
        if not file_path.exists():
            if self.verbose:
                logging.info(f"File {file_path} does not exist")
            return sockets
            
        if not os.access(file_path, os.R_OK):
            logging.error(f"No read permission for {file_path}")
            return sockets

        try:
            content = file_path.read_text().splitlines()
            if len(content) < 2:
                return sockets
            
            for line_num, line in enumerate(content[1:], 2):
                fields = re.split(r'\s+', line.strip())
                if len(fields) < 10:
                    if self.verbose:
                        logging.debug(f"Skipping line {line_num}: insufficient fields")
                    continue
                
                try:
                    local_ip, local_port = self.parse_hex_ip_port(fields[1])
                    remote_ip, remote_port = self.parse_hex_ip_port(fields[2])
                    state_code = int(fields[3], 16)
                    inode = fields[9]
                    
                    state = TCP_STATES.get(state_code, f"UNKNOWN({state_code})")
                    process = self.get_process_info(inode)
                    
                    socket = Socket(
                        local_ip=local_ip,
                        local_port=local_port,
                        remote_ip=remote_ip,
                        remote_port=remote_port,
                        state=state,
                        process=process,
                        protocol=protocol,
                        inode=inode
                    )
                    sockets.append(socket)
                    
                except ValueError as e:
                    if self.verbose:
                        logging.debug(f"Skipping line {line_num}: {e}")
                    continue
                except Exception as e:
                    if self.verbose:
                        logging.debug(f"Unexpected error on line {line_num}: {e}")
                    continue
                        
            return sockets
        except IOError as e:
            logging.error(f"Error reading {file_path}: {e}")
            return []
        except Exception as e:
            logging.error(f"Unexpected error processing {file_path}: {e}")
            return []

    def get_all_connections(self) -> List[Socket]:
        sockets = []
        protocols = [
            ("/proc/net/tcp", "TCP"),
            ("/proc/net/tcp6", "TCP6"),
            ("/proc/net/udp", "UDP"),
            ("/proc/net/udp6", "UDP6")
        ]
        
        for file_path, protocol in protocols:
            file_sockets = self.read_proc_net_file(Path(file_path), protocol)
            sockets.extend(file_sockets)
            if self.verbose:
                logging.info(f"Found {len(file_sockets)} connections in {file_path}")
        
        return sockets

    def filter_connections(self, sockets: List[Socket], filters: Dict) -> List[Socket]:
        filtered = sockets
        
        if filters.get('state'):
            state = filters['state'].upper()
            if state not in TCP_STATES.values():
                logging.error(f"Invalid state: {state}. Valid states: {', '.join(TCP_STATES.values())}")
                return []
            filtered = [s for s in filtered if s.state == state]
        
        if filters.get('local_ip'):
            try:
                local_net = ipaddress.ip_network(filters['local_ip'], strict=False)
                filtered = [s for s in filtered if ipaddress.ip_address(s.local_ip) in local_net]
            except ValueError as e:
                logging.error(f"Invalid local IP: {filters['local_ip']}")
                return []
        
        if filters.get('remote_ip'):
            try:
                remote_net = ipaddress.ip_network(filters['remote_ip'], strict=False)
                filtered = [s for s in filtered if ipaddress.ip_address(s.remote_ip) in remote_net]
            except ValueError as e:
                logging.error(f"Invalid remote IP: {filters['remote_ip']}")
                return []
        
        if filters.get('port'):
            port = filters['port']
            filtered = [s for s in filtered if s.local_port == port or s.remote_port == port]
        
        if filters.get('process'):
            process_filter = filters['process'].lower()
            filtered = [s for s in filtered if process_filter in s.process.lower()]
        
        if filters.get('protocol'):
            protocol_filter = filters['protocol'].upper()
            filtered = [s for s in filtered if protocol_filter in s.protocol]
        
        return filtered

    def sort_connections(self, sockets: List[Socket], sort_by: str) -> List[Socket]:
        sort_functions = {
            "state": lambda s: s.state,
            "local_ip": lambda s: ipaddress.ip_address(s.local_ip),
            "remote_ip": lambda s: ipaddress.ip_address(s.remote_ip),
            "port": lambda s: (s.local_port, s.remote_port),
            "process": lambda s: s.process,
            "protocol": lambda s: s.protocol
        }
        
        if sort_by in sort_functions:
            return sorted(sockets, key=sort_functions[sort_by])
        return sockets

    def calculate_statistics(self, sockets: List[Socket]) -> Dict:
        stats = {
            'total': len(sockets),
            'by_state': Counter(s.state for s in sockets),
            'by_protocol': Counter(s.protocol for s in sockets),
            'top_processes': Counter(s.process for s in sockets).most_common(5),
            'unique_ips': len(set(f"{s.local_ip}:{s.remote_ip}" for s in sockets)),
            'timestamp': time.time()
        }
        return stats

    def detect_anomalies(self, sockets: List[Socket]) -> List[Dict]:
        anomalies = []
        suspicious_ports = {21, 22, 23, 25, 53, 80, 110, 443, 993, 995}
        
        for socket in sockets:
            if socket.remote_port in suspicious_ports and socket.state == "ESTABLISHED":
                anomalies.append({
                    'type': 'SUSPICIOUS_PORT',
                    'socket': socket,
                    'reason': f'Connection to well-known port {socket.remote_port}',
                    'severity': 'MEDIUM'
                })
        
        return anomalies

class OutputFormatter:
    @staticmethod
    def format_table(sockets: List[Socket], stats: Optional[Dict] = None, no_color: bool = False, anomalies: List[Dict] = None) -> str:
        if not sockets:
            return "No connections found\n"
        
        max_local_len = max(len(f"{s.local_ip}:{s.local_port}") for s in sockets)
        max_remote_len = max(len(f"{s.remote_ip}:{s.remote_port}") for s in sockets)
        max_process_len = max(len(s.process) for s in sockets)
        
        max_local_len = max(max_local_len, len("Local Address"))
        max_remote_len = max(max_remote_len, len("Remote Address"))
        max_process_len = max(max_process_len, len("Process"))
        
        output = []
        output.append("\nACTIVE NETWORK CONNECTIONS:")
        header = f"{'Protocol':<8} {'State':<12} {'Local Address':<{max_local_len}} {'Remote Address':<{max_remote_len}} {'Process':<{max_process_len}}"
        output.append(header)
        output.append("-" * len(header))
        
        for socket in sockets:
            local_addr = f"{socket.local_ip}:{socket.local_port}"
            remote_addr = f"{socket.remote_ip}:{socket.remote_port}"
            
            if no_color or not sys.stdout.isatty():
                state = socket.state
            else:
                color = STATE_COLORS.get(socket.state, "")
                state = f"{color}{socket.state}\033[0m" if color else socket.state
            
            output.append(f"{socket.protocol:<8} {state:<12} {local_addr:<{max_local_len}} {remote_addr:<{max_remote_len}} {socket.process:<{max_process_len}}")
        
        if anomalies:
            output.extend(OutputFormatter.format_anomalies(anomalies))
        
        if stats:
            output.extend(OutputFormatter.format_stats(stats))
        
        return "\n".join(output)

    @staticmethod
    def format_json(sockets: List[Socket], stats: Optional[Dict] = None, compact: bool = False, anomalies: List[Dict] = None) -> str:
        output = {
            'connections': [
                {
                    'protocol': s.protocol,
                    'local_ip': s.local_ip,
                    'local_port': s.local_port,
                    'remote_ip': s.remote_ip,
                    'remote_port': s.remote_port,
                    'state': s.state,
                    'process': s.process,
                    'inode': s.inode
                } for s in sockets
            ]
        }
        
        if stats:
            output['statistics'] = stats
        
        if anomalies:
            output['anomalies'] = [
                {
                    'type': a['type'],
                    'reason': a['reason'],
                    'severity': a['severity'],
                    'socket': {
                        'protocol': a['socket'].protocol,
                        'local_ip': a['socket'].local_ip,
                        'local_port': a['socket'].local_port,
                        'remote_ip': a['socket'].remote_ip,
                        'remote_port': a['socket'].remote_port,
                        'state': a['socket'].state,
                        'process': a['socket'].process
                    }
                } for a in anomalies
            ]
        
        indent = None if compact else 2
        return json.dumps(output, indent=indent)

    @staticmethod
    def format_stats(stats: Dict) -> List[str]:
        output = []
        output.append("\nCONNECTION STATISTICS:")
        output.append(f"  Total connections: {stats['total']}")
        output.append("  By state:")
        for state, count in sorted(stats['by_state'].items()):
            output.append(f"    {state}: {count}")
        output.append("  By protocol:")
        for protocol, count in sorted(stats['by_protocol'].items()):
            output.append(f"    {protocol}: {count}")
        output.append("  Top processes:")
        for process, count in stats['top_processes']:
            output.append(f"    {process}: {count}")
        output.append(f"  Unique IP pairs: {stats['unique_ips']}")
        return output

    @staticmethod
    def format_anomalies(anomalies: List[Dict]) -> List[str]:
        output = []
        output.append(f"\nSECURITY ANOMALIES ({len(anomalies)} detected):")
        for anomaly in anomalies:
            output.append(f"  [{anomaly['severity']}] {anomaly['type']}: {anomaly['reason']}")
            socket = anomaly['socket']
            output.append(f"    {socket.protocol} {socket.local_ip}:{socket.local_port} -> {socket.remote_ip}:{socket.remote_port} ({socket.process})")
        return output

    @staticmethod
    def clear_screen():
        if sys.stdout.isatty():
            print("\033c", end="")

def signal_handler(sig, frame):
    print("\nMonitoring stopped")
    sys.exit(0)

def validate_args(args):
    if args.watch < 0:
        raise ValueError("Watch interval must be non-negative")
    if args.port and not (1 <= args.port <= 65535):
        raise ValueError("Port must be between 1 and 65535")
    if args.limit and args.limit < 1:
        raise ValueError("Limit must be at least 1")

def main():
    if platform.system() != "Linux":
        logging.error("This script requires Linux")
        sys.exit(1)
    
    parser = argparse.ArgumentParser(description="Network Connection Monitor")
    parser.add_argument("--watch", type=float, default=0, help="Refresh interval in seconds")
    parser.add_argument("--state", help="Filter by connection state")
    parser.add_argument("--local-ip", help="Filter by local IP or subnet")
    parser.add_argument("--remote-ip", help="Filter by remote IP or subnet")
    parser.add_argument("--port", type=int, help="Filter by local or remote port")
    parser.add_argument("--process", help="Filter by process name or PID")
    parser.add_argument("--protocol", help="Filter by protocol")
    parser.add_argument("--sort", choices=["state", "local_ip", "remote_ip", "port", "process", "protocol"], 
                       default="state", help="Sort by field")
    parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    parser.add_argument("--compact-json", action="store_true", help="Use compact JSON output")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--stats", action="store_true", help="Show connection statistics")
    parser.add_argument("--limit", type=int, help="Limit number of connections displayed")
    parser.add_argument("--clear-cache", action="store_true", help="Clear process cache")
    parser.add_argument("--security-scan", action="store_true", help="Enable security anomaly detection")
    
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)

    try:
        validate_args(args)
    except ValueError as e:
        logging.error(f"Argument error: {e}")
        sys.exit(1)

    if args.clear_cache:
        PROCESS_CACHE.clear()
        print("Process cache cleared")
        return

    if os.geteuid() != 0:
        logging.warning("Running without root privileges - some process information may be unavailable")

    monitor = NetworkMonitor(verbose=args.verbose)
    formatter = OutputFormatter()

    filters = {
        'state': args.state,
        'local_ip': args.local_ip,
        'remote_ip': args.remote_ip,
        'port': args.port,
        'process': args.process,
        'protocol': args.protocol
    }

    if args.watch > 0:
        signal.signal(signal.SIGINT, signal_handler)
        
        try:
            while True:
                sockets = monitor.get_all_connections()
                if args.verbose:
                    logging.info(f"Total connections found: {len(sockets)}")
                
                sockets = monitor.filter_connections(sockets, filters)
                sockets = monitor.sort_connections(sockets, args.sort)
                
                if args.limit:
                    sockets = sockets[:args.limit]
                
                stats = monitor.calculate_statistics(sockets) if args.stats else None
                anomalies = monitor.detect_anomalies(sockets) if args.security_scan else None
                
                formatter.clear_screen()
                
                if args.format == "json":
                    print(formatter.format_json(sockets, stats, args.compact_json, anomalies))
                else:
                    print(formatter.format_table(sockets, stats, args.no_color, anomalies))
                
                time.sleep(args.watch)
        except KeyboardInterrupt:
            signal_handler(None, None)
    else:
        sockets = monitor.get_all_connections()
        if args.verbose:
            logging.info(f"Total connections found: {len(sockets)}")
        
        sockets = monitor.filter_connections(sockets, filters)
        sockets = monitor.sort_connections(sockets, args.sort)
        
        if args.limit:
            sockets = sockets[:args.limit]
        
        stats = monitor.calculate_statistics(sockets) if args.stats else None
        anomalies = monitor.detect_anomalies(sockets) if args.security_scan else None
        
        if args.format == "json":
            print(formatter.format_json(sockets, stats, args.compact_json, anomalies))
        else:
            print(formatter.format_table(sockets, stats, args.no_color, anomalies))

if __name__ == "__main__":
    main()
