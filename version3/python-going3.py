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
from collections import defaultdict, Counter
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
import ipaddress
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import csv
import io
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
    timestamp: float
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
    def get(self, inode: str, pid: str) -> Optional[str]:
        if inode in self.cache:
            if time.time() - self.timestamps[inode] < self.ttl and Path(f"/proc/{pid}").exists():
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
    def __init__(self, verbose: bool = False, history_ttl: int = 300, rate_limit: int = 10, rate_window: int = 60, max_history: int = 10000):
        self.verbose = verbose
        self.start_time = time.time()
        self.connection_history = defaultdict(list)
        self.history_ttl = history_ttl
        self.rate_limit = rate_limit
        self.rate_window = rate_window
        self.max_history = max_history
        self.suspicious_ports = {21, 22, 23, 25, 53, 80, 110, 443, 993, 995}
        self.trusted_processes = {"sshd", "nginx", "apache2", "httpd", "mysqld", "postgres"}
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
        try:
            for pid_dir in Path("/proc").glob("[0-9]*/fd/*"):
                try:
                    if pid_dir.is_symlink() and f"socket:[{inode}]" in str(pid_dir.readlink()):
                        pid = pid_dir.parent.parent.name
                        cached = PROCESS_CACHE.get(inode, pid)
                        if cached:
                            return cached
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
            with open(file_path, 'r') as f:
                content = f.readlines()
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
                        inode=inode,
                        timestamp=time.time()
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
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_file = {executor.submit(self.read_proc_net_file, Path(file_path), protocol): protocol for file_path, protocol in protocols}
            for future in future_to_file:
                file_sockets = future.result()
                sockets.extend(file_sockets)
                if self.verbose:
                    logging.info(f"Found {len(file_sockets)} connections in {future_to_file[future]}")
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
        if filters.get('pid'):
            filtered = [s for s in filtered if f"({filters['pid']})" in s.process]
        return filtered
    def sort_connections(self, sockets: List[Socket], sort_by: str) -> List[Socket]:
        sort_functions = {
            "state": lambda s: s.state,
            "local_ip": lambda s: ipaddress.ip_address(s.local_ip),
            "remote_ip": lambda s: ipaddress.ip_address(s.remote_ip),
            "port": lambda s: (s.local_port, s.remote_port),
            "process": lambda s: s.process,
            "protocol": lambda s: s.protocol,
            "timestamp": lambda s: s.timestamp
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
        for socket in sockets:
            if socket.remote_port in self.suspicious_ports and socket.state == "ESTABLISHED":
                process_name = socket.process.split()[0].lower()
                if process_name not in self.trusted_processes:
                    anomalies.append({
                        'type': 'SUSPICIOUS_PORT',
                        'socket': socket,
                        'reason': f'Connection to well-known port {socket.remote_port} by unexpected process',
                        'severity': 'HIGH',
                        'score': 0.8
                    })
            if socket.state.startswith("UNKNOWN"):
                anomalies.append({
                    'type': 'UNKNOWN_STATE',
                    'socket': socket,
                    'reason': f'Connection in unknown state {socket.state}',
                    'severity': 'MEDIUM',
                    'score': 0.5
                })
            key = (socket.remote_ip, socket.remote_port, socket.process)
            self.connection_history[key].append(socket.timestamp)
            if len(self.connection_history[key]) > self.rate_limit and (self.connection_history[key][-1] - self.connection_history[key][0]) < self.rate_window:
                anomalies.append({
                    'type': 'HIGH_CONNECTION_RATE',
                    'socket': socket,
                    'reason': f'High connection rate to {socket.remote_ip}:{socket.remote_port}',
                    'severity': 'HIGH',
                    'score': 0.9
                })
            ip_pairs = Counter((s.remote_ip, s.remote_port) for s in sockets if s.process == socket.process)
            if ip_pairs[(socket.remote_ip, socket.remote_port)] > 20:
                anomalies.append({
                    'type': 'POTENTIAL_SCAN',
                    'socket': socket,
                    'reason': f'Process connecting to multiple IPs/ports',
                    'severity': 'HIGH',
                    'score': 0.85
                })
        if len(self.connection_history) > self.max_history:
            oldest_keys = sorted(self.connection_history.keys(), key=lambda k: self.connection_history[k][-1])[:len(self.connection_history) - self.max_history]
            for key in oldest_keys:
                del self.connection_history[key]
        for key in list(self.connection_history.keys()):
            if time.time() - self.connection_history[key][-1] > self.history_ttl:
                del self.connection_history[key]
        return anomalies
class OutputFormatter:
    @staticmethod
    def format_table(sockets: List[Socket], stats: Optional[Dict] = None, no_color: bool = False, anomalies: List[Dict] = None, columns: List[str] = None) -> str:
        if not sockets:
            return "No connections found\n"
        default_columns = ["protocol", "state", "local_address", "remote_address", "process"]
        columns = columns or default_columns
        headers = {"protocol": "Protocol", "state": "State", "local_address": "Local Address", "remote_address": "Remote Address", "process": "Process", "timestamp": "Timestamp"}
        max_lengths = {col: len(headers[col]) for col in columns}
        for socket in sockets:
            values = {
                "protocol": socket.protocol,
                "state": socket.state,
                "local_address": f"{socket.local_ip}:{socket.local_port}",
                "remote_address": f"{socket.remote_ip}:{socket.remote_port}",
                "process": socket.process,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(socket.timestamp))
            }
            for col in columns:
                max_lengths[col] = max(max_lengths[col], len(values[col]))
        output = []
        output.append("\nACTIVE NETWORK CONNECTIONS:")
        header = " ".join(f"{headers[col]:<{max_lengths[col]}}" for col in columns)
        output.append(header)
        output.append("-" * len(header))
        for socket in sockets:
            values = {
                "protocol": socket.protocol,
                "state": socket.state if no_color or not sys.stdout.isatty() else f"{STATE_COLORS.get(socket.state, '')}{socket.state}\033[0m" if STATE_COLORS.get(socket.state) else socket.state,
                "local_address": f"{socket.local_ip}:{socket.local_port}",
                "remote_address": f"{socket.remote_ip}:{socket.remote_port}",
                "process": socket.process,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(socket.timestamp))
            }
            output.append(" ".join(f"{values[col]:<{max_lengths[col]}}" for col in columns))
        if anomalies:
            output.extend(OutputFormatter.format_anomalies(anomalies))
        if stats:
            output.extend(OutputFormatter.format_stats(stats))
        return "\n".join(output)
    @staticmethod
    def format_json(sockets: List[Socket], stats: Optional[Dict] = None, compact: bool = False, anomalies: List[Dict] = None, columns: List[str] = None) -> str:
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
                    'inode': s.inode,
                    'timestamp': s.timestamp
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
                    'score': a['score'],
                    'socket': {
                        'protocol': a['socket'].protocol,
                        'local_ip': a['socket'].local_ip,
                        'local_port': a['socket'].local_port,
                        'remote_ip': a['socket'].remote_ip,
                        'remote_port': a['socket'].remote_port,
                        'state': a['socket'].state,
                        'process': a['socket'].process,
                        'timestamp': a['socket'].timestamp
                    }
                } for a in anomalies
            ]
        indent = None if compact else 2
        return json.dumps(output, indent=indent)
    @staticmethod
    def format_csv(sockets: List[Socket], stats: Optional[Dict] = None, anomalies: List[Dict] = None, columns: List[str] = None) -> str:
        output = io.StringIO()
        default_columns = ["protocol", "state", "local_address", "remote_address", "process", "timestamp"]
        columns = columns or default_columns
        writer = csv.DictWriter(output, fieldnames=columns, lineterminator='\n')
        writer.writeheader()
        for socket in sockets:
            writer.writerow({
                "protocol": socket.protocol,
                "state": socket.state,
                "local_address": f"{socket.local_ip}:{socket.local_port}",
                "remote_address": f"{socket.remote_ip}:{socket.remote_port}",
                "process": socket.process,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(socket.timestamp))
            })
        return output.getvalue()
    @staticmethod
    def format_stats(stats: Dict) -> List[str]:
        output = []
        output.append("\nCONNECTION STATISTICS:")
        output.append(f" Total connections: {stats['total']}")
        output.append(" By state:")
        for state, count in sorted(stats['by_state'].items()):
            output.append(f" {state}: {count}")
        output.append(" By protocol:")
        for protocol, count in sorted(stats['by_protocol'].items()):
            output.append(f" {protocol}: {count}")
        output.append(" Top processes:")
        for process, count in stats['top_processes']:
            output.append(f" {process}: {count}")
        output.append(f" Unique IP pairs: {stats['unique_ips']}")
        return output
    @staticmethod
    def format_anomalies(anomalies: List[Dict]) -> List[str]:
        output = []
        output.append(f"\nSECURITY ANOMALIES ({len(anomalies)} detected):")
        for anomaly in anomalies:
            output.append(f" [{anomaly['severity']}] {anomaly['type']}: {anomaly['reason']} (Score: {anomaly['score']:.2f})")
            socket = anomaly['socket']
            output.append(f" {socket.protocol} {socket.local_ip}:{socket.local_port} -> {socket.remote_ip}:{socket.remote_port} ({socket.process})")
        return output
    @staticmethod
    def clear_screen():
        if sys.stdout.isatty():
            print("\033c", end="")
def signal_handler(sig, frame):
    print("\nMonitoring stopped")
    sys.exit(0)
def parse_port_range(port_input: str) -> set:
    ports = set()
    for part in port_input.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise ValueError("Ports must be between 1 and 65535")
            ports.update(range(start, end + 1))
        else:
            port = int(part)
            if not (1 <= port <= 65535):
                raise ValueError("Ports must be between 1 and 65535")
            ports.add(port)
    return ports
def validate_args(args):
    if args.watch < 0:
        raise ValueError("Watch interval must be non-negative")
    if args.port and not (1 <= args.port <= 65535):
        raise ValueError("Port must be between 1 and 65535")
    if args.limit and args.limit < 1:
        raise ValueError("Limit must be at least 1")
    if args.protocol and args.protocol.upper() not in {"TCP", "TCP6", "UDP", "UDP6"}:
        raise ValueError("Protocol must be one of TCP, TCP6, UDP, UDP6")
    if args.cache_ttl <= 0:
        raise ValueError("Cache TTL must be positive")
    if args.history_ttl <= 0:
        raise ValueError("History TTL must be positive")
    if args.rate_limit < 1:
        raise ValueError("Rate limit must be at least 1")
    if args.rate_window <= 0:
        raise ValueError("Rate window must be positive")
    if args.max_history < 1:
        raise ValueError("Max history size must be at least 1")
def main():
    if platform.system() != "Linux":
        logging.error("This script requires Linux. For non-Linux systems, install 'psutil' for limited functionality.")
        sys.exit(1)
    parser = argparse.ArgumentParser(description="Network Connection Monitor\nExamples:\n  python network_monitor.py --watch 5 --security-scan --suspicious-ports 22,80,443\n  python network_monitor.py --format csv --pid 1234")
    parser.add_argument("--watch", type=float, default=0, help="Refresh interval in seconds")
    parser.add_argument("--state", help="Filter by connection state")
    parser.add_argument("--local-ip", help="Filter by local IP or subnet")
    parser.add_argument("--remote-ip", help="Filter by remote IP or subnet")
    parser.add_argument("--port", type=int, help="Filter by local or remote port")
    parser.add_argument("--process", help="Filter by process name")
    parser.add_argument("--pid", type=int, help="Filter by process ID")
    parser.add_argument("--protocol", help="Filter by protocol (TCP, TCP6, UDP, UDP6)")
    parser.add_argument("--sort", choices=["state", "local_ip", "remote_ip", "port", "process", "protocol", "timestamp"],
                        default="state", help="Sort by field")
    parser.add_argument("--format", choices=["table", "json", "csv"], default="table", help="Output format")
    parser.add_argument("--compact-json", action="store_true", help="Use compact JSON output")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--stats", action="store_true", help="Show connection statistics")
    parser.add_argument("--limit", type=int, help="Limit number of connections displayed")
    parser.add_argument("--clear-cache", action="store_true", help="Clear process cache")
    parser.add_argument("--security-scan", action="store_true", help="Enable security anomaly detection")
    parser.add_argument("--suspicious-ports", type=str, help="Comma-separated list or range of suspicious ports (e.g., 22,80,443 or 80-443)")
    parser.add_argument("--trusted-processes", type=str, help="Comma-separated list of trusted process names")
    parser.add_argument("--cache-ttl", type=int, default=300, help="Process cache TTL in seconds")
    parser.add_argument("--history-ttl", type=int, default=300, help="Connection history TTL in seconds")
    parser.add_argument("--rate-limit", type=int, default=10, help="Max connections for rate limiting")
    parser.add_argument("--rate-window", type=int, default=60, help="Time window for rate limiting in seconds")
    parser.add_argument("--max-history", type=int, default=10000, help="Max number of connection history entries")
    parser.add_argument("--columns", type=str, help="Comma-separated list of columns to display (protocol, state, local_address, remote_address, process, timestamp)")
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
        logging.warning("Running without root privileges - some process information may be unavailable. Consider using sudo.")
    PROCESS_CACHE.ttl = args.cache_ttl
    monitor = NetworkMonitor(verbose=args.verbose, history_ttl=args.history_ttl, rate_limit=args.rate_limit, rate_window=args.rate_window, max_history=args.max_history)
    formatter = OutputFormatter()
    filters = {
        'state': args.state,
        'local_ip': args.local_ip,
        'remote_ip': args.remote_ip,
        'port': args.port,
        'process': args.process,
        'protocol': args.protocol,
        'pid': args.pid
    }
    if args.suspicious_ports:
        try:
            monitor.suspicious_ports = parse_port_range(args.suspicious_ports) if args.suspicious_ports else set()
        except ValueError as e:
            logging.error(f"Invalid suspicious ports format: {e}")
            sys.exit(1)
    if args.trusted_processes:
        monitor.trusted_processes = set(args.trusted_processes.split(','))
    columns = args.columns.split(',') if args.columns else None
    if columns:
        valid_columns = {"protocol", "state", "local_address", "remote_address", "process", "timestamp"}
        if not all(col in valid_columns for col in columns):
            logging.error(f"Invalid columns: {args.columns}. Valid columns: {', '.join(valid_columns)}")
            sys.exit(1)
    for file_path in ["/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"]:
        if not os.access(file_path, os.R_OK):
            logging.error(f"Cannot read {file_path}. Ensure proper permissions or run with sudo.")
            sys.exit(1)
    if args.watch > 0:
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGHUP, signal_handler)
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
                    print(formatter.format_json(sockets, stats, args.compact_json, anomalies, columns))
                elif args.format == "csv":
                    print(formatter.format_csv(sockets, stats, anomalies, columns))
                else:
                    print(formatter.format_table(sockets, stats, args.no_color, anomalies, columns))
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
            print(formatter.format_json(sockets, stats, args.compact_json, anomalies, columns))
        elif args.format == "csv":
            print(formatter.format_csv(sockets, stats, anomalies, columns))
        else:
            print(formatter.format_table(sockets, stats, args.no_color, anomalies, columns))
if __name__ == "__main__":
    main()
