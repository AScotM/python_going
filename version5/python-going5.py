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
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple, Set, Any
from enum import Enum
import ipaddress
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
import csv
import io
from abc import ABC, abstractmethod
import threading
import subprocess

logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM" 
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

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
    pid: Optional[int] = None

@dataclass
class Anomaly:
    type: str
    socket: Socket
    reason: str
    severity: Severity
    score: float
    timestamp: float

@dataclass
class MonitorConfig:
    verbose: bool = False
    history_ttl: int = 300
    rate_limit: int = 10
    rate_window: int = 60
    max_history: int = 10000
    cache_ttl: int = 300
    suspicious_ports: Set[int] = None
    trusted_processes: Set[str] = None
    
    def __post_init__(self):
        if self.suspicious_ports is None:
            self.suspicious_ports = {21, 22, 23, 25, 53, 80, 110, 443, 993, 995}
        if self.trusted_processes is None:
            self.trusted_processes = {"sshd", "nginx", "apache2", "httpd", "mysqld", "postgres"}

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
        self.pid_cache = {}
        self.timestamps = {}
        self.ttl = ttl
        self._lock = threading.RLock()

    def get(self, inode: str, pid: Optional[int] = None) -> Optional[str]:
        with self._lock:
            if inode in self.cache:
                if time.time() - self.timestamps[inode] < self.ttl:
                    if pid and Path(f"/proc/{pid}").exists():
                        return self.cache[inode]
                    elif not pid:
                        return self.cache[inode]
                else:
                    del self.cache[inode]
                    del self.timestamps[inode]
            return None

    def get_by_pid(self, pid: int) -> Optional[str]:
        with self._lock:
            if pid in self.pid_cache:
                if time.time() - self.pid_cache[pid]['timestamp'] < self.ttl:
                    if Path(f"/proc/{pid}").exists():
                        return self.pid_cache[pid]['name']
                else:
                    del self.pid_cache[pid]
            return None

    def set(self, inode: str, value: str, pid: int = None):
        with self._lock:
            self.cache[inode] = value
            self.timestamps[inode] = time.time()
            if pid:
                self.pid_cache[pid] = {'name': value, 'timestamp': time.time()}

    def clear(self):
        with self._lock:
            self.cache.clear()
            self.pid_cache.clear()
            self.timestamps.clear()

    def cleanup_expired(self):
        with self._lock:
            current_time = time.time()
            expired_inodes = [inode for inode, ts in self.timestamps.items() 
                            if current_time - ts >= self.ttl]
            for inode in expired_inodes:
                del self.cache[inode]
                del self.timestamps[inode]
            
            expired_pids = [pid for pid, data in self.pid_cache.items() 
                          if current_time - data['timestamp'] >= self.ttl]
            for pid in expired_pids:
                del self.pid_cache[pid]

PROCESS_CACHE = ProcessCache()

class AnomalyDetector(ABC):
    @abstractmethod
    def detect(self, socket: Socket, history: Dict, config: MonitorConfig) -> Optional[Anomaly]:
        pass

class SuspiciousPortDetector(AnomalyDetector):
    def detect(self, socket: Socket, history: Dict, config: MonitorConfig) -> Optional[Anomaly]:
        if (socket.remote_port in config.suspicious_ports and 
            socket.state == "ESTABLISHED"):
            process_name = socket.process.split()[0].lower() if socket.process else "unknown"
            if process_name not in config.trusted_processes:
                return Anomaly(
                    type='SUSPICIOUS_PORT',
                    socket=socket,
                    reason=f'Connection to well-known port {socket.remote_port} by unexpected process: {process_name}',
                    severity=Severity.HIGH,
                    score=0.8,
                    timestamp=time.time()
                )
        return None

class ConnectionRateDetector(AnomalyDetector):
    def detect(self, socket: Socket, history: Dict, config: MonitorConfig) -> Optional[Anomaly]:
        key = (socket.remote_ip, socket.remote_port, socket.process)
        if key in history:
            timestamps = history[key]
            recent_timestamps = [ts for ts in timestamps if time.time() - ts < config.rate_window]
            history[key] = recent_timestamps
            
            if len(recent_timestamps) > config.rate_limit:
                return Anomaly(
                    type='HIGH_CONNECTION_RATE',
                    socket=socket,
                    reason=f'High connection rate to {socket.remote_ip}:{socket.remote_port} '
                          f'({len(recent_timestamps)} connections in {config.rate_window}s)',
                    severity=Severity.HIGH,
                    score=0.9,
                    timestamp=time.time()
                )
        return None

class PortScanDetector(AnomalyDetector):
    def detect(self, socket: Socket, history: Dict, config: MonitorConfig) -> Optional[Anomaly]:
        process_connections = Counter()
        for key in history:
            if key[2] == socket.process:
                process_connections[key] += 1
        
        if len(process_connections) > 20:
            return Anomaly(
                type='POTENTIAL_SCAN',
                socket=socket,
                reason=f'Process connecting to multiple endpoints: {len(process_connections)} unique connections',
                severity=Severity.HIGH,
                score=0.85,
                timestamp=time.time()
            )
        return None

class UnknownStateDetector(AnomalyDetector):
    def detect(self, socket: Socket, history: Dict, config: MonitorConfig) -> Optional[Anomaly]:
        if socket.state.startswith("UNKNOWN"):
            return Anomaly(
                type='UNKNOWN_STATE',
                socket=socket,
                reason=f'Connection in unknown state: {socket.state}',
                severity=Severity.MEDIUM,
                score=0.5,
                timestamp=time.time()
            )
        return None

class SecurityScanner:
    def __init__(self, config: MonitorConfig):
        self.config = config
        self.detectors = [
            SuspiciousPortDetector(),
            ConnectionRateDetector(),
            PortScanDetector(),
            UnknownStateDetector()
        ]
    
    def scan(self, sockets: List[Socket], history: Dict) -> List[Anomaly]:
        anomalies = []
        
        for socket in sockets:
            for detector in self.detectors:
                try:
                    anomaly = detector.detect(socket, history, self.config)
                    if anomaly:
                        anomalies.append(anomaly)
                except Exception as e:
                    logger.warning(f"Anomaly detector {detector.__class__.__name__} failed: {e}")
        
        return anomalies

class NetworkMonitor:
    def __init__(self, config: MonitorConfig):
        self.config = config
        self.start_time = time.time()
        self.connection_history = defaultdict(list)
        self.security_scanner = SecurityScanner(config)
        self._cleanup_lock = threading.Lock()

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
            if self.config.verbose:
                logger.debug(f"Failed to parse {hex_str}: {e}")
            raise

    def get_process_info(self, inode: str) -> Tuple[str, Optional[int]]:
        try:
            cached = PROCESS_CACHE.get(inode)
            if cached:
                return cached, None
            
            for pid_dir in Path("/proc").glob("[0-9]*"):
                try:
                    pid = pid_dir.name
                    if not pid.isdigit():
                        continue
                    
                    cached_name = PROCESS_CACHE.get_by_pid(int(pid))
                    if cached_name:
                        PROCESS_CACHE.set(inode, cached_name, int(pid))
                        return cached_name, int(pid)
                    
                    fd_dir = pid_dir / "fd"
                    if not fd_dir.exists():
                        continue
                    
                    for fd in fd_dir.iterdir():
                        if fd.is_symlink():
                            try:
                                target = fd.readlink()
                                if f"socket:[{inode}]" in str(target):
                                    comm_file = pid_dir / "comm"
                                    if comm_file.exists():
                                        process_name = f"{comm_file.read_text().strip()} ({pid})"
                                        PROCESS_CACHE.set(inode, process_name, int(pid))
                                        return process_name, int(pid)
                            except (OSError, IOError):
                                continue
                                
                except (OSError, IOError, PermissionError):
                    continue
                    
        except Exception as e:
            if self.config.verbose:
                logger.debug(f"Process lookup failed for inode {inode}: {e}")
        
        process_name = self._get_process_info_lsof(inode)
        if process_name:
            PROCESS_CACHE.set(inode, process_name)
            return process_name, None
            
        PROCESS_CACHE.set(inode, "Unknown")
        return "Unknown", None

    def _get_process_info_lsof(self, inode: str) -> Optional[str]:
        try:
            result = subprocess.run(
                ['lsof', '-i', f'socket:[{inode}]'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:
                    parts = lines[1].split()
                    if len(parts) >= 2:
                        return f"{parts[0]} ({parts[1]})"
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, 
                FileNotFoundError, ImportError):
            pass
        return None

    def read_proc_net_file(self, file_path: Path, protocol: str) -> List[Socket]:
        sockets = []
        
        if not file_path.exists():
            if self.config.verbose:
                logger.info(f"File {file_path} does not exist")
            return sockets
            
        if not os.access(file_path, os.R_OK):
            logger.error(f"No read permission for {file_path}")
            return sockets
            
        try:
            with open(file_path, 'r') as f:
                content = f.readlines()
                
            if len(content) < 2:
                return sockets
                
            for line_num, line in enumerate(content[1:], 2):
                fields = re.split(r'\s+', line.strip())
                if len(fields) < 10:
                    if self.config.verbose:
                        logger.debug(f"Skipping line {line_num}: insufficient fields")
                    continue
                    
                try:
                    local_ip, local_port = self.parse_hex_ip_port(fields[1])
                    remote_ip, remote_port = self.parse_hex_ip_port(fields[2])
                    state_code = int(fields[3], 16)
                    inode = fields[9]
                    
                    state = TCP_STATES.get(state_code, f"UNKNOWN({state_code})")
                    process_name, pid = self.get_process_info(inode)
                    
                    socket = Socket(
                        local_ip=local_ip,
                        local_port=local_port,
                        remote_ip=remote_ip,
                        remote_port=remote_port,
                        state=state,
                        process=process_name,
                        protocol=protocol,
                        inode=inode,
                        timestamp=time.time(),
                        pid=pid
                    )
                    sockets.append(socket)
                    
                except ValueError as e:
                    if self.config.verbose:
                        logger.debug(f"Skipping line {line_num}: {e}")
                    continue
                except Exception as e:
                    if self.config.verbose:
                        logger.debug(f"Unexpected error on line {line_num}: {e}")
                    continue
                    
            return sockets
            
        except IOError as e:
            logger.error(f"Error reading {file_path}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error processing {file_path}: {e}")
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
            future_to_file = {
                executor.submit(self.read_proc_net_file, Path(file_path), protocol): protocol 
                for file_path, protocol in protocols
            }
            
            for future in future_to_file:
                try:
                    file_sockets = future.result(timeout=10)
                    sockets.extend(file_sockets)
                    if self.config.verbose:
                        logger.info(f"Found {len(file_sockets)} connections in {future_to_file[future]}")
                except FutureTimeoutError:
                    logger.warning(f"Timeout reading {future_to_file[future]}")
                except Exception as e:
                    logger.error(f"Error processing {future_to_file[future]}: {e}")
                    
        return sockets

    def filter_connections(self, sockets: List[Socket], filters: Dict) -> List[Socket]:
        filtered = sockets
        
        if filters.get('state'):
            state = filters['state'].upper()
            if state not in TCP_STATES.values():
                logger.error(f"Invalid state: {state}. Valid states: {', '.join(TCP_STATES.values())}")
                return []
            filtered = [s for s in filtered if s.state == state]
            
        if filters.get('local_ip'):
            try:
                local_net = ipaddress.ip_network(self._sanitize_filter_input(filters['local_ip']), strict=False)
                filtered = [s for s in filtered if ipaddress.ip_address(s.local_ip) in local_net]
            except ValueError as e:
                logger.error(f"Invalid local IP: {filters['local_ip']}")
                return []
                
        if filters.get('remote_ip'):
            try:
                remote_net = ipaddress.ip_network(self._sanitize_filter_input(filters['remote_ip']), strict=False)
                filtered = [s for s in filtered if ipaddress.ip_address(s.remote_ip) in remote_net]
            except ValueError as e:
                logger.error(f"Invalid remote IP: {filters['remote_ip']}")
                return []
                
        if filters.get('port'):
            port = filters['port']
            filtered = [s for s in filtered if s.local_port == port or s.remote_port == port]
            
        if filters.get('process'):
            process_filter = self._sanitize_filter_input(filters['process'].lower())
            filtered = [s for s in filtered if process_filter in s.process.lower()]
            
        if filters.get('protocol'):
            protocol_filter = filters['protocol'].upper()
            filtered = [s for s in filtered if protocol_filter in s.protocol]
            
        if filters.get('pid'):
            filtered = [s for s in filtered if s.pid == filters['pid'] or f"({filters['pid']})" in s.process]
            
        return filtered

    def _sanitize_filter_input(self, value: str) -> str:
        return re.sub(r'[^\w\.\-\:\/]', '', value)

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

    def calculate_statistics(self, sockets: List[Socket]) -> Dict[str, Any]:
        stats = {
            'total': len(sockets),
            'by_state': Counter(s.state for s in sockets),
            'by_protocol': Counter(s.protocol for s in sockets),
            'top_processes': Counter(s.process for s in sockets).most_common(5),
            'unique_ips': len(set(f"{s.local_ip}:{s.remote_ip}" for s in sockets)),
            'timestamp': time.time(),
            'monitor_uptime': time.time() - self.start_time
        }
        return stats

    def detect_anomalies(self, sockets: List[Socket]) -> List[Anomaly]:
        for socket in sockets:
            key = (socket.remote_ip, socket.remote_port, socket.process)
            self.connection_history[key].append(socket.timestamp)
        
        self._cleanup_old_history()
        
        anomalies = self.security_scanner.scan(sockets, self.connection_history)
        
        return anomalies

    def _cleanup_old_history(self):
        with self._cleanup_lock:
            current_time = time.time()
            keys_to_remove = []
            
            for key, timestamps in self.connection_history.items():
                recent_timestamps = [ts for ts in timestamps 
                                   if current_time - ts < self.config.history_ttl]
                
                if recent_timestamps:
                    self.connection_history[key] = recent_timestamps
                else:
                    keys_to_remove.append(key)
            
            for key in keys_to_remove:
                del self.connection_history[key]
            
            if len(self.connection_history) > self.config.max_history:
                sorted_keys = sorted(self.connection_history.keys(),
                                  key=lambda k: max(self.connection_history[k]),
                                  reverse=True)
                for key in sorted_keys[self.config.max_history:]:
                    del self.connection_history[key]

class OutputFormatter:
    @staticmethod
    def format_table(sockets: List[Socket], stats: Optional[Dict] = None, 
                    no_color: bool = False, anomalies: List[Anomaly] = None, 
                    columns: List[str] = None) -> str:
        if not sockets:
            return "No connections found\n"
            
        default_columns = ["protocol", "state", "local_address", "remote_address", "process"]
        columns = columns or default_columns
        
        headers = {
            "protocol": "Protocol", 
            "state": "State", 
            "local_address": "Local Address", 
            "remote_address": "Remote Address", 
            "process": "Process", 
            "timestamp": "Timestamp"
        }
        
        max_lengths = {col: len(headers[col]) for col in columns}
        for socket in sockets:
            values = OutputFormatter._get_socket_values(socket, no_color)
            for col in columns:
                max_lengths[col] = max(max_lengths[col], len(values[col]))
        
        output = []
        output.append("\nACTIVE NETWORK CONNECTIONS:")
        
        header = " ".join(f"{headers[col]:<{max_lengths[col]}}" for col in columns)
        output.append(header)
        output.append("-" * len(header))
        
        for socket in sockets:
            values = OutputFormatter._get_socket_values(socket, no_color)
            output.append(" ".join(f"{values[col]:<{max_lengths[col]}}" for col in columns))
        
        if anomalies:
            output.extend(OutputFormatter.format_anomalies(anomalies))
        if stats:
            output.extend(OutputFormatter.format_stats(stats))
            
        return "\n".join(output)

    @staticmethod
    def _get_socket_values(socket: Socket, no_color: bool = False) -> Dict[str, str]:
        state = socket.state
        if not no_color and sys.stdout.isatty() and STATE_COLORS.get(socket.state):
            state = f"{STATE_COLORS.get(socket.state)}{socket.state}\033[0m"
            
        return {
            "protocol": socket.protocol,
            "state": state,
            "local_address": f"{socket.local_ip}:{socket.local_port}",
            "remote_address": f"{socket.remote_ip}:{socket.remote_port}",
            "process": socket.process,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(socket.timestamp))
        }

    @staticmethod
    def format_json(sockets: List[Socket], stats: Optional[Dict] = None, 
                   compact: bool = False, anomalies: List[Anomaly] = None, 
                   columns: List[str] = None) -> str:
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
                    'timestamp': s.timestamp,
                    'pid': s.pid
                } for s in sockets
            ]
        }
        
        if stats:
            output['statistics'] = stats
            
        if anomalies:
            output['anomalies'] = [
                {
                    'type': a.type,
                    'reason': a.reason,
                    'severity': a.severity.value,
                    'score': a.score,
                    'timestamp': a.timestamp,
                    'socket': {
                        'protocol': a.socket.protocol,
                        'local_ip': a.socket.local_ip,
                        'local_port': a.socket.local_port,
                        'remote_ip': a.socket.remote_ip,
                        'remote_port': a.socket.remote_port,
                        'state': a.socket.state,
                        'process': a.socket.process,
                        'timestamp': a.socket.timestamp
                    }
                } for a in anomalies
            ]
            
        indent = None if compact else 2
        return json.dumps(output, indent=indent, default=str)

    @staticmethod
    def format_csv(sockets: List[Socket], stats: Optional[Dict] = None, 
                  anomalies: List[Anomaly] = None, columns: List[str] = None) -> str:
        output = io.StringIO()
        default_columns = ["protocol", "state", "local_address", "remote_address", "process", "timestamp"]
        columns = columns or default_columns
        
        writer = csv.DictWriter(output, fieldnames=columns, lineterminator='\n')
        writer.writeheader()
        
        for socket in sockets:
            values = OutputFormatter._get_socket_values(socket, no_color=True)
            writer.writerow({col: values[col] for col in columns})
            
        return output.getvalue()

    @staticmethod
    def format_stats(stats: Dict) -> List[str]:
        output = []
        output.append("\nCONNECTION STATISTICS:")
        output.append(f" Total connections: {stats['total']}")
        output.append(" By state:")
        for state, count in sorted(stats['by_state'].items()):
            output.append(f"  {state}: {count}")
        output.append(" By protocol:")
        for protocol, count in sorted(stats['by_protocol'].items()):
            output.append(f"  {protocol}: {count}")
        output.append(" Top processes:")
        for process, count in stats['top_processes']:
            output.append(f"  {process}: {count}")
        output.append(f" Unique IP pairs: {stats['unique_ips']}")
        output.append(f" Monitor uptime: {stats['monitor_uptime']:.2f}s")
        return output

    @staticmethod
    def format_anomalies(anomalies: List[Anomaly]) -> List[str]:
        output = []
        output.append(f"\nSECURITY ANOMALIES ({len(anomalies)} detected):")
        
        for anomaly in anomalies:
            output.append(f" [{anomaly.severity.value}] {anomaly.type}: {anomaly.reason} (Score: {anomaly.score:.2f})")
            socket = anomaly.socket
            output.append(f"  {socket.protocol} {socket.local_ip}:{socket.local_port} -> "
                         f"{socket.remote_ip}:{socket.remote_port} ({socket.process})")
                         
        return output

    @staticmethod
    def clear_screen():
        if sys.stdout.isatty():
            print("\033c", end="")

def signal_handler(sig, frame):
    print("\nMonitoring stopped")
    sys.exit(0)

def parse_port_range(port_input: str) -> Set[int]:
    ports = set()
    
    for part in port_input.split(','):
        part = part.strip()
        if not part:
            continue
            
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                if not (1 <= start <= 65535 and 1 <= end <= 65535):
                    raise ValueError("Ports must be between 1 and 65535")
                if start > end:
                    raise ValueError("Start port must be less than or equal to end port")
                ports.update(range(start, end + 1))
            except ValueError as e:
                raise ValueError(f"Invalid port range '{part}': {e}")
        else:
            try:
                port = int(part)
                if not (1 <= port <= 65535):
                    raise ValueError("Ports must be between 1 and 65535")
                ports.add(port)
            except ValueError as e:
                raise ValueError(f"Invalid port '{part}': {e}")
                
    return ports

def validate_args(args) -> None:
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

def check_system_compatibility() -> bool:
    if platform.system() != "Linux":
        logger.error("This tool requires Linux. /proc filesystem is not available on other systems.")
        return False
    
    # On Fedora/CentOS/RHEL we expect /proc to exist; IPv6 files may be optional
    required_files = ["/proc/net/tcp", "/proc/net/udp"]
    optional_files = ["/proc/net/tcp6", "/proc/net/udp6"]
    for file_path in required_files:
        if not Path(file_path).exists():
            logger.error(f"Required file not found: {file_path}")
            return False

    for file_path in optional_files:
        if not Path(file_path).exists():
            # don't fail; just log - IPv6 may be disabled on the host
            logger.info(f"Optional file not found (IPv6 may be disabled): {file_path}")
            
    return True

def main():
    if not check_system_compatibility():
        sys.exit(1)
    
    parser = argparse.ArgumentParser(
        description="Advanced Network Connection Monitor for Linux Systems",
        epilog="""
Examples:
  python network_monitor.py --watch 5 --security-scan --suspicious-ports 22,80,443
  python network_monitor.py --format csv --pid 1234 --stats
  python network_monitor.py --local-ip 192.168.1.0/24 --state ESTABLISHED
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    filter_group = parser.add_argument_group('Filtering Options')
    filter_group.add_argument("--state", help="Filter by connection state")
    filter_group.add_argument("--local-ip", help="Filter by local IP or subnet")
    filter_group.add_argument("--remote-ip", help="Filter by remote IP or subnet")
    filter_group.add_argument("--port", type=int, help="Filter by local or remote port")
    filter_group.add_argument("--process", help="Filter by process name")
    filter_group.add_argument("--pid", type=int, help="Filter by process ID")
    filter_group.add_argument("--protocol", help="Filter by protocol (TCP, TCP6, UDP, UDP6)")
    
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument("--watch", type=float, default=0, help="Refresh interval in seconds")
    output_group.add_argument("--sort", choices=["state", "local_ip", "remote_ip", "port", "process", "protocol", "timestamp"],
                             default="state", help="Sort by field")
    output_group.add_argument("--format", choices=["table", "json", "csv"], default="table", help="Output format")
    output_group.add_argument("--compact-json", action="store_true", help="Use compact JSON output")
    output_group.add_argument("--no-color", action="store_true", help="Disable colored output")
    output_group.add_argument("--stats", action="store_true", help="Show connection statistics")
    output_group.add_argument("--limit", type=int, help="Limit number of connections displayed")
    output_group.add_argument("--columns", type=str, help="Comma-separated list of columns to display")
    
    security_group = parser.add_argument_group('Security Options')
    security_group.add_argument("--security-scan", action="store_true", help="Enable security anomaly detection")
    security_group.add_argument("--suspicious-ports", type=str, help="Comma-separated list or range of suspicious ports")
    security_group.add_argument("--trusted-processes", type=str, help="Comma-separated list of trusted process names")
    
    perf_group = parser.add_argument_group('Performance Options')
    perf_group.add_argument("--cache-ttl", type=int, default=300, help="Process cache TTL in seconds")
    perf_group.add_argument("--history-ttl", type=int, default=300, help="Connection history TTL in seconds")
    perf_group.add_argument("--rate-limit", type=int, default=10, help="Max connections for rate limiting")
    perf_group.add_argument("--rate-window", type=int, default=60, help="Time window for rate limiting in seconds")
    perf_group.add_argument("--max-history", type=int, default=10000, help="Max number of connection history entries")
    
    misc_group = parser.add_argument_group('Miscellaneous Options')
    misc_group.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    misc_group.add_argument("--clear-cache", action="store_true", help="Clear process cache")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)
    
    try:
        validate_args(args)
    except ValueError as e:
        logger.error(f"Argument error: {e}")
        sys.exit(1)
    
    if args.clear_cache:
        PROCESS_CACHE.clear()
        print("Process cache cleared")
        return
    
    if os.geteuid() != 0:
        logger.warning("Running without root privileges - some process information may be unavailable. Consider using sudo.")
    
    PROCESS_CACHE.ttl = args.cache_ttl
    
    config = MonitorConfig(
        verbose=args.verbose,
        history_ttl=args.history_ttl,
        rate_limit=args.rate_limit,
        rate_window=args.rate_window,
        max_history=args.max_history,
        cache_ttl=args.cache_ttl
    )
    
    if args.suspicious_ports:
        try:
            config.suspicious_ports = parse_port_range(args.suspicious_ports)
        except ValueError as e:
            logger.error(f"Invalid suspicious ports format: {e}")
            sys.exit(1)
    
    if args.trusted_processes:
        # normalize trusted process names (strip whitespace, lowercase)
        config.trusted_processes = {p.strip().lower() for p in args.trusted_processes.split(',') if p.strip()}
    
    monitor = NetworkMonitor(config)
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
    
    columns = args.columns.split(',') if args.columns else None
    if columns:
        valid_columns = {"protocol", "state", "local_address", "remote_address", "process", "timestamp"}
        if not all(col in valid_columns for col in columns):
            logger.error(f"Invalid columns: {args.columns}. Valid columns: {', '.join(valid_columns)}")
            sys.exit(1)
    
    # Only require IPv4 proc files for functionality; IPv6 files are optional.
    for file_path in ["/proc/net/tcp", "/proc/net/udp"]:
        if not os.access(file_path, os.R_OK):
            logger.error(f"Cannot read {file_path}. Ensure proper permissions or run with sudo.")
            sys.exit(1)
    # Warn if IPv6 files are missing but don't exit; IPv6 may be disabled on some systems.
    for file_path in ["/proc/net/tcp6", "/proc/net/udp6"]:
        if not Path(file_path).exists():
            logger.info(f"{file_path} not found; IPv6 connections will not be listed on this system.")
    
    def process_cycle():
        PROCESS_CACHE.cleanup_expired()
        sockets = monitor.get_all_connections()
        if args.verbose:
            logger.info(f"Total connections found: {len(sockets)}")
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
    
    if args.watch > 0:
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGHUP, signal_handler)
        try:
            while True:
                formatter.clear_screen()
                process_cycle()
                time.sleep(args.watch)
        except KeyboardInterrupt:
            signal_handler(None, None)
    else:
        process_cycle()

if __name__ == "__main__":
    main()
