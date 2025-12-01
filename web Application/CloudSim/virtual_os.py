import os
import time
import threading
import json
import hashlib
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass
from enum import Enum, auto
from virtual_disk import VirtualDisk, VirtualFile

class ProcessType(Enum):
    SYSTEM = auto()
    USER = auto()
    DAEMON = auto()

class FileSystemType(Enum):
    VIRTUAL_FS = "vfs"
    DISTRIBUTED_FS = "dfs"

@dataclass
class VirtualFile:
    path: str
    name: str
    size: int
    created_at: float
    modified_at: float
    file_id: str
    is_directory: bool = False
    parent_path: str = "/"
    permissions: str = "rwxr-xr-x"
    owner: str = "root"
    group: str = "root"

@dataclass
class VirtualProcess:
    pid: int
    name: str
    process_type: ProcessType
    state: str
    priority: int
    created_at: float
    cpu_time: float = 0.0
    memory_usage: int = 0
    parent_pid: Optional[int] = None
    command: str = ""

class VirtualFileSystem:
    def __init__(self, virtual_disk: VirtualDisk, node_id: str):
        self.virtual_disk = virtual_disk
        self.node_id = node_id
        self.files: Dict[str, VirtualFile] = {}  # path -> VirtualFile
        self.root_directory = "/"
        self.current_directory = "/"
        
        # Initialize root directory
        self._initialize_filesystem()
        
        # File operations
        self.open_files: Dict[str, Dict] = {}  # file_handle -> file_info
        
    def _initialize_filesystem(self):
        """Initialize the virtual filesystem with basic structure"""
        # Create root directory
        root_file = VirtualFile(
            path="/",
            name="root",
            size=0,
            created_at=time.time(),
            modified_at=time.time(),
            file_id="root",
            is_directory=True,
            parent_path="/"
        )
        self.files["/"] = root_file
        
        # Create basic directories
        directories = ["/bin", "/etc", "/home", "/tmp", "/var", "/usr", "/dev"]
        for dir_path in directories:
            self.create_directory(dir_path)
    
    def create_directory(self, path: str) -> bool:
        """Create a directory"""
        if path in self.files:
            return False
        
        parent_path = os.path.dirname(path)
        dir_name = os.path.basename(path)
        
        # Check if parent exists
        if parent_path != "/" and parent_path not in self.files:
            return False
        
        dir_file = VirtualFile(
            path=path,
            name=dir_name,
            size=0,
            created_at=time.time(),
            modified_at=time.time(),
            file_id=f"dir_{hashlib.md5(path.encode()).hexdigest()}",
            is_directory=True,
            parent_path=parent_path
        )
        
        self.files[path] = dir_file
        return True
    
    def create_file(self, path: str, content: bytes = b"") -> bool:
        """Create a file with content"""
        if path in self.files:
            return False
        
        parent_path = os.path.dirname(path)
        file_name = os.path.basename(path)
        
        # Check if parent directory exists
        if parent_path not in self.files or not self.files[parent_path].is_directory:
            return False
        
        # Allocate storage on virtual disk
        file_id = f"file_{hashlib.md5(path.encode()).hexdigest()}"
        allocated_blocks = self.virtual_disk.allocate_storage(file_id, file_name, len(content))
        
        if allocated_blocks is None:
            return False
        
        # Write content to disk
        if content:
            success = self.virtual_disk.write_data(file_id, content)
            if not success:
                # Clean up allocation
                self.virtual_disk.delete_file(file_id)
                return False
        
        # Create file record
        virtual_file = VirtualFile(
            path=path,
            name=file_name,
            size=len(content),
            created_at=time.time(),
            modified_at=time.time(),
            file_id=file_id,
            is_directory=False,
            parent_path=parent_path
        )
        
        self.files[path] = virtual_file
        return True
    
    def read_file(self, path: str) -> Optional[bytes]:
        """Read file content"""
        if path not in self.files or self.files[path].is_directory:
            return None
        
        file_obj = self.files[path]
        return self.virtual_disk.read_data(file_obj.file_id, file_obj.size)
    
    def write_file(self, path: str, content: bytes) -> bool:
        """Write content to a file"""
        if path not in self.files or self.files[path].is_directory:
            return False
        
        file_obj = self.files[path]
        
        # Check if we need to resize
        if len(content) > file_obj.size:
            # Need more storage
            additional_space = len(content) - file_obj.size
            # For simplicity, delete and recreate
            self.delete_file(path)
            return self.create_file(path, content)
        else:
            # Write to existing storage
            success = self.virtual_disk.write_data(file_obj.file_id, content)
            if success:
                file_obj.size = len(content)
                file_obj.modified_at = time.time()
            return success
    
    def delete_file(self, path: str) -> bool:
        """Delete a file or directory"""
        if path not in self.files:
            return False
        
        file_obj = self.files[path]
        
        if file_obj.is_directory:
            # Check if directory is empty
            children = [f for f in self.files.values() if f.parent_path == path]
            if children:
                return False  # Directory not empty
        
        # Delete from virtual disk
        if not file_obj.is_directory:
            self.virtual_disk.delete_file(file_obj.file_id)
        
        # Remove from filesystem
        del self.files[path]
        return True
    
    def list_directory(self, path: str) -> List[VirtualFile]:
        """List contents of a directory"""
        if path not in self.files or not self.files[path].is_directory:
            return []
        
        return [f for f in self.files.values() if f.parent_path == path]
    
    def file_exists(self, path: str) -> bool:
        """Check if file exists"""
        return path in self.files
    
    def get_file_info(self, path: str) -> Optional[VirtualFile]:
        """Get file information"""
        return self.files.get(path)
    
    def change_directory(self, path: str) -> bool:
        """Change current directory"""
        if path in self.files and self.files[path].is_directory:
            self.current_directory = path
            return True
        return False
    
    def get_current_directory(self) -> str:
        """Get current directory"""
        return self.current_directory
    
    def get_absolute_path(self, path: str) -> str:
        """Convert relative path to absolute path"""
        if path.startswith("/"):
            return path
        else:
            return os.path.normpath(os.path.join(self.current_directory, path)).replace("\\", "/")

class VirtualProcessManager:
    def __init__(self):
        self.processes: Dict[int, VirtualProcess] = {}
        self.next_pid = 1
        self.running_processes: Dict[int, threading.Thread] = {}
        self.process_table: Dict[str, List[int]] = {}  # process_name -> list of pids
        
    def create_process(self, name: str, command: str, process_type: ProcessType = ProcessType.USER,
                      priority: int = 5, parent_pid: Optional[int] = None) -> int:
        """Create a new virtual process"""
        pid = self.next_pid
        self.next_pid += 1
        
        process = VirtualProcess(
            pid=pid,
            name=name,
            process_type=process_type,
            state="READY",
            priority=priority,
            created_at=time.time(),
            parent_pid=parent_pid,
            command=command
        )
        
        self.processes[pid] = process
        
        # Add to process table
        if name not in self.process_table:
            self.process_table[name] = []
        self.process_table[name].append(pid)
        
        return pid
    
    def start_process(self, pid: int, target: Callable, args: tuple = ()) -> bool:
        """Start a process execution"""
        if pid not in self.processes:
            return False
        
        process = self.processes[pid]
        process.state = "RUNNING"
        
        def process_wrapper():
            try:
                start_time = time.time()
                target(*args)
                end_time = time.time()
                process.cpu_time = end_time - start_time
                process.state = "TERMINATED"
            except Exception as e:
                process.state = "FAILED"
                print(f"Process {pid} failed: {e}")
            finally:
                if pid in self.running_processes:
                    del self.running_processes[pid]
        
        thread = threading.Thread(target=process_wrapper, daemon=True)
        self.running_processes[pid] = thread
        thread.start()
        
        return True
    
    def kill_process(self, pid: int) -> bool:
        """Kill a process"""
        if pid not in self.processes:
            return False
        
        process = self.processes[pid]
        if process.state == "RUNNING":
            process.state = "TERMINATED"
            if pid in self.running_processes:
                # Note: In a real OS, we'd need proper thread termination
                del self.running_processes[pid]
        
        return True
    
    def get_process_info(self, pid: int) -> Optional[Dict]:
        """Get process information"""
        if pid not in self.processes:
            return None
        
        process = self.processes[pid]
        return {
            "pid": process.pid,
            "name": process.name,
            "type": process.process_type.name,
            "state": process.state,
            "priority": process.priority,
            "created_at": process.created_at,
            "cpu_time": process.cpu_time,
            "memory_usage": process.memory_usage,
            "parent_pid": process.parent_pid,
            "command": process.command
        }
    
    def list_processes(self) -> List[Dict]:
        """List all processes"""
        return [self.get_process_info(pid) for pid in sorted(self.processes.keys())]
    
    def get_process_by_name(self, name: str) -> List[int]:
        """Get all PIDs for a process name"""
        return self.process_table.get(name, [])

class VirtualOS:
    def __init__(self, node_id: str, virtual_disk: VirtualDisk):
        self.node_id = node_id
        self.boot_time = time.time()
        self.is_running = False
        
        # Core components
        self.virtual_disk = virtual_disk
        self.filesystem = VirtualFileSystem(virtual_disk, node_id)
        self.process_manager = VirtualProcessManager()
        
        # System information
        self.kernel_version = "CloudOS-1.0.0"
        self.hostname = f"{node_id}-os"
        self.uptime = 0
        
        # System services
        self.services: Dict[str, Dict] = {}
        self.system_logs: List[Dict] = []
        
        # Shell interface
        self.shell_commands: Dict[str, Callable] = {}
        self._register_shell_commands()
        
    def boot(self):
        """Boot the virtual OS"""
        print(f"[{self.node_id}] Booting CloudOS {self.kernel_version}...")
        
        # Start system services
        self._start_system_services()
        
        # Create initial processes
        self._create_system_processes()
        
        self.is_running = True
        self.uptime = 0
        
        # Start uptime counter
        uptime_thread = threading.Thread(target=self._uptime_counter, daemon=True)
        uptime_thread.start()
        
        print(f"[{self.node_id}] CloudOS booted successfully")
        print(f"[{self.node_id}] Hostname: {self.hostname}")
        print(f"[{self.node_id}] Storage: {self.virtual_disk.get_storage_info()['capacity_gb']} GB")
        
        return True
    
    def _uptime_counter(self):
        """Update uptime counter"""
        while self.is_running:
            time.sleep(1)
            self.uptime = time.time() - self.boot_time
    
    def _start_system_services(self):
        """Start essential system services"""
        services = [
            {"name": "init", "description": "System initialization"},
            {"name": "network", "description": "Network management"},
            {"name": "storage", "description": "Storage management"},
            {"name": "rpc", "description": "RPC service"},
        ]
        
        for service in services:
            service_id = self.process_manager.create_process(
                service["name"], 
                f"system-service-{service['name']}",
                ProcessType.SYSTEM,
                priority=1
            )
            
            self.services[service["name"]] = {
                "pid": service_id,
                "status": "running",
                "description": service["description"],
                "started_at": time.time()
            }
            
            self._log("system", f"Started service: {service['name']}")
    
    def _create_system_processes(self):
        """Create essential system processes"""
        # Create shell process
        shell_pid = self.process_manager.create_process(
            "shell", "cloud-shell", ProcessType.USER, priority=5
        )
        
        self._log("system", f"Created shell process (PID: {shell_pid})")
    
    def _register_shell_commands(self):
        """Register shell commands"""
        self.shell_commands = {
            "ls": self._cmd_ls,
            "cd": self._cmd_cd,
            "pwd": self._cmd_pwd,
            "mkdir": self._cmd_mkdir,
            "touch": self._cmd_touch,
            "cat": self._cmd_cat,
            "echo": self._cmd_echo,
            "ps": self._cmd_ps,
            "kill": self._cmd_kill,
            "df": self._cmd_df,
            "help": self._cmd_help,
            "clear": self._cmd_clear,
            "exit": self._cmd_exit,
        }
    
    def execute_command(self, command_line: str) -> str:
        """Execute a shell command"""
        parts = command_line.strip().split()
        if not parts:
            return ""
        
        command = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        
        if command in self.shell_commands:
            try:
                return self.shell_commands[command](args)
            except Exception as e:
                return f"Error: {e}"
        else:
            return f"Command not found: {command}"
    
    # Shell command implementations
    def _cmd_ls(self, args: List[str]) -> str:
        """List directory contents"""
        path = self.filesystem.get_absolute_path(args[0]) if args else self.filesystem.current_directory
        files = self.filesystem.list_directory(path)
        
        if not files:
            return ""
        
        output = []
        for file_obj in files:
            file_type = "d" if file_obj.is_directory else "-"
            permissions = file_obj.permissions
            size = file_obj.size
            name = file_obj.name
            modified = time.ctime(file_obj.modified_at)
            
            output.append(f"{file_type}{permissions} {size:>8} {name}")
        
        return "\n".join(output)
    
    def _cmd_cd(self, args: List[str]) -> str:
        """Change directory"""
        if not args:
            return "Usage: cd <directory>"
        
        path = self.filesystem.get_absolute_path(args[0])
        if self.filesystem.change_directory(path):
            return ""
        else:
            return f"cd: {args[0]}: No such directory"
    
    def _cmd_pwd(self, args: List[str]) -> str:
        """Print working directory"""
        return self.filesystem.current_directory
    
    def _cmd_mkdir(self, args: List[str]) -> str:
        """Create directory"""
        if not args:
            return "Usage: mkdir <directory>"
        
        path = self.filesystem.get_absolute_path(args[0])
        if self.filesystem.create_directory(path):
            return ""
        else:
            return f"mkdir: cannot create directory '{args[0]}': File exists"
    
    def _cmd_touch(self, args: List[str]) -> str:
        """Create empty file"""
        if not args:
            return "Usage: touch <file>"
        
        path = self.filesystem.get_absolute_path(args[0])
        if self.filesystem.create_file(path):
            return ""
        else:
            return f"touch: cannot create file '{args[0]}': File exists"
    
    def _cmd_cat(self, args: List[str]) -> str:
        """Display file contents"""
        if not args:
            return "Usage: cat <file>"
        
        path = self.filesystem.get_absolute_path(args[0])
        content = self.filesystem.read_file(path)
        
        if content is None:
            return f"cat: {args[0]}: No such file or directory"
        
        return content.decode('utf-8', errors='replace')
    
    def _cmd_echo(self, args: List[str]) -> str:
        """Echo arguments"""
        return " ".join(args)
    
    def _cmd_ps(self, args: List[str]) -> str:
        """List processes"""
        processes = self.process_manager.list_processes()
        
        output = ["PID  NAME           STATE    TYPE     CPU_TIME"]
        for proc in processes:
            output.append(f"{proc['pid']:<5} {proc['name']:<15} {proc['state']:<8} {proc['type']:<8} {proc['cpu_time']:.2f}")
        
        return "\n".join(output)
    
    def _cmd_kill(self, args: List[str]) -> str:
        """Kill process"""
        if not args:
            return "Usage: kill <pid>"
        
        try:
            pid = int(args[0])
            if self.process_manager.kill_process(pid):
                return ""
            else:
                return f"kill: ({pid}) - No such process"
        except ValueError:
            return "Usage: kill <pid>"
    
    def _cmd_df(self, args: List[str]) -> str:
        """Display disk usage"""
        storage_info = self.virtual_disk.get_storage_info()
        
        output = [
            f"Filesystem      Size  Used Avail Use% Mounted on",
            f"CloudOS         {storage_info['capacity_gb']:.1f}G {storage_info['used_storage_gb']:.1f}G {storage_info['free_storage_gb']:.1f}G {storage_info['utilization_percent']:.0f}% /"
        ]
        
        return "\n".join(output)
    
    def _cmd_help(self, args: List[str]) -> str:
        """Display help"""
        commands = list(self.shell_commands.keys())
        return f"Available commands: {', '.join(sorted(commands))}"
    
    def _cmd_clear(self, args: List[str]) -> str:
        """Clear screen"""
        return "\n" * 50  # Simple clear
    
    def _cmd_exit(self, args: List[str]) -> str:
        """Exit shell"""
        return "exit"
    
    def _log(self, category: str, message: str):
        """Add system log entry"""
        log_entry = {
            "timestamp": time.time(),
            "category": category,
            "message": message
        }
        self.system_logs.append(log_entry)
        
        # Keep only last 1000 log entries
        if len(self.system_logs) > 1000:
            self.system_logs = self.system_logs[-1000:]
    
    def get_system_info(self) -> Dict:
        """Get system information"""
        return {
            "hostname": self.hostname,
            "kernel_version": self.kernel_version,
            "uptime": self.uptime,
            "boot_time": self.boot_time,
            "is_running": self.is_running,
            "process_count": len(self.process_manager.processes),
            "service_count": len(self.services),
            "storage": self.virtual_disk.get_storage_info(),
            "current_directory": self.filesystem.current_directory
        }
    
    def shutdown(self):
        """Shutdown the virtual OS"""
        print(f"[{self.node_id}] Shutting down CloudOS...")
        
        # Stop all processes
        for pid in list(self.process_manager.processes.keys()):
            self.process_manager.kill_process(pid)
        
        # Stop services
        for service_name in self.services:
            self.services[service_name]["status"] = "stopped"
        
        self.is_running = False
        self._log("system", "CloudOS shutdown complete")
        
        print(f"[{self.node_id}] CloudOS shutdown complete")
