import time
import threading
import hashlib
import json
import os
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass
from enum import Enum, auto
from virtual_disk import VirtualDisk
from network_manager import NetworkManager, TCPCommunication, MessageTypes, NetworkMessage

class ProcessState(Enum):
    READY = auto()
    WAITING = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()

@dataclass
class Process:
    process_id: str
    name: str
    state: ProcessState
    created_at: float
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    result: Optional[Any] = None
    error: Optional[str] = None

class RPCService:
    def __init__(self, node_id: str, tcp_comm: TCPCommunication):
        self.node_id = node_id
        self.tcp_comm = tcp_comm
        self.rpc_methods: Dict[str, Callable] = {}
        self.pending_calls: Dict[str, tuple] = {}  # call_id -> (future, timestamp)
        
        # Register RPC handler
        tcp_comm.register_handler(MessageTypes.RPC_REQUEST, self._handle_rpc_request)
        tcp_comm.register_handler(MessageTypes.RPC_RESPONSE, self._handle_rpc_response)
    
    def register_method(self, method_name: str, method: Callable):
        """Register an RPC method"""
        self.rpc_methods[method_name] = method
    
    def call_remote_method(self, target_ip: str, target_port: int, method_name: str, 
                          params: dict = None, timeout: float = 30.0) -> Any:  # Increased timeout
        """Call a remote method on another node"""
        call_id = hashlib.md5(f"{self.node_id}-{method_name}-{time.time()}".encode()).hexdigest()
        
        request_message = NetworkMessage(
            message_id=call_id,
            message_type=MessageTypes.RPC_REQUEST,
            source_ip=self.tcp_comm.ip,
            target_ip=target_ip,
            payload={
                "call_id": call_id,
                "method_name": method_name,
                "params": params or {},
                "source_port": self.tcp_comm.port  # Include source port for response
            },
            timestamp=time.time(),
            requires_ack=True
        )
        
        # Create a future-like object for the result
        result_container = {"result": None, "completed": False, "error": None}
        self.pending_calls[call_id] = (result_container, time.time())
        
        # Send the request
        print(f"[{self.node_id}] Sending RPC request for {method_name} to {target_ip}:{target_port}")
        success = self.tcp_comm.send_message(target_ip, target_port, request_message)
        
        if success:
            print(f"[{self.node_id}] RPC request sent, waiting for response...")
            # Wait for response
            start_time = time.time()
            while not result_container["completed"] and (time.time() - start_time) < timeout:
                time.sleep(0.1)
            
            if result_container["completed"]:
                print(f"[{self.node_id}] RPC response received for {method_name}")
                if result_container["error"]:
                    raise Exception(result_container["error"])
                return result_container["result"]
            else:
                # Timeout
                print(f"[{self.node_id}] RPC timeout for {method_name}")
                del self.pending_calls[call_id]
                raise TimeoutError(f"RPC call to {method_name} timed out")
        else:
            print(f"[{self.node_id}] Failed to send RPC request for {method_name}")
            del self.pending_calls[call_id]
            raise Exception("Failed to send RPC request")
    
    def _handle_rpc_request(self, message: NetworkMessage):
        """Handle incoming RPC request"""
        print(f"[{self.node_id}] Received RPC request for {message.payload.get('method_name', 'unknown')}")
        payload = message.payload
        call_id = payload["call_id"]
        method_name = payload["method_name"]
        params = payload.get("params", {})
        
        try:
            if method_name in self.rpc_methods:
                print(f"[{self.node_id}] Executing RPC method: {method_name}")
                result = self.rpc_methods[method_name](**params)
                
                response = NetworkMessage(
                    message_id=self.tcp_comm._generate_message_id(),
                    message_type=MessageTypes.RPC_RESPONSE,
                    source_ip=self.tcp_comm.ip,
                    target_ip=message.source_ip,
                    payload={
                        "call_id": call_id,
                        "result": result,
                        "error": None
                    },
                    timestamp=time.time()
                )
                print(f"[{self.node_id}] Sending RPC response for {method_name}")
            else:
                print(f"[{self.node_id}] RPC method not found: {method_name}")
                response = NetworkMessage(
                    message_id=self.tcp_comm._generate_message_id(),
                    message_type=MessageTypes.RPC_RESPONSE,
                    source_ip=self.tcp_comm.ip,
                    target_ip=message.source_ip,
                    payload={
                        "call_id": call_id,
                        "result": None,
                        "error": f"Method {method_name} not found"
                    },
                    timestamp=time.time()
                )
            
            # Send response
            target_port = message.payload.get("source_port", self.tcp_comm.port)
            success = self.tcp_comm.send_message(message.source_ip, target_port, response)
            print(f"[{self.node_id}] RPC response sent to {message.source_ip}:{target_port} - Success: {success}")
            
        except Exception as e:
            print(f"[{self.node_id}] RPC request error: {e}")
            # Send error response
            response = NetworkMessage(
                message_id=self.tcp_comm._generate_message_id(),
                message_type=MessageTypes.RPC_RESPONSE,
                source_ip=self.tcp_comm.ip,
                target_ip=message.source_ip,
                payload={
                    "call_id": call_id,
                    "result": None,
                    "error": str(e)
                },
                timestamp=time.time()
            )
            target_port = message.payload.get("source_port", self.tcp_comm.port)
            self.tcp_comm.send_message(message.source_ip, target_port, response)
    
    def _handle_rpc_response(self, message: NetworkMessage):
        """Handle incoming RPC response"""
        payload = message.payload
        call_id = payload["call_id"]
        
        if call_id in self.pending_calls:
            result_container, _ = self.pending_calls[call_id]
            result_container["result"] = payload["result"]
            result_container["error"] = payload["error"]
            result_container["completed"] = True
            del self.pending_calls[call_id]

class ProcessManager:
    def __init__(self, node_id: str):
        self.node_id = node_id
        self.processes: Dict[str, Process] = {}
        self.ready_queue: List[str] = []
        self.waiting_processes: Dict[str, str] = {}  # process_id -> reason
        self.running = True
        self.scheduler_thread = None
        
    def create_process(self, name: str, task: Callable, *args, **kwargs) -> str:
        """Create a new process"""
        process_id = hashlib.md5(f"{self.node_id}-{name}-{time.time()}".encode()).hexdigest()
        
        process = Process(
            process_id=process_id,
            name=name,
            state=ProcessState.READY,
            created_at=time.time()
        )
        
        self.processes[process_id] = process
        self.ready_queue.append(process_id)
        
        return process_id
    
    def set_process_state(self, process_id: str, state: ProcessState, reason: str = None):
        """Set the state of a process"""
        if process_id in self.processes:
            process = self.processes[process_id]
            old_state = process.state
            
            # Update queues based on state change
            if old_state == ProcessState.READY and process_id in self.ready_queue:
                self.ready_queue.remove(process_id)
            elif old_state == ProcessState.WAITING and process_id in self.waiting_processes:
                del self.waiting_processes[process_id]
            
            process.state = state
            
            if state == ProcessState.READY:
                self.ready_queue.append(process_id)
            elif state == ProcessState.WAITING and reason:
                self.waiting_processes[process_id] = reason
            elif state == ProcessState.RUNNING:
                process.started_at = time.time()
            elif state in [ProcessState.COMPLETED, ProcessState.FAILED]:
                process.completed_at = time.time()
    
    def get_next_ready_process(self) -> Optional[str]:
        """Get the next ready process"""
        if self.ready_queue:
            return self.ready_queue.pop(0)
        return None
    
    def get_process_info(self, process_id: str) -> Optional[Dict]:
        """Get information about a process"""
        if process_id in self.processes:
            process = self.processes[process_id]
            return {
                "process_id": process.process_id,
                "name": process.name,
                "state": process.state.name,
                "created_at": process.created_at,
                "started_at": process.started_at,
                "completed_at": process.completed_at,
                "result": process.result,
                "error": process.error
            }
        return None
    
    def list_processes(self) -> List[Dict]:
        """List all processes"""
        return [self.get_process_info(pid) for pid in self.processes.keys()]
    
    def start_scheduler(self):
        """Start the process scheduler"""
        self.running = True
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self.scheduler_thread.start()
    
    def _scheduler_loop(self):
        """Simple scheduler loop"""
        while self.running:
            if self.ready_queue:
                process_id = self.get_next_ready_process()
                if process_id:
                    self.set_process_state(process_id, ProcessState.RUNNING)
                    # In a real implementation, we'd execute the process here
                    # For now, just mark as completed after a short delay
                    time.sleep(0.1)
                    self.set_process_state(process_id, ProcessState.COMPLETED)
            
            time.sleep(0.1)  # Scheduler tick

class VirtualNode:
    def __init__(self, node_id: str, capacity_gb: int = 2, port: int = 8000, use_localhost: bool = True, shared_network_manager=None):
        self.node_id = node_id
        self.capacity_gb = capacity_gb
        self.port = port
        
        # Core components
        self.virtual_disk = VirtualDisk(node_id, capacity_gb)
        self.network_manager = shared_network_manager if shared_network_manager else NetworkManager(use_localhost=use_localhost)
        self.tcp_comm = None  # Will be set after network setup
        self.rpc_service = None  # Will be set after TCP setup
        self.process_manager = ProcessManager(node_id)
        
        # Node status
        self.is_active = True
        self.start_time = time.time()
        
        # Performance metrics
        self.files_uploaded = 0
        self.files_downloaded = 0
        self.bytes_transferred = 0
        self.active_transfers = 0
        
        # Initialize network
        self._initialize_network()
        
        # Start process manager
        self.process_manager.start_scheduler()
    
    def _initialize_network(self):
        """Initialize network components"""
        # Add node to network
        ip = self.network_manager.add_node(self.node_id, self.port)
        self.tcp_comm = self.network_manager.nodes[self.node_id]
        
        # Initialize RPC service
        self.rpc_service = RPCService(self.node_id, self.tcp_comm)
        print(f"[{self.node_id}] RPC service initialized")
        
        # Register RPC methods
        self._register_rpc_methods()
        print(f"[{self.node_id}] RPC methods registered")
        
        print(f"[{self.node_id}] Node initialized with IP {ip}:{self.port}")
    
    def _register_rpc_methods(self):
        """Register RPC methods that this node provides"""
        def store_file_chunk(file_id: str, chunk_data: str, chunk_hash: str) -> dict:
            """Store a file chunk on this node"""
            try:
                # Decode chunk data
                chunk_bytes = bytes.fromhex(chunk_data)
                
                # Verify hash
                calculated_hash = hashlib.md5(chunk_bytes).hexdigest()
                if calculated_hash != chunk_hash:
                    return {"success": False, "error": "Hash mismatch"}
                
                # Allocate storage
                allocated_blocks = self.virtual_disk.allocate_storage(
                    f"{file_id}_chunk", f"{file_id}_chunk", len(chunk_bytes)
                )
                
                if allocated_blocks is None:
                    return {"success": False, "error": "Insufficient storage"}
                
                # Write data
                success = self.virtual_disk.write_data(f"{file_id}_chunk", chunk_bytes)
                
                if success:
                    self.files_uploaded += 1
                    self.bytes_transferred += len(chunk_bytes)
                    return {"success": True, "blocks": allocated_blocks}
                else:
                    return {"success": False, "error": "Failed to write data"}
                    
            except Exception as e:
                return {"success": False, "error": str(e)}
        
        def retrieve_file_chunk(file_id: str) -> dict:
            """Retrieve a file chunk from this node"""
            try:
                chunk_file_id = f"{file_id}_chunk"
                data = self.virtual_disk.read_data(chunk_file_id, 1024*1024)  # Read up to 1MB
                
                if data is None:
                    return {"success": False, "error": "Chunk not found"}
                
                chunk_hash = hashlib.md5(data).hexdigest()
                chunk_data = data.hex()
                
                self.files_downloaded += 1
                self.bytes_transferred += len(data)
                
                return {
                    "success": True,
                    "chunk_data": chunk_data,
                    "chunk_hash": chunk_hash,
                    "size": len(data)
                }
                
            except Exception as e:
                return {"success": False, "error": str(e)}
        
        def get_storage_info() -> dict:
            """Get storage information for this node"""
            return self.virtual_disk.get_storage_info()
        
        def list_files() -> dict:
            """List files stored on this node"""
            return {"files": self.virtual_disk.list_files()}
        
        def ping() -> dict:
            """Simple ping to check if node is alive"""
            return {
                "success": True,
                "node_id": self.node_id,
                "timestamp": time.time(),
                "uptime": time.time() - self.start_time
            }
        
        # Register methods
        self.rpc_service.register_method("store_file_chunk", store_file_chunk)
        self.rpc_service.register_method("retrieve_file_chunk", retrieve_file_chunk)
        self.rpc_service.register_method("get_storage_info", get_storage_info)
        self.rpc_service.register_method("list_files", list_files)
        self.rpc_service.register_method("ping", ping)
    
    def discover_other_nodes(self) -> List[str]:
        """Discover other nodes in the network"""
        return self.network_manager.discover_nodes(self.node_id)
    
    def call_remote_method(self, target_node_id: str, method_name: str, params: dict = None) -> Any:
        """Call a method on a remote node"""
        if target_node_id not in self.network_manager.nodes:
            raise Exception(f"Node {target_node_id} not found")
        
        target_tcp = self.network_manager.nodes[target_node_id]
        return self.rpc_service.call_remote_method(
            target_tcp.ip, target_tcp.port, method_name, params
        )
    
    def distribute_file(self, file_path: str, replication_factor: int = 2) -> dict:
        """Distribute a file across multiple nodes"""
        try:
            # Read the file
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            file_id = hashlib.md5(file_data).hexdigest()
            file_size = len(file_data)
            
            # Get all available nodes (including self)
            all_nodes = list(self.network_manager.nodes.keys())
            available_nodes = [node for node in all_nodes if node != self.node_id]
            
            # For small files, we can distribute to fewer nodes
            if len(available_nodes) == 0:
                return {"success": False, "error": "No other nodes available"}
            
            # Adjust replication factor based on available nodes
            actual_replication = min(replication_factor, len(available_nodes))
            
            # Split file into chunks
            chunk_size = 1024 * 1024  # 1MB chunks
            chunks = []
            
            for i in range(0, len(file_data), chunk_size):
                chunk_data = file_data[i:i + chunk_size]
                chunk_id = f"{file_id}_chunk_{i // chunk_size}"
                chunks.append({
                    "chunk_id": chunk_id,
                    "data": chunk_data,
                    "chunk_index": i // chunk_size
                })
            
            # Distribute chunks to different nodes
            chunk_distribution = {}
            successful_distributions = 0
            
            for i, chunk in enumerate(chunks):
                # Select target node using round-robin
                target_node = available_nodes[i % len(available_nodes)]
                
                # Store chunk on target node
                chunk_hash = hashlib.md5(chunk["data"]).hexdigest()
                result = self.call_remote_method(
                    target_node, 
                    "store_file_chunk",
                    {
                        "file_id": file_id,
                        "chunk_data": chunk["data"].hex(),
                        "chunk_hash": chunk_hash
                    }
                )
                
                if result["success"]:
                    chunk_distribution[chunk["chunk_id"]] = target_node
                    successful_distributions += 1
                else:
                    print(f"Failed to store chunk {chunk['chunk_id']} on {target_node}: {result.get('error', 'Unknown error')}")
            
            # Store metadata on current node
            metadata = {
                "file_id": file_id,
                "filename": os.path.basename(file_path),
                "file_size": file_size,
                "chunk_count": len(chunks),
                "chunk_distribution": chunk_distribution,
                "created_at": time.time()
            }
            
            metadata_json = json.dumps(metadata)
            self.virtual_disk.write_data(f"{file_id}_metadata", metadata_json.encode())
            
            return {
                "success": True,
                "file_id": file_id,
                "filename": os.path.basename(file_path),
                "file_size": file_size,
                "chunk_count": len(chunks),
                "chunks_distributed": successful_distributions,
                "chunk_distribution": chunk_distribution,
                "replication_factor": actual_replication
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def get_node_stats(self) -> Dict:
        """Get comprehensive node statistics"""
        storage_info = self.virtual_disk.get_storage_info()
        
        return {
            "node_id": self.node_id,
            "ip": self.tcp_comm.ip if self.tcp_comm else None,
            "port": self.port,
            "uptime": time.time() - self.start_time,
            "is_active": self.is_active,
            "storage": storage_info,
            "performance": {
                "files_uploaded": self.files_uploaded,
                "files_downloaded": self.files_downloaded,
                "bytes_transferred": self.bytes_transferred,
                "active_transfers": self.active_transfers
            },
            "processes": {
                "total": len(self.process_manager.processes),
                "ready": len(self.process_manager.ready_queue),
                "waiting": len(self.process_manager.waiting_processes)
            }
        }
    
    def shutdown(self):
        """Shutdown the node gracefully"""
        self.is_active = False
        self.process_manager.running = False
        if self.network_manager:
            self.network_manager.stop()
        print(f"[{self.node_id}] Node shutdown complete")
