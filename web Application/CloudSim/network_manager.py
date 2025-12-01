import socket
import threading
import time
import json
import hashlib
from typing import Dict, List, Optional, Callable, Tuple
from dataclasses import dataclass
from enum import Enum, auto
import random

class MessageTypes(Enum):
    HEARTBEAT = "heartbeat"
    HEARTBEAT_RESPONSE = "heartbeat_response"
    DATA_TRANSFER = "data_transfer"
    DATA_ACK = "data_ack"
    RPC_REQUEST = "rpc_request"
    RPC_RESPONSE = "rpc_response"
    NODE_DISCOVERY = "node_discovery"
    NODE_ANNOUNCE = "node_announce"

@dataclass
class NetworkMessage:
    message_id: str
    message_type: MessageTypes
    source_ip: str
    target_ip: str
    payload: dict
    timestamp: float
    requires_ack: bool = False

class IPManager:
    def __init__(self, use_localhost: bool = True):
        self.use_localhost = use_localhost
        self.allocated_ips: Dict[str, str] = {}  # node_id -> ip
        self.ip_to_node: Dict[str, str] = {}  # ip -> node_id
        self.next_host = 1
        
    def allocate_ip(self, node_id: str) -> str:
        """Allocate an IP address to a node"""
        if node_id in self.allocated_ips:
            return self.allocated_ips[node_id]
        
        if self.use_localhost:
            # Use localhost for all nodes to avoid binding issues
            ip = "127.0.0.1"
        else:
            # Use custom network (may cause issues on some systems)
            if self.next_host > 254:
                raise Exception("No more IP addresses available")
            ip = f"10.0.0.{self.next_host}"
            self.next_host += 1
        
        self.allocated_ips[node_id] = ip
        self.ip_to_node[ip] = node_id
        
        return ip
    
    def get_node_ip(self, node_id: str) -> Optional[str]:
        """Get IP address for a node"""
        return self.allocated_ips.get(node_id)
    
    def get_node_from_ip(self, ip: str) -> Optional[str]:
        """Get node ID from IP address"""
        return self.ip_to_node.get(ip)
    
    def release_ip(self, node_id: str) -> bool:
        """Release an IP address"""
        if node_id in self.allocated_ips:
            ip = self.allocated_ips[node_id]
            del self.allocated_ips[node_id]
            del self.ip_to_node[ip]
            return True
        return False

class TCPCommunication:
    def __init__(self, node_id: str, ip: str, port: int):
        self.node_id = node_id
        self.ip = ip
        self.port = port
        self.socket = None
        self.server_socket = None
        self.running = False
        self.message_handlers: Dict[MessageTypes, Callable] = {}
        self.pending_acks: Dict[str, Tuple[NetworkMessage, float]] = {}
        self.ack_timeout = 5.0  # seconds
        
    def start_server(self):
        """Start the TCP server for this node"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Try to bind to the specified IP and port
        try:
            self.server_socket.bind((self.ip, self.port))
        except OSError as e:
            if "WinError 10049" in str(e) or "Address not available" in str(e):
                # Fallback to localhost if custom IP fails
                print(f"[{self.node_id}] Cannot bind to {self.ip}, falling back to localhost")
                self.ip = "127.0.0.1"
                self.server_socket.bind((self.ip, self.port))
            else:
                raise e
                
        self.server_socket.listen(5)
        self.running = True
        
        # Start server thread
        server_thread = threading.Thread(target=self._server_loop, daemon=True)
        server_thread.start()
        
        # Start ACK checker thread
        ack_thread = threading.Thread(target=self._ack_checker, daemon=True)
        ack_thread.start()
        
        print(f"[{self.node_id}] TCP server started on {self.ip}:{self.port}")
    
    def _server_loop(self):
        """Main server loop for accepting connections"""
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                # Handle each client in a separate thread
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, address),
                    daemon=True
                )
                client_thread.start()
            except Exception as e:
                if self.running:
                    print(f"[{self.node_id}] Server error: {e}")
    
    def _handle_client(self, client_socket: socket.socket, address: Tuple[str, int]):
        """Handle incoming client connection"""
        print(f"[{self.node_id}] Client connected from {address}")
        try:
            while self.running:
                data = client_socket.recv(4096)
                if not data:
                    break
                
                print(f"[{self.node_id}] Received {len(data)} bytes from {address}")
                try:
                    message_data = json.loads(data.decode())
                    # Convert string message_type back to enum
                    message_data['message_type'] = MessageTypes(message_data['message_type'])
                    message = NetworkMessage(**message_data)
                    self._process_message(message, client_socket)
                except Exception as e:
                    print(f"[{self.node_id}] Error processing message: {e}")
                    
        except Exception as e:
            print(f"[{self.node_id}] Client handler error: {e}")
        finally:
            print(f"[{self.node_id}] Client disconnected from {address}")
            client_socket.close()
    
    def _process_message(self, message: NetworkMessage, client_socket: socket.socket):
        """Process incoming message"""
        print(f"[{self.node_id}] Received {message.message_type.value} from {message.source_ip}")
        
        # Handle message based on type
        if message.message_type == MessageTypes.HEARTBEAT:
            response = NetworkMessage(
                message_id=self._generate_message_id(),
                message_type=MessageTypes.HEARTBEAT_RESPONSE,
                source_ip=self.ip,
                target_ip=message.source_ip,
                payload={"node_id": self.node_id, "status": "alive"},
                timestamp=time.time()
            )
            self._send_message_direct(response, client_socket)
        elif message.message_type == MessageTypes.DATA_TRANSFER:
            # Handle data transfer
            if message.message_type in self.message_handlers:
                self.message_handlers[message.message_type](message)
            
            # Send acknowledgment if required
            if message.requires_ack:
                ack = NetworkMessage(
                    message_id=self._generate_message_id(),
                    message_type=MessageTypes.DATA_ACK,
                    source_ip=self.ip,
                    target_ip=message.source_ip,
                    payload={"original_message_id": message.message_id},
                    timestamp=time.time()
                )
                self._send_message_direct(ack, client_socket)
        elif message.message_type == MessageTypes.DATA_ACK:
            # Process acknowledgment
            self._handle_ack(message)
        elif message.message_type in self.message_handlers:
            print(f"[{self.node_id}] Dispatching to handler for {message.message_type.value}")
            self.message_handlers[message.message_type](message)
        else:
            print(f"[{self.node_id}] No handler for message type: {message.message_type.value}")
    
    def _handle_ack(self, ack_message: NetworkMessage):
        """Handle incoming acknowledgment"""
        original_message_id = ack_message.payload.get("original_message_id")
        if original_message_id in self.pending_acks:
            del self.pending_acks[original_message_id]
            print(f"[{self.node_id}] Received ACK for message {original_message_id}")
    
    def send_message(self, target_ip: int, target_port: int, message: NetworkMessage) -> bool:
        """Send message to another node"""
        try:
            print(f"[{self.node_id}] Connecting to {target_ip}:{target_port}")
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(10.0)  # 10 second timeout
            client_socket.connect((target_ip, target_port))
            print(f"[{self.node_id}] Connected to {target_ip}:{target_port}")
            
            # Convert message to JSON-serializable format
            message_dict = {
                "message_id": message.message_id,
                "message_type": message.message_type.value,  # Convert enum to string
                "source_ip": message.source_ip,
                "target_ip": message.target_ip,
                "payload": message.payload,
                "timestamp": message.timestamp,
                "requires_ack": message.requires_ack
            }
            
            # Send message
            message_data = json.dumps(message_dict).encode()
            print(f"[{self.node_id}] Sending {len(message_data)} bytes to {target_ip}:{target_port}")
            client_socket.send(message_data)
            print(f"[{self.node_id}] Message sent to {target_ip}:{target_port}")
            
            # Store for ACK tracking if required
            if message.requires_ack:
                self.pending_acks[message.message_id] = (message, time.time())
            
            client_socket.close()
            return True
            
        except Exception as e:
            print(f"[{self.node_id}] Error sending message to {target_ip}:{target_port} - {e}")
            return False
    
    def _send_message_direct(self, message: NetworkMessage, client_socket: socket.socket):
        """Send message directly through existing socket"""
        try:
            message_data = json.dumps(message.__dict__).encode()
            client_socket.send(message_data)
        except Exception as e:
            print(f"[{self.node_id}] Error sending direct message: {e}")
    
    def _ack_checker(self):
        """Check for pending ACK timeouts"""
        while self.running:
            current_time = time.time()
            expired_messages = []
            
            for message_id, (message, sent_time) in self.pending_acks.items():
                if current_time - sent_time > self.ack_timeout:
                    expired_messages.append(message_id)
                    print(f"[{self.node_id}] ACK timeout for message {message_id}")
            
            # Remove expired messages
            for message_id in expired_messages:
                del self.pending_acks[message_id]
            
            time.sleep(1)  # Check every second
    
    def register_handler(self, message_type: MessageTypes, handler: Callable):
        """Register a message handler"""
        self.message_handlers[message_type] = handler
    
    def _generate_message_id(self) -> str:
        """Generate unique message ID"""
        return hashlib.md5(f"{self.node_id}-{time.time()}-{random.random()}".encode()).hexdigest()
    
    def stop(self):
        """Stop the TCP server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()

class NetworkManager:
    def __init__(self, use_localhost: bool = True):
        self.ip_manager = IPManager(use_localhost)
        self.nodes: Dict[str, TCPCommunication] = {}
        self.node_status: Dict[str, bool] = {}  # node_id -> is_alive
        self.heartbeat_interval = 10.0  # seconds
        self.heartbeat_thread = None
        self.running = False
        
    def add_node(self, node_id: str, port: int = 8000) -> str:
        """Add a node to the network"""
        ip = self.ip_manager.allocate_ip(node_id)
        
        # Create TCP communication for the node
        tcp_comm = TCPCommunication(node_id, ip, port)
        self.nodes[node_id] = tcp_comm
        self.node_status[node_id] = True
        
        # Start the node's server
        tcp_comm.start_server()
        
        # Register default handlers
        self._register_default_handlers(tcp_comm)
        
        return ip
    
    def _register_default_handlers(self, tcp_comm: TCPCommunication):
        """Register default message handlers"""
        def handle_node_discovery(message: NetworkMessage):
            """Handle node discovery requests"""
            response = NetworkMessage(
                message_id=tcp_comm._generate_message_id(),
                message_type=MessageTypes.NODE_ANNOUNCE,
                source_ip=tcp_comm.ip,
                target_ip=message.source_ip,
                payload={
                    "node_id": tcp_comm.node_id,
                    "status": "active",
                    "port": tcp_comm.port
                },
                timestamp=time.time()
            )
            # Send response back
            target_ip = message.source_ip
            target_port = message.payload.get("port", 8000)
            tcp_comm.send_message(target_ip, target_port, response)
        
        tcp_comm.register_handler(MessageTypes.NODE_DISCOVERY, handle_node_discovery)
    
    def discover_nodes(self, node_id: str) -> List[str]:
        """Discover other active nodes in the network"""
        if node_id not in self.nodes:
            return []
        
        tcp_comm = self.nodes[node_id]
        discovered_nodes = []
        
        # Send discovery message to all known nodes (regardless of status)
        for other_node_id, other_tcp in self.nodes.items():
            if other_node_id != node_id:
                discovery_message = NetworkMessage(
                    message_id=tcp_comm._generate_message_id(),
                    message_type=MessageTypes.NODE_DISCOVERY,
                    source_ip=tcp_comm.ip,
                    target_ip=other_tcp.ip,
                    payload={"port": tcp_comm.port},
                    timestamp=time.time()
                )
                
                if tcp_comm.send_message(other_tcp.ip, other_tcp.port, discovery_message):
                    discovered_nodes.append(other_node_id)
                    # Update node status to active if discovery succeeds
                    self.node_status[other_node_id] = True
        
        return discovered_nodes
    
    def check_node_status(self, node_id: str) -> bool:
        """Check if a node is alive by sending heartbeat"""
        if node_id not in self.nodes or node_id not in self.node_status:
            return False
        
        tcp_comm = self.nodes[node_id]
        
        # Send heartbeat to all other nodes
        for other_node_id, other_tcp in self.nodes.items():
            if other_node_id != node_id:
                heartbeat = NetworkMessage(
                    message_id=tcp_comm._generate_message_id(),
                    message_type=MessageTypes.HEARTBEAT,
                    source_ip=tcp_comm.ip,
                    target_ip=other_tcp.ip,
                    payload={"node_id": node_id},
                    timestamp=time.time()
                )
                tcp_comm.send_message(other_tcp.ip, other_tcp.port, heartbeat)
        
        return True
    
    def start_heartbeat_monitor(self):
        """Start continuous heartbeat monitoring"""
        self.running = True
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.heartbeat_thread.start()
    
    def _heartbeat_loop(self):
        """Continuous heartbeat monitoring loop"""
        while self.running:
            for node_id in self.nodes:
                self.check_node_status(node_id)
            time.sleep(self.heartbeat_interval)
    
    def stop(self):
        """Stop the network manager"""
        self.running = False
        for tcp_comm in self.nodes.values():
            tcp_comm.stop()
    
    def get_network_info(self) -> Dict:
        """Get network information"""
        return {
            "total_nodes": len(self.nodes),
            "active_nodes": sum(1 for status in self.node_status.values() if status),
            "node_ips": {node_id: comm.ip for node_id, comm in self.nodes.items()},
            "node_status": self.node_status.copy()
        }
