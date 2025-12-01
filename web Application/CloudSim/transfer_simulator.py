import time
import threading
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from enum import Enum, auto

class TransferSpeed(Enum):
    SLOW = "64kb/s"      # 64 KB/s
    MEDIUM = "1mb/s"     # 1 MB/s
    FAST = "10mb/s"      # 10 MB/s
    VERY_FAST = "100mb/s" # 100 MB/s

@dataclass
class TransferConfig:
    speed: TransferSpeed
    latency_ms: int = 50  # Network latency in milliseconds
    packet_loss: float = 0.0  # Packet loss percentage (0.0 to 1.0)
    jitter_ms: int = 10  # Jitter in milliseconds

class TransferSimulator:
    def __init__(self, default_config: Optional[TransferConfig] = None):
        self.speed_bytes_per_second = {
            TransferSpeed.SLOW: 64 * 1024,           # 64 KB/s
            TransferSpeed.MEDIUM: 1024 * 1024,       # 1 MB/s
            TransferSpeed.FAST: 10 * 1024 * 1024,    # 10 MB/s
            TransferSpeed.VERY_FAST: 100 * 1024 * 1024  # 100 MB/s
        }
        
        self.default_config = default_config or TransferConfig(TransferSpeed.SLOW)
        self.active_transfers: Dict[str, 'FileTransfer'] = {}
        self.transfer_history: List[Dict] = []
        self.callbacks: Dict[str, List[Callable]] = {
            'transfer_started': [],
            'transfer_progress': [],
            'transfer_completed': [],
            'transfer_failed': []
        }
    
    def register_callback(self, event: str, callback: Callable):
        """Register a callback for transfer events"""
        if event in self.callbacks:
            self.callbacks[event].append(callback)
    
    def _trigger_callbacks(self, event: str, transfer_data: dict):
        """Trigger callbacks for an event"""
        for callback in self.callbacks.get(event, []):
            try:
                callback(transfer_data)
            except Exception as e:
                print(f"Callback error: {e}")
    
    def simulate_transfer(self, transfer_id: str, file_size: int, 
                         config: Optional[TransferConfig] = None) -> 'FileTransfer':
        """Start a simulated file transfer"""
        transfer_config = config or self.default_config
        speed_bps = self.speed_bytes_per_second[transfer_config.speed]
        
        transfer = FileTransfer(
            transfer_id=transfer_id,
            file_size=file_size,
            speed_bps=speed_bps,
            config=transfer_config,
            start_time=time.time()
        )
        
        self.active_transfers[transfer_id] = transfer
        
        # Start transfer in background thread
        transfer_thread = threading.Thread(
            target=self._execute_transfer,
            args=(transfer,),
            daemon=True
        )
        transfer_thread.start()
        
        return transfer
    
    def _execute_transfer(self, transfer: 'FileTransfer'):
        """Execute the transfer simulation"""
        transfer.status = TransferStatus.RUNNING
        
        # Trigger transfer started callback
        self._trigger_callbacks('transfer_started', {
            'transfer_id': transfer.transfer_id,
            'file_size': transfer.file_size,
            'speed_bps': transfer.speed_bps
        })
        
        chunk_size = 1024  # 1KB chunks for simulation
        bytes_transferred = 0
        start_time = time.time()
        
        while bytes_transferred < transfer.file_size and transfer.status == TransferStatus.RUNNING:
            # Calculate transfer time for this chunk
            chunk_transfer_time = chunk_size / transfer.speed_bps
            
            # Add latency and jitter
            latency_factor = (transfer.config.latency_ms / 1000) / chunk_size
            jitter_factor = (transfer.config.jitter_ms / 1000) / chunk_size
            
            # Simulate packet loss (retry with delay)
            if transfer.config.packet_loss > 0:
                import random
                if random.random() < transfer.config.packet_loss:
                    # Packet lost, add retry delay
                    time.sleep(0.1)  # 100ms retry delay
                    continue
            
            # Simulate the transfer
            time.sleep(chunk_transfer_time * (1 + latency_factor + jitter_factor))
            
            bytes_transferred += chunk_size
            progress = min(bytes_transferred / transfer.file_size, 1.0)
            
            # Update transfer progress
            transfer.bytes_transferred = bytes_transferred
            transfer.progress = progress
            
            # Trigger progress callback
            self._trigger_callbacks('transfer_progress', {
                'transfer_id': transfer.transfer_id,
                'bytes_transferred': bytes_transferred,
                'progress': progress,
                'speed_bps': transfer.speed_bps
            })
        
        # Transfer completed or failed
        end_time = time.time()
        transfer.end_time = end_time
        transfer.duration = end_time - start_time
        
        if transfer.status == TransferStatus.RUNNING:
            transfer.status = TransferStatus.COMPLETED
            transfer.actual_speed_bps = transfer.file_size / transfer.duration
            
            # Add to history
            self._trigger_callbacks('transfer_completed', {
                'transfer_id': transfer.transfer_id,
                'duration': transfer.duration,
                'actual_speed_bps': transfer.actual_speed_bps
            })
            
            self.transfer_history.append({
                'transfer_id': transfer.transfer_id,
                'file_size': transfer.file_size,
                'duration': transfer.duration,
                'speed_bps': transfer.actual_speed_bps,
                'status': 'completed',
                'timestamp': end_time
            })
        else:
            # Transfer was cancelled/failed
            self._trigger_callbacks('transfer_failed', {
                'transfer_id': transfer.transfer_id,
                'reason': 'Transfer cancelled'
            })
            
            self.transfer_history.append({
                'transfer_id': transfer.transfer_id,
                'file_size': transfer.file_size,
                'duration': transfer.duration,
                'status': 'failed',
                'timestamp': end_time
            })
        
        # Remove from active transfers
        if transfer.transfer_id in self.active_transfers:
            del self.active_transfers[transfer.transfer_id]
    
    def cancel_transfer(self, transfer_id: str) -> bool:
        """Cancel an active transfer"""
        if transfer_id in self.active_transfers:
            transfer = self.active_transfers[transfer_id]
            transfer.status = TransferStatus.CANCELLED
            return True
        return False
    
    def get_transfer_status(self, transfer_id: str) -> Optional[Dict]:
        """Get status of a transfer"""
        if transfer_id in self.active_transfers:
            transfer = self.active_transfers[transfer_id]
            return {
                'transfer_id': transfer.transfer_id,
                'file_size': transfer.file_size,
                'bytes_transferred': transfer.bytes_transferred,
                'progress': transfer.progress,
                'status': transfer.status.name,
                'speed_bps': transfer.speed_bps,
                'duration': time.time() - transfer.start_time
            }
        return None
    
    def get_active_transfers(self) -> List[Dict]:
        """Get all active transfers"""
        return [
            self.get_transfer_status(tid) 
            for tid in self.active_transfers.keys()
        ]
    
    def get_transfer_statistics(self) -> Dict:
        """Get transfer statistics"""
        completed_transfers = [t for t in self.transfer_history if t['status'] == 'completed']
        failed_transfers = [t for t in self.transfer_history if t['status'] == 'failed']
        
        if completed_transfers:
            avg_speed = sum(t['speed_bps'] for t in completed_transfers) / len(completed_transfers)
            avg_duration = sum(t['duration'] for t in completed_transfers) / len(completed_transfers)
            total_bytes = sum(t['file_size'] for t in completed_transfers)
        else:
            avg_speed = 0
            avg_duration = 0
            total_bytes = 0
        
        return {
            'total_transfers': len(self.transfer_history),
            'completed_transfers': len(completed_transfers),
            'failed_transfers': len(failed_transfers),
            'active_transfers': len(self.active_transfers),
            'average_speed_bps': avg_speed,
            'average_duration': avg_duration,
            'total_bytes_transferred': total_bytes,
            'success_rate': len(completed_transfers) / max(len(self.transfer_history), 1) * 100
        }

class TransferStatus(Enum):
    PENDING = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()
    CANCELLED = auto()

@dataclass
class FileTransfer:
    transfer_id: str
    file_size: int
    speed_bps: int
    config: TransferConfig
    start_time: float
    end_time: Optional[float] = None
    duration: Optional[float] = None
    bytes_transferred: int = 0
    progress: float = 0.0
    status: TransferStatus = TransferStatus.PENDING
    actual_speed_bps: Optional[float] = None

# Utility functions for common transfer scenarios
def create_slow_transfer() -> TransferConfig:
    """Create a slow transfer configuration (64kb/s)"""
    return TransferConfig(
        speed=TransferSpeed.SLOW,
        latency_ms=100,
        packet_loss=0.05,
        jitter_ms=20
    )

def create_medium_transfer() -> TransferConfig:
    """Create a medium transfer configuration (1mb/s)"""
    return TransferConfig(
        speed=TransferSpeed.MEDIUM,
        latency_ms=50,
        packet_loss=0.02,
        jitter_ms=10
    )

def create_fast_transfer() -> TransferConfig:
    """Create a fast transfer configuration (10mb/s)"""
    return TransferConfig(
        speed=TransferSpeed.FAST,
        latency_ms=20,
        packet_loss=0.01,
        jitter_ms=5
    )

def simulate_realistic_upload(file_size_mb: float, simulator: TransferSimulator) -> str:
    """Simulate a realistic file upload with varying speeds"""
    # Simulate different speeds based on file size
    if file_size_mb < 1:
        config = create_fast_transfer()
    elif file_size_mb < 10:
        config = create_medium_transfer()
    else:
        config = create_slow_transfer()
    
    file_size_bytes = int(file_size_mb * 1024 * 1024)
    transfer_id = f"upload_{int(time.time())}"
    
    simulator.simulate_transfer(transfer_id, file_size_bytes, config)
    return transfer_id
