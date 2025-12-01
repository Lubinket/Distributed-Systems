import os
import json
import time
import hashlib
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum, auto

class BlockStatus(Enum):
    FREE = auto()
    ALLOCATED = auto()
    OCCUPIED = auto()

@dataclass
class StorageBlock:
    block_id: int
    start_offset: int
    size: int
    status: BlockStatus = BlockStatus.FREE
    file_id: Optional[str] = None
    checksum: Optional[str] = None

@dataclass
class VirtualFile:
    file_id: str
    filename: str
    size: int
    blocks: List[int]
    created_at: float
    checksum: str

class VirtualDisk:
    def __init__(self, node_id: str, capacity_gb: int = 2, block_size_kb: int = 64):
        self.node_id = node_id
        self.capacity_bytes = capacity_gb * 1024 * 1024 * 1024  # Convert GB to bytes
        self.block_size = block_size_kb * 1024  # Convert KB to bytes
        self.total_blocks = self.capacity_bytes // self.block_size
        
        # Create disk storage directory
        self.disk_path = f"virtual_storage/{node_id}"
        self.disk_file = os.path.join(self.disk_path, "disk.img")
        self.metadata_file = os.path.join(self.disk_path, "metadata.json")
        
        # Initialize storage
        self._initialize_disk()
        
        # Storage management
        self.blocks: List[StorageBlock] = []
        self.files: Dict[str, VirtualFile] = {}
        self.allocated_blocks = 0
        self.used_storage = 0
        
        # Initialize blocks
        self._initialize_blocks()
        
    def _initialize_disk(self):
        """Create virtual disk file and directory structure"""
        os.makedirs(self.disk_path, exist_ok=True)
        
        # Create disk image file (sparse file)
        if not os.path.exists(self.disk_file):
            with open(self.disk_file, 'wb') as f:
                f.seek(self.capacity_bytes - 1)
                f.write(b'\0')
                
        # Initialize metadata if doesn't exist
        if not os.path.exists(self.metadata_file):
            metadata = {
                "node_id": self.node_id,
                "capacity_bytes": self.capacity_bytes,
                "block_size": self.block_size,
                "total_blocks": self.total_blocks,
                "created_at": time.time()
            }
            with open(self.metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
    
    def _initialize_blocks(self):
        """Initialize storage blocks"""
        self.blocks = []
        for i in range(self.total_blocks):
            block = StorageBlock(
                block_id=i,
                start_offset=i * self.block_size,
                size=self.block_size,
                status=BlockStatus.FREE
            )
            self.blocks.append(block)
    
    def _save_metadata(self):
        """Save disk metadata to file"""
        metadata = {
            "node_id": self.node_id,
            "capacity_bytes": self.capacity_bytes,
            "block_size": self.block_size,
            "total_blocks": self.total_blocks,
            "allocated_blocks": self.allocated_blocks,
            "used_storage": self.used_storage,
            "blocks": [
                {
                    "block_id": b.block_id,
                    "start_offset": b.start_offset,
                    "size": b.size,
                    "status": b.status.name,
                    "file_id": b.file_id,
                    "checksum": b.checksum
                }
                for b in self.blocks
            ],
            "files": {
                file_id: {
                    "file_id": f.file_id,
                    "filename": f.filename,
                    "size": f.size,
                    "blocks": f.blocks,
                    "created_at": f.created_at,
                    "checksum": f.checksum
                }
                for file_id, f in self.files.items()
            }
        }
        
        with open(self.metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
    
    def _load_metadata(self):
        """Load disk metadata from file"""
        if os.path.exists(self.metadata_file):
            with open(self.metadata_file, 'r') as f:
                metadata = json.load(f)
                
            self.allocated_blocks = metadata.get("allocated_blocks", 0)
            self.used_storage = metadata.get("used_storage", 0)
            
            # Load blocks
            self.blocks = []
            for block_data in metadata.get("blocks", []):
                block = StorageBlock(
                    block_id=block_data["block_id"],
                    start_offset=block_data["start_offset"],
                    size=block_data["size"],
                    status=BlockStatus[block_data["status"]],
                    file_id=block_data.get("file_id"),
                    checksum=block_data.get("checksum")
                )
                self.blocks.append(block)
            
            # Load files
            self.files = {}
            for file_id, file_data in metadata.get("files", {}).items():
                file_obj = VirtualFile(
                    file_id=file_data["file_id"],
                    filename=file_data["filename"],
                    size=file_data["size"],
                    blocks=file_data["blocks"],
                    created_at=file_data["created_at"],
                    checksum=file_data["checksum"]
                )
                self.files[file_id] = file_obj
    
    def allocate_storage(self, file_id: str, filename: str, size: int) -> Optional[List[int]]:
        """Allocate storage blocks for a file"""
        required_blocks = (size + self.block_size - 1) // self.block_size
        
        # Find contiguous free blocks
        free_blocks = [b for b in self.blocks if b.status == BlockStatus.FREE]
        
        if len(free_blocks) < required_blocks:
            return None
        
        # Allocate blocks
        allocated_blocks = []
        for i in range(required_blocks):
            block = free_blocks[i]
            block.status = BlockStatus.ALLOCATED
            block.file_id = file_id
            allocated_blocks.append(block.block_id)
        
        # Create file record
        file_checksum = hashlib.md5(f"{file_id}-{filename}-{size}".encode()).hexdigest()
        virtual_file = VirtualFile(
            file_id=file_id,
            filename=filename,
            size=size,
            blocks=allocated_blocks,
            created_at=time.time(),
            checksum=file_checksum
        )
        
        self.files[file_id] = virtual_file
        self.allocated_blocks += required_blocks
        self.used_storage += size
        
        self._save_metadata()
        return allocated_blocks
    
    def write_data(self, file_id: str, data: bytes, offset: int = 0) -> bool:
        """Write data to allocated blocks"""
        if file_id not in self.files:
            return False
        
        virtual_file = self.files[file_id]
        block_size = self.block_size
        
        # Calculate which blocks to write to
        start_block = offset // block_size
        block_offset = offset % block_size
        
        data_written = 0
        for block_id in virtual_file.blocks[start_block:]:
            if data_written >= len(data):
                break
                
            block = self.blocks[block_id]
            remaining_data = len(data) - data_written
            bytes_to_write = min(remaining_data, block_size - block_offset)
            
            # Write to disk file
            with open(self.disk_file, 'r+b') as f:
                f.seek(block.start_offset + block_offset)
                f.write(data[data_written:data_written + bytes_to_write])
            
            # Update block metadata
            block.status = BlockStatus.OCCUPIED
            block.checksum = hashlib.md5(data[data_written:data_written + bytes_to_write]).hexdigest()
            
            data_written += bytes_to_write
            block_offset = 0  # Only first block has offset
        
        self._save_metadata()
        return True
    
    def read_data(self, file_id: str, size: int, offset: int = 0) -> Optional[bytes]:
        """Read data from storage blocks"""
        if file_id not in self.files:
            return None
        
        virtual_file = self.files[file_id]
        block_size = self.block_size
        
        # Calculate which blocks to read from
        start_block = offset // block_size
        block_offset = offset % block_size
        
        data = b''
        for block_id in virtual_file.blocks[start_block:]:
            if len(data) >= size:
                break
                
            block = self.blocks[block_id]
            remaining_bytes = size - len(data)
            bytes_to_read = min(remaining_bytes, block_size - block_offset)
            
            # Read from disk file
            with open(self.disk_file, 'rb') as f:
                f.seek(block.start_offset + block_offset)
                chunk = f.read(bytes_to_read)
                data += chunk
            
            block_offset = 0  # Only first block has offset
        
        return data
    
    def delete_file(self, file_id: str) -> bool:
        """Delete a file and free its blocks"""
        if file_id not in self.files:
            return False
        
        virtual_file = self.files[file_id]
        
        # Free blocks
        for block_id in virtual_file.blocks:
            block = self.blocks[block_id]
            block.status = BlockStatus.FREE
            block.file_id = None
            block.checksum = None
            
            # Zero out the block data
            with open(self.disk_file, 'r+b') as f:
                f.seek(block.start_offset)
                f.write(b'\0' * block.size)
        
        # Update statistics
        self.allocated_blocks -= len(virtual_file.blocks)
        self.used_storage -= virtual_file.size
        
        # Remove file record
        del self.files[file_id]
        
        self._save_metadata()
        return True
    
    def get_storage_info(self) -> Dict:
        """Get storage utilization information"""
        return {
            "node_id": self.node_id,
            "capacity_gb": self.capacity_bytes / (1024**3),
            "total_blocks": self.total_blocks,
            "allocated_blocks": self.allocated_blocks,
            "free_blocks": self.total_blocks - self.allocated_blocks,
            "used_storage_gb": self.used_storage / (1024**3),
            "free_storage_gb": (self.capacity_bytes - self.used_storage) / (1024**3),
            "utilization_percent": (self.used_storage / self.capacity_bytes) * 100,
            "files_stored": len(self.files),
            "block_size_kb": self.block_size / 1024
        }
    
    def list_files(self) -> List[Dict]:
        """List all stored files"""
        return [
            {
                "file_id": f.file_id,
                "filename": f.filename,
                "size_mb": f.size / (1024**2),
                "blocks_count": len(f.blocks),
                "created_at": f.created_at
            }
            for f in self.files.values()
        ]
    
    def get_block_allocation_map(self) -> List[Dict]:
        """Get detailed block allocation information"""
        return [
            {
                "block_id": b.block_id,
                "status": b.status.name,
                "file_id": b.file_id,
                "has_data": b.status == BlockStatus.OCCUPIED
            }
            for b in self.blocks
        ]
