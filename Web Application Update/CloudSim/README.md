# CloudSim - Distributed Storage System Simulation

**Engineer Moone's Distributed Systems Project**

A comprehensive distributed storage system simulation built from scratch without frameworks, featuring virtual nodes, TCP-based communication, and a minimal operating system environment.

## 🌟 Features

### Core Infrastructure
- **Virtual Disks**: 2GB storage per node, backed by actual host files
- **Block-based Storage Allocation**: Clear visualization of data segment allocation
- **TCP/IP Communication**: Reliable messaging with acknowledgment mechanisms
- **IP Addressing System**: Custom virtual network management

### Distributed System Components
- **5+ Virtual Nodes**: Each with independent interfaces and 2GB storage
- **Node Discovery**: Heartbeat system for detecting active/inactive nodes
- **Data Chunking**: Files split into chunks distributed across nodes
- **Transfer Speed Simulation**: Configurable speeds including 64kb/s as specified
- **Process Management**: Ready/waiting states for concurrent operations

### Advanced Features
- **RPC-like Functions**: Remote procedure calls for node communication
- **Command-line Interface**: Interactive file operations and system management
- **Minimal OS Environment**: CloudOS with filesystem, processes, and shell
- **Real Storage Backing**: Uses actual host machine storage for virtual disks

## 🚀 Quick Start

### Installation
```bash
# Clone or navigate to the CloudSim directory
cd "Distributed Systems Sample Project1/CloudSim"

# Ensure Python 3.7+ is installed
python --version
```

### Running the System

#### 1. Interactive CLI (Recommended)
```bash
python main.py
```
Then type `start` to initialize the distributed network.

#### 2. Demonstration Mode
```bash
python main.py --demo
```
Runs a complete demonstration of all system features.

#### 3. Test Suite
```bash
python main.py --test
```
Runs comprehensive system tests.

## 📋 CLI Commands

### Network Management
- `start` - Initialize 5-node distributed network
- `status` - Show network and node status
- `nodes` - List all nodes in the network
- `switch <node_id>` - Switch to a different node
- `discover` - Discover other nodes in the network
- `shutdown` - Shutdown the network

### File Operations
- `upload <file_path>` - Upload a file to the distributed network
- `storage` - Show storage information for current node
- `blockmap` - Show block allocation map

### Network Communication
- `ping <node_id>` - Ping a node to check connectivity
- `rpc <node_id> <method> [params]` - Execute RPC command

### System Monitoring
- `transfers` - Show active and completed transfers
- `help` - List all available commands
- `exit` / `quit` - Exit the CLI

## 🏗️ System Architecture

### Core Components

#### VirtualDisk (`virtual_disk.py`)
- 2GB capacity per node
- 64KB block size
- Block-based allocation with clear visualization
- Backed by host machine files

#### NetworkManager (`network_manager.py`)
- TCP-based communication with acknowledgments
- IP address allocation (10.0.0.x range)
- Heartbeat monitoring for node discovery
- Message routing and delivery confirmation

#### VirtualNode (`virtual_node.py`)
- Independent node interfaces
- RPC service registration and calling
- File distribution across nodes
- Process management integration

#### TransferSimulator (`transfer_simulator.py`)
- Configurable transfer speeds (64kb/s, 1mb/s, 10mb/s, 100mb/s)
- Network latency and packet loss simulation
- Real-time progress tracking
- Transfer statistics and monitoring

#### VirtualOS (`virtual_os.py`)
- Minimal operating system environment
- Virtual filesystem with Unix-like commands
- Process management (ready/waiting/running states)
- System services and logging

#### CLI Interface (`cli_interface.py`)
- Interactive command-line interface
- Real-time system monitoring
- File upload/download operations
- Network diagnostics

## 📊 Technical Specifications

### Storage System
- **Capacity**: 2GB per node (10GB total for 5 nodes)
- **Block Size**: 64KB
- **Allocation**: Block-based with free/allocated/occupied states
- **Backing**: Actual host files in `virtual_storage/` directory

### Network System
- **Protocol**: TCP/IP
- **IP Range**: 10.0.0.1 - 10.0.0.254
- **Ports**: 8000-8004 for 5 nodes
- **Features**: Acknowledgments, heartbeat, node discovery

### Transfer System
- **Default Speed**: 64kb/s (as specified)
- **Chunk Size**: 1MB for file transfers
- **Latency**: Configurable network latency simulation
- **Packet Loss**: Optional packet loss simulation

### Process Management
- **States**: Ready, Waiting, Running, Completed, Failed
- **Priority**: 1-10 priority levels
- **Types**: System, User, Daemon processes
- **Scheduling**: Simple round-robin scheduler

## 🧪 Testing

The system includes comprehensive tests for all major components:

```bash
python main.py --test
```

Test Coverage:
- ✅ Virtual Disk Creation and Management
- ✅ File System Operations
- ✅ Network Manager Functionality
- ✅ Transfer Simulator
- ✅ Virtual OS Operations

## 📁 File Structure

```
CloudSim/
├── main.py                 # Main entry point
├── virtual_disk.py         # Virtual disk implementation
├── network_manager.py      # Network communication
├── virtual_node.py         # Virtual node with RPC
├── transfer_simulator.py   # Transfer speed simulation
├── virtual_os.py          # Minimal OS environment
├── cli_interface.py       # Command-line interface
├── README.md              # This file
└── virtual_storage/       # Created during runtime
    ├── node_alpha/
    ├── node_beta/
    ├── node_gamma/
    ├── node_delta/
    └── node_epsilon/
        ├── disk.img       # Virtual disk image
        └── metadata.json  # Disk metadata
```

## 🔧 Configuration

### Default Settings
- **Nodes**: 5 (alpha, beta, gamma, delta, epsilon)
- **Storage per node**: 2GB
- **Transfer speed**: 64kb/s
- **Network**: 10.0.0.x IP range
- **Ports**: 8000-8004

### Customization
You can modify the following in the code:
- Node count and names in `main.py`
- Storage capacity in `VirtualDisk` constructor
- Transfer speeds in `TransferSimulator`
- Network configuration in `NetworkManager`

## 🎯 Project Requirements Fulfilled

✅ **Virtual Storage Environment**: Complete virtual disk implementation  
✅ **No Frameworks**: Pure Python using only standard library  
✅ **Virtual HDD**: 2GB storage per node backed by host files  
✅ **Storage Allocation**: Clear block-based allocation mechanism  
✅ **5+ Virtual Nodes**: Independent interfaces for each node  
✅ **Node Discovery**: Heartbeat system for alive/inactive detection  
✅ **TCP Communication**: With acknowledgment mechanism  
✅ **Data Chunking**: Files split and distributed across nodes  
✅ **Transfer Speed Simulation**: 64kb/s with timing  
✅ **Process Management**: Ready/waiting states implementation  
✅ **RPC Functions**: Remote procedure call system  
✅ **Command-line Operations**: File upload/download interface  
✅ **Minimal OS Environment**: CloudOS with filesystem and shell  

## 🚀 Running the Complete Simulation

1. **Start the system**:
   ```bash
   python main.py
   ```

2. **Initialize the network**:
   ```
   d_storage> start
   ```

3. **Upload a file**:
   ```
   d_storage> upload test_file.txt
   ```

4. **Monitor the system**:
   ```
   d_storage> status
   d_storage> storage
   d_storage> transfers
   ```

5. **Test communication**:
   ```
   d_storage> ping node_beta
   d_storage> rpc node_gamma get_storage_info
   ```

6. **Shutdown gracefully**:
   ```
   d_storage> shutdown
   ```

## 🎓 Educational Value

This system demonstrates:
- Distributed storage concepts
- Network communication protocols
- Operating system principles
- Process management
- File system design
- RPC mechanisms
- System simulation techniques

Perfect for understanding distributed systems, cloud storage, and network programming concepts!
