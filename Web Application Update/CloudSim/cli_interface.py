import cmd
import sys
import os
import time
import threading
from typing import Dict, List, Optional
from virtual_node import VirtualNode
from transfer_simulator import TransferSimulator, create_slow_transfer
import json

class DistributedStorageCLI(cmd.Cmd):
    intro = """
    ========================================================================
                           Distributed Storage System CLI
                              Engineer Moone's Project
    ========================================================================
    
    Type 'help' or '?' to list commands.
    Type 'start' to initialize the distributed network.
    """
    
    prompt = "d_storage> "
    
    def __init__(self):
        super().__init__()
        self.nodes: Dict[str, VirtualNode] = {}
        self.transfer_simulator = TransferSimulator()
        self.network_started = False
        self.current_node = None
        
        # Register transfer callbacks
        self.transfer_simulator.register_callback('transfer_started', self._on_transfer_started)
        self.transfer_simulator.register_callback('transfer_progress', self._on_transfer_progress)
        self.transfer_simulator.register_callback('transfer_completed', self._on_transfer_completed)
    
    def _on_transfer_started(self, transfer_data: dict):
        print(f"Transfer started: {transfer_data['transfer_id']}")
        print(f"   File size: {transfer_data['file_size'] / (1024*1024):.2f} MB")
        print(f"   Speed: {transfer_data['speed_bps'] / 1024:.0f} KB/s")
    
    def _on_transfer_progress(self, transfer_data: dict):
        progress = transfer_data['progress'] * 100
        print(f"{transfer_data['transfer_id']}: {progress:.1f}% complete")
    
    def _on_transfer_completed(self, transfer_data: dict):
        duration = transfer_data['duration']
        speed = transfer_data['actual_speed_bps']
        print(f"Transfer completed: {transfer_data['transfer_id']}")
        print(f"   Duration: {duration:.2f}s")
        print(f"   Average speed: {speed / 1024:.0f} KB/s")
    
    def do_start(self, arg):
        """Start the distributed network with 5 nodes"""
        if self.network_started:
            print("Network already started!")
            return
        
        print("Starting distributed storage network...")
        print("   Creating 5 virtual nodes with 2GB storage each...")
        
        # Create 5 nodes
        node_configs = [
            ("node_alpha", 8000),
            ("node_beta", 8001),
            ("node_gamma", 8002),
            ("node_delta", 8003),
            ("node_epsilon", 8004)
        ]
        
        for node_id, port in node_configs:
            try:
                node = VirtualNode(node_id, capacity_gb=2, port=port, use_localhost=True)
                self.nodes[node_id] = node
                print(f"   SUCCESS: {node_id} created at {node.tcp_comm.ip}:{port}")
                time.sleep(0.5)  # Give each node time to initialize
            except Exception as e:
                print(f"   FAILED: {node_id}: {e}")
        
        if len(self.nodes) == 5:
            self.network_started = True
            self.current_node = "node_alpha"
            
            # Start heartbeat monitoring
            self.nodes["node_alpha"].network_manager.start_heartbeat_monitor()
            
            print(f"\nNetwork started successfully!")
            print(f"   Active nodes: {len(self.nodes)}")
            print(f"   Current node: {self.current_node}")
            print(f"   Total storage: {len(self.nodes) * 2} GB")
        else:
            print("FAILED to start complete network")
    
    def do_status(self, arg):
        """Show network and node status"""
        if not self.network_started:
            print("Network not started. Use 'start' command first.")
            return
        
        print("\nNetwork Status")
        print("=" * 60)
        
        for node_id, node in self.nodes.items():
            is_current = "CURRENT" if node_id == self.current_node else "       "
            status = "ACTIVE" if node.is_active else "INACTIVE"
            
            print(f"{is_current} {status} {node_id}")
            print(f"   IP: {node.tcp_comm.ip}:{node.port}")
            print(f"   Uptime: {time.time() - node.start_time:.1f}s")
            
            storage = node.virtual_disk.get_storage_info()
            print(f"   Storage: {storage['used_storage_gb']:.2f}/{storage['capacity_gb']:.1f} GB "
                  f"({storage['utilization_percent']:.1f}%)")
            print(f"   Files: {storage['files_stored']}")
            
            perf = node.get_node_stats()['performance']
            print(f"   Transfers: UP:{perf['files_uploaded']} DOWN:{perf['files_downloaded']}")
            print()
    
    def do_nodes(self, arg):
        """List all nodes in the network"""
        if not self.network_started:
            print("❌ Network not started. Use 'start' command first.")
            return
        
        print("\n🖥️  Network Nodes")
        print("=" * 50)
        
        for i, (node_id, node) in enumerate(self.nodes.items(), 1):
            current = " (CURRENT)" if node_id == self.current_node else ""
            status = "🟢 Active" if node.is_active else "🔴 Inactive"
            print(f"{i}. {node_id}{current}")
            print(f"   Status: {status}")
            print(f"   Address: {node.tcp_comm.ip}:{node.port}")
            print(f"   Storage: {node.virtual_disk.get_storage_info()['capacity_gb']} GB")
            print()
    
    def do_switch(self, arg):
        """Switch to a different node: switch <node_id>"""
        if not self.network_started:
            print("❌ Network not started. Use 'start' command first.")
            return
        
        args = arg.split()
        if len(args) != 1:
            print("Usage: switch <node_id>")
            return
        
        node_id = args[0]
        if node_id in self.nodes:
            old_node = self.current_node
            self.current_node = node_id
            print(f"🔄 Switched from {old_node} to {node_id}")
        else:
            print(f"❌ Node {node_id} not found")
    
    def do_discover(self, arg):
        """Discover other nodes in the network"""
        if not self.network_started:
            print("❌ Network not started. Use 'start' command first.")
            return
        
        current_node = self.nodes[self.current_node]
        discovered = current_node.discover_other_nodes()
        
        print(f"\n🔍 Node Discovery from {self.current_node}")
        print("=" * 50)
        
        if discovered:
            print(f"Found {len(discovered)} other nodes:")
            for node_id in discovered:
                status = "🟢" if self.nodes[node_id].is_active else "🔴"
                print(f"  {status} {node_id}")
        else:
            print("No other nodes discovered")
    
    def do_upload(self, arg):
        """Upload a file to the distributed network: upload <file_path>"""
        if not self.network_started:
            print("❌ Network not started. Use 'start' command first.")
            return
        
        args = arg.split()
        if len(args) != 1:
            print("Usage: upload <file_path>")
            return
        
        file_path = args[0]
        if not os.path.exists(file_path):
            print(f"❌ File {file_path} not found")
            return
        
        try:
            current_node = self.nodes[self.current_node]
            print(f"📤 Uploading {file_path} from {self.current_node}...")
            
            # Start simulated transfer
            file_size = os.path.getsize(file_path)
            transfer_id = self.transfer_simulator.simulate_transfer(
                f"upload_{int(time.time())}", 
                file_size,
                create_slow_transfer()  # 64kb/s as specified
            )
            
            # Actually distribute the file
            result = current_node.distribute_file(file_path, replication_factor=2)
            
            if result["success"]:
                print(f"✅ File uploaded successfully!")
                print(f"   File ID: {result['file_id']}")
                print(f"   Size: {result['file_size'] / (1024*1024):.2f} MB")
                print(f"   Chunks distributed to {len(result['chunk_distribution'])} nodes")
            else:
                print(f"❌ Upload failed: {result['error']}")
                
        except Exception as e:
            print(f"❌ Upload error: {e}")
    
    def do_storage(self, arg):
        """Show storage information for current node"""
        if not self.network_started:
            print("❌ Network not started. Use 'start' command first.")
            return
        
        current_node = self.nodes[self.current_node]
        storage_info = current_node.virtual_disk.get_storage_info()
        
        print(f"\n💾 Storage Information for {self.current_node}")
        print("=" * 60)
        print(f"Capacity: {storage_info['capacity_gb']:.1f} GB")
        print(f"Used: {storage_info['used_storage_gb']:.2f} GB")
        print(f"Free: {storage_info['free_storage_gb']:.2f} GB")
        print(f"Utilization: {storage_info['utilization_percent']:.1f}%")
        print(f"Files stored: {storage_info['files_stored']}")
        print(f"Total blocks: {storage_info['total_blocks']}")
        print(f"Allocated blocks: {storage_info['allocated_blocks']}")
        print(f"Free blocks: {storage_info['free_blocks']}")
        print(f"Block size: {storage_info['block_size_kb']} KB")
        
        # Show file list
        files = current_node.virtual_disk.list_files()
        if files:
            print(f"\n📁 Stored Files:")
            for file_info in files:
                print(f"  📄 {file_info['filename']}")
                print(f"     Size: {file_info['size_mb']:.2f} MB")
                print(f"     Blocks: {file_info['blocks_count']}")
                print(f"     Created: {time.ctime(file_info['created_at'])}")
    
    def do_ping(self, arg):
        """Ping a node: ping <node_id>"""
        if not self.network_started:
            print("❌ Network not started. Use 'start' command first.")
            return
        
        args = arg.split()
        if len(args) != 1:
            print("Usage: ping <node_id>")
            return
        
        target_node_id = args[0]
        if target_node_id not in self.nodes:
            print(f"❌ Node {target_node_id} not found")
            return
        
        try:
            current_node = self.nodes[self.current_node]
            print(f"🏓 Pinging {target_node_id} from {self.current_node}...")
            
            result = current_node.call_remote_method(target_node_id, "ping")
            
            if result["success"]:
                response_time = time.time() - result["timestamp"]
                print(f"✅ Reply from {target_node_id}")
                print(f"   Node ID: {result['node_id']}")
                print(f"   Uptime: {result['uptime']:.1f}s")
                print(f"   Response time: {response_time*1000:.0f}ms")
            else:
                print(f"❌ Ping failed: {result.get('error', 'Unknown error')}")
                
        except Exception as e:
            print(f"❌ Ping error: {e}")
    
    def do_transfers(self, arg):
        """Show active and completed transfers"""
        print("\n📡 Transfer Status")
        print("=" * 50)
        
        # Active transfers
        active = self.transfer_simulator.get_active_transfers()
        if active:
            print("🔄 Active Transfers:")
            for transfer in active:
                progress = transfer['progress'] * 100
                print(f"  📤 {transfer['transfer_id']}")
                print(f"     Progress: {progress:.1f}%")
                print(f"     Speed: {transfer['speed_bps'] / 1024:.0f} KB/s")
        else:
            print("🔄 No active transfers")
        
        # Statistics
        stats = self.transfer_simulator.get_transfer_statistics()
        print(f"\n📊 Transfer Statistics:")
        print(f"   Total: {stats['total_transfers']}")
        print(f"   Completed: {stats['completed_transfers']}")
        print(f"   Failed: {stats['failed_transfers']}")
        print(f"   Success rate: {stats['success_rate']:.1f}%")
        print(f"   Average speed: {stats['average_speed_bps'] / 1024:.0f} KB/s")
    
    def do_blockmap(self, arg):
        """Show block allocation map for current node"""
        if not self.network_started:
            print("❌ Network not started. Use 'start' command first.")
            return
        
        current_node = self.nodes[self.current_node]
        blocks = current_node.virtual_disk.get_block_allocation_map()
        
        print(f"\n🗺️  Block Allocation Map for {self.current_node}")
        print("=" * 60)
        
        allocated = sum(1 for b in blocks if b['status'] != 'FREE')
        free = len(blocks) - allocated
        
        print(f"Total blocks: {len(blocks)}")
        print(f"Allocated: {allocated}")
        print(f"Free: {free}")
        
        # Visual representation
        print(f"\n📊 Block Map (F=Free, A=Allocated, O=Occupied):")
        row = ""
        for i, block in enumerate(blocks):
            if i > 0 and i % 50 == 0:
                print(row)
                row = ""
            
            if block['status'] == 'FREE':
                row += "F"
            elif block['status'] == 'ALLOCATED':
                row += "A"
            else:
                row += "O"
        
        if row:
            print(row)
    
    def do_rpc(self, arg):
        """Execute RPC command: rpc <node_id> <method> [params as JSON]"""
        if not self.network_started:
            print("❌ Network not started. Use 'start' command first.")
            return
        
        args = arg.split(maxsplit=2)
        if len(args) < 2:
            print("Usage: rpc <node_id> <method> [params as JSON]")
            return
        
        node_id, method = args[0], args[1]
        params = {}
        
        if len(args) == 3:
            try:
                params = json.loads(args[2])
            except json.JSONDecodeError:
                print("❌ Invalid JSON parameters")
                return
        
        if node_id not in self.nodes:
            print(f"❌ Node {node_id} not found")
            return
        
        try:
            current_node = self.nodes[self.current_node]
            print(f"🔧 Calling {method} on {node_id}...")
            
            result = current_node.call_remote_method(node_id, method, params)
            
            print(f"✅ RPC Result:")
            print(json.dumps(result, indent=2))
            
        except Exception as e:
            print(f"❌ RPC error: {e}")
    
    def do_shutdown(self, arg):
        """Shutdown the network"""
        if not self.network_started:
            print("❌ Network not started.")
            return
        
        print("🛑 Shutting down distributed storage network...")
        
        for node_id, node in self.nodes.items():
            try:
                node.shutdown()
                print(f"   ✅ {node_id} shutdown")
            except Exception as e:
                print(f"   ❌ Error shutting down {node_id}: {e}")
        
        self.nodes.clear()
        self.network_started = False
        self.current_node = None
        print("🔌 Network shutdown complete")
    
    def do_exit(self, arg):
        """Exit the CLI"""
        if self.network_started:
            print("🛑 Shutting down network before exit...")
            self.do_shutdown(arg)
        print("👋 Goodbye!")
        return True
    
    def do_quit(self, arg):
        """Exit the CLI (alias for exit)"""
        return self.do_exit(arg)

def main():
    """Main entry point for the CLI"""
    cli = DistributedStorageCLI()
    
    try:
        cli.cmdloop()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        if cli.network_started:
            cli.do_shutdown("")
    except Exception as e:
        print(f"❌ CLI error: {e}")

if __name__ == "__main__":
    main()
