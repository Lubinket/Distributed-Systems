#!/usr/bin/env python3
"""
Comprehensive Test Suite for Distributed Systems CloudSim Project
Tests all major functionality including:
- Node creation and management
- File storage and retrieval
- RPC communication
- Process management
- Distributed file operations
- Network discovery
"""

import os
import time
import hashlib
import tempfile
from virtual_node import VirtualNode
from network_manager import NetworkManager

class CloudSimTestSuite:
    def __init__(self):
        self.shared_network = NetworkManager(use_localhost=True)
        self.nodes = {}
        self.test_files = {}
        
    def setup_nodes(self, node_count=3):
        """Setup multiple nodes for testing"""
        print(f"=== Setting up {node_count} nodes ===")
        ports = [8000, 8001, 8002][:node_count]
        
        for i, port in enumerate(ports):
            node_id = f"node_{chr(65+i)}"  # node_A, node_B, node_C
            print(f"Creating {node_id} on port {port}...")
            node = VirtualNode(node_id, capacity_gb=2, port=port, 
                             use_localhost=True, shared_network_manager=self.shared_network)
            self.nodes[node_id] = node
            time.sleep(0.5)  # Give each node time to start
        
        print(f"✓ Created {len(self.nodes)} nodes")
        time.sleep(2)  # Let all nodes fully initialize
        
    def test_node_discovery(self):
        """Test node discovery functionality"""
        print("\n=== Testing Node Discovery ===")
        
        for node_id, node in self.nodes.items():
            try:
                discovered = node.discover_other_nodes()
                expected_count = len(self.nodes) - 1
                print(f"{node_id} discovered {len(discovered)} nodes (expected: {expected_count})")
                if len(discovered) == expected_count:
                    print(f"✓ {node_id} discovery successful")
                else:
                    print(f"✗ {node_id} discovery incomplete")
            except Exception as e:
                print(f"✗ {node_id} discovery failed: {e}")
    
    def test_rpc_communication(self):
        """Test RPC communication between nodes"""
        print("\n=== Testing RPC Communication ===")
        
        node_ids = list(self.nodes.keys())
        success_count = 0
        
        for i, source_id in enumerate(node_ids):
            for target_id in node_ids:
                if source_id != target_id:
                    try:
                        source_node = self.nodes[source_id]
                        print(f"{source_id} pinging {target_id}...")
                        result = source_node.call_remote_method(target_id, "ping")
                        
                        if result and result.get('success'):
                            print(f"✓ {source_id} → {target_id}: {result['node_id']} (uptime: {result['uptime']:.2f}s)")
                            success_count += 1
                        else:
                            print(f"✗ {source_id} → {target_id}: Invalid response")
                    except Exception as e:
                        print(f"✗ {source_id} → {target_id}: {e}")
        
        total_tests = len(node_ids) * (len(node_ids) - 1)
        print(f"\nRPC Tests: {success_count}/{total_tests} successful")
    
    def test_storage_info(self):
        """Test storage information retrieval"""
        print("\n=== Testing Storage Information ===")
        
        for node_id, node in self.nodes.items():
            try:
                storage_info = node.call_remote_method(node_id, "get_storage_info")
                print(f"{node_id} Storage:")
                print(f"  Total blocks: {storage_info['total_blocks']}")
                print(f"  Free blocks: {storage_info['free_blocks']}")
                print(f"  Used blocks: {storage_info['used_blocks']}")
                print(f"  Capacity: {storage_info['capacity_gb']}GB")
                print(f"✓ {node_id} storage info retrieved")
            except Exception as e:
                print(f"✗ {node_id} storage info failed: {e}")
    
    def create_test_files(self, count=3):
        """Create test files for distribution testing"""
        print(f"\n=== Creating {count} Test Files ===")
        
        for i in range(count):
            # Create test content
            content = f"This is test file {i+1} with some sample content.\n"
            content += f"File index: {i}\n"
            content += f"Timestamp: {time.time()}\n"
            content += f"Random data: {hashlib.md5(f'{i}{time.time()}'.encode()).hexdigest()}\n"
            
            # Create temporary file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=f'_test_{i}.txt') as f:
                f.write(content)
                file_path = f.name
            
            self.test_files[f"test_file_{i}"] = {
                'path': file_path,
                'size': len(content.encode()),
                'hash': hashlib.md5(content.encode()).hexdigest()
            }
            
            print(f"Created test_file_{i}: {len(content)} bytes")
        
        print(f"✓ Created {len(self.test_files)} test files")
    
    def test_file_distribution(self):
        """Test distributed file storage"""
        print("\n=== Testing File Distribution ===")
        
        if len(self.nodes) < 2:
            print("✗ Need at least 2 nodes for file distribution testing")
            return
        
        # Use the first node as the distributor
        distributor_id = list(self.nodes.keys())[0]
        distributor = self.nodes[distributor_id]
        
        for file_name, file_info in self.test_files.items():
            try:
                print(f"Distributing {file_name} from {distributor_id}...")
                result = distributor.distribute_file(file_info['path'], replication_factor=2)
                
                if result.get('success'):
                    print(f"✓ {file_name} distributed successfully:")
                    print(f"  File ID: {result['file_id']}")
                    print(f"  Size: {result['file_size']} bytes")
                    print(f"  Chunks: {result['chunk_count']}")
                    print(f"  Distributed chunks: {result['chunks_distributed']}")
                    print(f"  Replication factor: {result['replication_factor']}")
                    
                    # Store distribution info for later retrieval test
                    file_info['distribution'] = result
                else:
                    print(f"✗ {file_name} distribution failed: {result.get('error', 'Unknown error')}")
                    
            except Exception as e:
                print(f"✗ {file_name} distribution error: {e}")
    
    def test_file_retrieval(self):
        """Test distributed file retrieval"""
        print("\n=== Testing File Retrieval ===")
        
        for file_name, file_info in self.test_files.items():
            if 'distribution' not in file_info:
                print(f"✗ {file_name}: No distribution info available")
                continue
            
            try:
                file_id = file_info['distribution']['file_id']
                chunk_distribution = file_info['distribution']['chunk_distribution']
                
                print(f"Retrieving {file_name} (ID: {file_id})...")
                
                # Test retrieval from different nodes
                retrieved_chunks = 0
                for chunk_id, target_node in chunk_distribution.items():
                    try:
                        target = self.nodes[target_node]
                        result = target.call_remote_method(target_node, "retrieve_file_chunk", 
                                                         {"file_id": file_id})
                        
                        if result.get('success'):
                            retrieved_chunks += 1
                            print(f"✓ Retrieved {chunk_id} from {target_node} ({result['size']} bytes)")
                        else:
                            print(f"✗ Failed to retrieve {chunk_id} from {target_node}: {result.get('error')}")
                    except Exception as e:
                        print(f"✗ Error retrieving {chunk_id} from {target_node}: {e}")
                
                expected_chunks = len(chunk_distribution)
                print(f"Retrieved {retrieved_chunks}/{expected_chunks} chunks for {file_name}")
                
            except Exception as e:
                print(f"✗ {file_name} retrieval error: {e}")
    
    def test_process_management(self):
        """Test process management functionality"""
        print("\n=== Testing Process Management ===")
        
        for node_id, node in self.nodes.items():
            try:
                # Create some test processes
                process_ids = []
                
                for i in range(3):
                    proc_id = node.process_manager.create_process(f"test_process_{i}", lambda: None)
                    process_ids.append(proc_id)
                
                print(f"{node_id} created {len(process_ids)} processes")
                
                # List processes
                processes = node.process_manager.list_processes()
                print(f"{node_id} has {len(processes)} processes:")
                
                for proc in processes:
                    print(f"  {proc['name']}: {proc['state']}")
                
                print(f"✓ {node_id} process management working")
                
            except Exception as e:
                print(f"✗ {node_id} process management failed: {e}")
    
    def test_network_resilience(self):
        """Test network resilience and node failure simulation"""
        print("\n=== Testing Network Resilience ===")
        
        if len(self.nodes) < 3:
            print("✗ Need at least 3 nodes for resilience testing")
            return
        
        # Pick a node to "shutdown"
        node_to_shutdown = list(self.nodes.keys())[2]
        print(f"Simulating shutdown of {node_to_shutdown}...")
        
        # Test communication before shutdown
        source_node = list(self.nodes.keys())[0]
        target_node = list(self.nodes.keys())[1]
        
        try:
            result = self.nodes[source_node].call_remote_method(target_node, "ping")
            before_shutdown = result.get('success', False)
            print(f"Communication before shutdown: {'✓' if before_shutdown else '✗'}")
        except Exception as e:
            print(f"Communication before shutdown failed: {e}")
            before_shutdown = False
        
        # Shutdown the node
        self.nodes[node_to_shutdown].shutdown()
        time.sleep(1)
        
        # Test communication after shutdown
        try:
            result = self.nodes[source_node].call_remote_method(target_node, "ping")
            after_shutdown = result.get('success', False)
            print(f"Communication after shutdown: {'✓' if after_shutdown else '✗'}")
        except Exception as e:
            print(f"Communication after shutdown failed: {e}")
            after_shutdown = False
        
        # Test discovery after shutdown
        try:
            discovered = self.nodes[source_node].discover_other_nodes()
            print(f"Discovered nodes after shutdown: {discovered}")
            if node_to_shutdown not in discovered:
                print("✓ Shutdown node properly removed from discovery")
            else:
                print("✗ Shutdown node still appears in discovery")
        except Exception as e:
            print(f"Discovery after shutdown failed: {e}")
    
    def test_performance_metrics(self):
        """Test performance metrics collection"""
        print("\n=== Testing Performance Metrics ===")
        
        for node_id, node in self.nodes.items():
            try:
                stats = node.get_node_stats()
                print(f"{node_id} Statistics:")
                print(f"  Uptime: {stats['uptime']:.2f}s")
                print(f"  IP: {stats['ip']}:{stats['port']}")
                print(f"  Active: {stats['is_active']}")
                print(f"  Files uploaded: {stats['performance']['files_uploaded']}")
                print(f"  Files downloaded: {stats['performance']['files_downloaded']}")
                print(f"  Bytes transferred: {stats['performance']['bytes_transferred']}")
                print(f"  Total processes: {stats['processes']['total']}")
                print(f"✓ {node_id} metrics collected")
            except Exception as e:
                print(f"✗ {node_id} metrics failed: {e}")
    
    def cleanup(self):
        """Clean up test environment"""
        print("\n=== Cleanup ===")
        
        # Shutdown all nodes
        for node_id, node in self.nodes.items():
            try:
                node.shutdown()
                print(f"✓ {node_id} shutdown")
            except Exception as e:
                print(f"✗ {node_id} shutdown failed: {e}")
        
        # Stop network manager
        try:
            self.shared_network.stop()
            print("✓ Network manager stopped")
        except Exception as e:
            print(f"✗ Network manager stop failed: {e}")
        
        # Remove test files
        for file_name, file_info in self.test_files.items():
            try:
                os.unlink(file_info['path'])
                print(f"✓ Removed {file_name}")
            except Exception as e:
                print(f"✗ Failed to remove {file_name}: {e}")
    
    def run_all_tests(self):
        """Run complete test suite"""
        print("🚀 Starting CloudSim Comprehensive Test Suite")
        print("=" * 60)
        
        try:
            # Setup
            self.setup_nodes(3)
            
            # Core functionality tests
            self.test_node_discovery()
            self.test_rpc_communication()
            self.test_storage_info()
            
            # File system tests
            self.create_test_files(3)
            self.test_file_distribution()
            self.test_file_retrieval()
            
            # Process management
            self.test_process_management()
            
            # Advanced tests
            self.test_network_resilience()
            self.test_performance_metrics()
            
            print("\n" + "=" * 60)
            print("🎉 All tests completed!")
            print("Check the output above for any ✗ markers indicating failures.")
            
        except KeyboardInterrupt:
            print("\n🛑 Test suite interrupted by user")
        except Exception as e:
            print(f"\n💥 Test suite failed with error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.cleanup()

if __name__ == "__main__":
    test_suite = CloudSimTestSuite()
    test_suite.run_all_tests()
