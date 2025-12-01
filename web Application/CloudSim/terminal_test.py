#!/usr/bin/env python3
"""
Simple Terminal Test for CloudSim Distributed Systems
Run this to verify all functionality works perfectly
"""

import os
import time
import tempfile
from virtual_node import VirtualNode
from network_manager import NetworkManager

def print_status(message, status="INFO"):
    """Print status with color coding"""
    colors = {
        "INFO": "\033[94m",     # Blue
        "SUCCESS": "\033[92m",  # Green
        "WARNING": "\033[93m",  # Yellow
        "ERROR": "\033[91m",    # Red
        "RESET": "\033[0m"      # Reset
    }
    
    color = colors.get(status, colors["INFO"])
    reset = colors["RESET"]
    print(f"{color}[{status}]{reset} {message}")

def test_basic_functionality():
    """Test basic node functionality"""
    print_status("=== Testing Basic Functionality ===", "INFO")
    
    # Create shared network
    network = NetworkManager(use_localhost=True)
    
    # Create nodes
    print_status("Creating nodes...", "INFO")
    node1 = VirtualNode("alpha", port=8000, shared_network_manager=network)
    node2 = VirtualNode("beta", port=8001, shared_network_manager=network)
    
    time.sleep(2)  # Wait for initialization
    
    # Test discovery
    print_status("Testing node discovery...", "INFO")
    discovered = node1.discover_other_nodes()
    if discovered:
        print_status(f"Node discovery successful: {discovered}", "SUCCESS")
    else:
        print_status("Node discovery failed", "ERROR")
        return False
    
    # Test RPC
    print_status("Testing RPC communication...", "INFO")
    try:
        result = node1.call_remote_method("beta", "ping")
        if result and result.get('success'):
            print_status(f"RPC ping successful: {result['node_id']}", "SUCCESS")
        else:
            print_status("RPC ping failed", "ERROR")
            return False
    except Exception as e:
        print_status(f"RPC ping error: {e}", "ERROR")
        return False
    
    # Test storage
    print_status("Testing storage operations...", "INFO")
    try:
        storage_info = node1.call_remote_method("alpha", "get_storage_info")
        print_status(f"Storage info: {storage_info['total_blocks']} blocks total, {storage_info['free_blocks']} free", "SUCCESS")
    except Exception as e:
        print_status(f"Storage info error: {e}", "ERROR")
        return False
    
    # Cleanup
    node1.shutdown()
    node2.shutdown()
    network.stop()
    
    return True

def test_file_operations():
    """Test file distribution and retrieval"""
    print_status("=== Testing File Operations ===", "INFO")
    
    # Create network and nodes
    network = NetworkManager(use_localhost=True)
    node1 = VirtualNode("storage_node1", port=8002, shared_network_manager=network)
    node2 = VirtualNode("storage_node2", port=8003, shared_network_manager=network)
    
    time.sleep(2)
    
    # Create test file
    print_status("Creating test file...", "INFO")
    test_content = "Hello, Distributed Cloud Storage System!\nThis is a test file.\n"
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write(test_content)
        test_file = f.name
    
    try:
        # Distribute file
        print_status("Distributing file across nodes...", "INFO")
        result = node1.distribute_file(test_file, replication_factor=1)
        
        if result.get('success'):
            print_status(f"File distributed successfully: {result['chunk_count']} chunks", "SUCCESS")
            file_id = result['file_id']
            
            # Test retrieval
            print_status("Testing file retrieval...", "INFO")
            retrieve_result = node2.call_remote_method("storage_node2", "retrieve_file_chunk", 
                                                      {"file_id": file_id})
            
            if retrieve_result.get('success'):
                retrieved_content = bytes.fromhex(retrieve_result['chunk_data']).decode()
                if retrieved_content == test_content:
                    print_status("File retrieval successful - content matches!", "SUCCESS")
                else:
                    print_status("File retrieval failed - content mismatch", "ERROR")
                    return False
            else:
                print_status(f"File retrieval failed: {retrieve_result.get('error')}", "ERROR")
                return False
        else:
            print_status(f"File distribution failed: {result.get('error')}", "ERROR")
            return False
            
    except Exception as e:
        print_status(f"File operations error: {e}", "ERROR")
        return False
    finally:
        # Cleanup
        os.unlink(test_file)
        node1.shutdown()
        node2.shutdown()
        network.stop()
    
    return True

def test_process_management():
    """Test process management"""
    print_status("=== Testing Process Management ===", "INFO")
    
    network = NetworkManager(use_localhost=True)
    node = VirtualNode("process_node", port=8004, shared_network_manager=network)
    
    time.sleep(1)
    
    try:
        # Create processes
        print_status("Creating test processes...", "INFO")
        proc_ids = []
        for i in range(3):
            proc_id = node.process_manager.create_process(f"test_proc_{i}", lambda: None)
            proc_ids.append(proc_id)
        
        # List processes
        processes = node.process_manager.list_processes()
        print_status(f"Created {len(processes)} processes", "SUCCESS")
        
        for proc in processes:
            print_status(f"  - {proc['name']}: {proc['state']}", "INFO")
        
    except Exception as e:
        print_status(f"Process management error: {e}", "ERROR")
        return False
    finally:
        node.shutdown()
        network.stop()
    
    return True

def test_performance_metrics():
    """Test performance metrics"""
    print_status("=== Testing Performance Metrics ===", "INFO")
    
    network = NetworkManager(use_localhost=True)
    node = VirtualNode("metrics_node", port=8005, shared_network_manager=network)
    
    time.sleep(1)
    
    try:
        stats = node.get_node_stats()
        print_status("Performance Metrics:", "INFO")
        print_status(f"  Node ID: {stats['node_id']}", "INFO")
        print_status(f"  Uptime: {stats['uptime']:.2f} seconds", "INFO")
        print_status(f"  Storage: {stats['storage']['used_blocks']}/{stats['storage']['total_blocks']} blocks used", "INFO")
        print_status(f"  Processes: {stats['processes']['total']} total", "INFO")
        print_status("Metrics collection successful", "SUCCESS")
        
    except Exception as e:
        print_status(f"Metrics error: {e}", "ERROR")
        return False
    finally:
        node.shutdown()
        network.stop()
    
    return True

def main():
    """Run all tests"""
    print_status("🚀 CloudSim Distributed Systems Test Suite", "INFO")
    print_status("=" * 50, "INFO")
    
    tests = [
        ("Basic Functionality", test_basic_functionality),
        ("File Operations", test_file_operations),
        ("Process Management", test_process_management),
        ("Performance Metrics", test_performance_metrics)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print_status(f"\nRunning {test_name} test...", "INFO")
        try:
            if test_func():
                passed += 1
                print_status(f"✅ {test_name} PASSED", "SUCCESS")
            else:
                print_status(f"❌ {test_name} FAILED", "ERROR")
        except Exception as e:
            print_status(f"💥 {test_name} CRASHED: {e}", "ERROR")
    
    print_status("\n" + "=" * 50, "INFO")
    print_status(f"Test Results: {passed}/{total} tests passed", "INFO")
    
    if passed == total:
        print_status("🎉 ALL TESTS PASSED! Your CloudSim system is working perfectly!", "SUCCESS")
    else:
        print_status("⚠️  Some tests failed. Check the output above for details.", "WARNING")
    
    print_status("\nTo run individual tests:", "INFO")
    print_status("  python terminal_test.py", "INFO")
    print_status("\nTo run the comprehensive test suite:", "INFO")
    print_status("  python comprehensive_test.py", "INFO")

if __name__ == "__main__":
    main()
