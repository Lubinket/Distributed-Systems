#!/usr/bin/env python3
"""
Simple test to isolate the node_beta connection issue.
This test will:
1. Create two nodes with different configurations
2. Test basic TCP connectivity between them
3. Check if servers are properly binding and accepting connections
"""

import time
import threading
import socket
from virtual_node import VirtualNode

def test_basic_connectivity():
    """Test basic TCP connectivity between two nodes"""
    print("=== Basic TCP Connectivity Test ===")
    
    # Create two nodes with different ports
    print("Creating node_alpha on port 8000...")
    node_alpha = VirtualNode("node_alpha", capacity_gb=2, port=8000, use_localhost=True)
    
    print("Creating node_beta on port 8001...")
    node_beta = VirtualNode("node_beta", capacity_gb=2, port=8001, use_localhost=True)
    
    # Wait for servers to start
    time.sleep(2)
    
    # Check server status
    print(f"\nNode Alpha Status:")
    print(f"  IP: {node_alpha.tcp_comm.ip}")
    print(f"  Port: {node_alpha.tcp_comm.port}")
    print(f"  Server running: {node_alpha.tcp_comm.running}")
    print(f"  Server socket: {node_alpha.tcp_comm.server_socket}")
    
    print(f"\nNode Beta Status:")
    print(f"  IP: {node_beta.tcp_comm.ip}")
    print(f"  Port: {node_beta.tcp_comm.port}")
    print(f"  Server running: {node_beta.tcp_comm.running}")
    print(f"  Server socket: {node_beta.tcp_comm.server_socket}")
    
    # Test direct socket connection from alpha to beta
    print(f"\n=== Testing Direct Socket Connection ===")
    try:
        print(f"Attempting to connect from alpha to beta ({node_beta.tcp_comm.ip}:{node_beta.tcp_comm.port})...")
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.settimeout(5.0)
        result = test_socket.connect((node_beta.tcp_comm.ip, node_beta.tcp_comm.port))
        print(f"✓ Direct connection successful!")
        test_socket.close()
    except Exception as e:
        print(f"✗ Direct connection failed: {e}")
    
    # Test ping using RPC
    print(f"\n=== Testing RPC Ping ===")
    try:
        print("Alpha pinging Beta...")
        ping_result = node_alpha.call_remote_method("node_beta", "ping")
        print(f"✓ Ping successful: {ping_result}")
    except Exception as e:
        print(f"✗ Ping failed: {e}")
    
    # Test reverse ping
    print(f"\n=== Testing Reverse RPC Ping ===")
    try:
        print("Beta pinging Alpha...")
        ping_result = node_beta.call_remote_method("node_alpha", "ping")
        print(f"✓ Reverse ping successful: {ping_result}")
    except Exception as e:
        print(f"✗ Reverse ping failed: {e}")
    
    # Test node discovery
    print(f"\n=== Testing Node Discovery ===")
    try:
        alpha_discoveries = node_alpha.discover_other_nodes()
        print(f"Alpha discovered: {alpha_discoveries}")
        
        beta_discoveries = node_beta.discover_other_nodes()
        print(f"Beta discovered: {beta_discoveries}")
    except Exception as e:
        print(f"Discovery failed: {e}")
    
    # Wait a bit to see any debug output
    print(f"\n=== Waiting for Debug Output (5 seconds) ===")
    time.sleep(5)
    
    # Cleanup
    print(f"\n=== Cleanup ===")
    node_alpha.shutdown()
    node_beta.shutdown()
    
    print("Test completed.")

def test_server_binding():
    """Test server binding with different IP configurations"""
    print("\n=== Server Binding Test ===")
    
    # Test 1: Both nodes on localhost
    print("Test 1: Both nodes on localhost")
    try:
        node1 = VirtualNode("test1", port=9000, use_localhost=True)
        node2 = VirtualNode("test2", port=9001, use_localhost=True)
        time.sleep(1)
        
        # Test connection
        try:
            result = node1.call_remote_method("test2", "ping")
            print(f"✓ Localhost test successful: {result}")
        except Exception as e:
            print(f"✗ Localhost test failed: {e}")
        finally:
            node1.shutdown()
            node2.shutdown()
    except Exception as e:
        print(f"✗ Localhost binding failed: {e}")
    
    # Test 2: Mixed binding (one localhost, one custom)
    print("\nTest 2: Mixed binding")
    try:
        node1 = VirtualNode("test1", port=9002, use_localhost=True)
        node2 = VirtualNode("test2", port=9003, use_localhost=False)  # This might cause issues
        time.sleep(1)
        
        # Test connection
        try:
            result = node1.call_remote_method("test2", "ping")
            print(f"✓ Mixed binding test successful: {result}")
        except Exception as e:
            print(f"✗ Mixed binding test failed: {e}")
        finally:
            node1.shutdown()
            node2.shutdown()
    except Exception as e:
        print(f"✗ Mixed binding setup failed: {e}")

def test_port_conflicts():
    """Test what happens with port conflicts"""
    print("\n=== Port Conflict Test ===")
    
    try:
        # Try to create two nodes on the same port
        node1 = VirtualNode("conflict1", port=10000, use_localhost=True)
        time.sleep(1)
        
        try:
            node2 = VirtualNode("conflict2", port=10000, use_localhost=True)  # Same port
            print("✗ Port conflict not detected - this should fail!")
            node2.shutdown()
        except Exception as e:
            print(f"✓ Port conflict properly detected: {e}")
        finally:
            node1.shutdown()
    except Exception as e:
        print(f"Port conflict test setup failed: {e}")

if __name__ == "__main__":
    print("Starting Node Beta Connection Isolation Test")
    print("=" * 50)
    
    try:
        # Run tests
        test_basic_connectivity()
        test_server_binding()
        test_port_conflicts()
        
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
    
    print("\nAll tests completed.")
