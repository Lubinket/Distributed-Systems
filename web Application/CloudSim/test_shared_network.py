#!/usr/bin/env python3
"""
Test with shared NetworkManager to fix the node discovery issue.
"""

import time
from virtual_node import VirtualNode
from network_manager import NetworkManager

def test_shared_network_manager():
    """Test nodes with a shared NetworkManager"""
    print("=== Shared NetworkManager Test ===")
    
    # Create a shared network manager
    shared_network = NetworkManager(use_localhost=True)
    
    # Create nodes using the shared network manager
    print("Creating nodes with shared NetworkManager...")
    node_alpha = VirtualNode("node_alpha", capacity_gb=2, port=8000, use_localhost=True, shared_network_manager=shared_network)
    node_beta = VirtualNode("node_beta", capacity_gb=2, port=8001, use_localhost=True, shared_network_manager=shared_network)
    
    # Wait for initialization
    time.sleep(2)
    
    # Check network status
    print(f"\nNetwork Info:")
    network_info = shared_network.get_network_info()
    print(f"  Total nodes: {network_info['total_nodes']}")
    print(f"  Active nodes: {network_info['active_nodes']}")
    print(f"  Node IPs: {network_info['node_ips']}")
    print(f"  Node status: {network_info['node_status']}")
    
    # Test node discovery
    print(f"\n=== Testing Node Discovery ===")
    try:
        alpha_discoveries = node_alpha.discover_other_nodes()
        print(f"Alpha discovered: {alpha_discoveries}")
        
        beta_discoveries = node_beta.discover_other_nodes()
        print(f"Beta discovered: {beta_discoveries}")
    except Exception as e:
        print(f"Discovery failed: {e}")
    
    # Test RPC ping
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
    
    # Wait for debug output
    print(f"\n=== Waiting for Debug Output (5 seconds) ===")
    time.sleep(5)
    
    # Cleanup
    print(f"\n=== Cleanup ===")
    node_alpha.shutdown()
    node_beta.shutdown()
    shared_network.stop()
    
    print("Shared NetworkManager test completed.")

if __name__ == "__main__":
    print("Starting Shared NetworkManager Test")
    print("=" * 50)
    
    try:
        test_shared_network_manager()
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
    
    print("\nTest completed.")
