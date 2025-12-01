#!/usr/bin/env python3
"""
CloudSim - Distributed Storage System Simulation
Engineer Moone's Distributed Systems Project

This is the main entry point for the distributed storage system simulation.
The system includes:
- Virtual disks with 2GB storage per node
- TCP-based network communication with acknowledgments
- 5+ virtual nodes with independent interfaces
- Data chunking and distribution across nodes
- Transfer speed simulation (64kb/s)
- Process management with ready/waiting states
- RPC-like functions for node communication
- Command-line interface for file operations
- Minimal OS environment simulation

Usage:
    python main.py                    # Start CLI interface
    python main.py --demo             # Run demonstration
    python main.py --test             # Run system tests
"""

import sys
import time
import threading
from cli_interface_fixed import DistributedStorageCLI
from virtual_node import VirtualNode
from virtual_os import VirtualOS

def run_demo():
    """Run a demonstration of the distributed storage system"""
    print("CloudSim Distributed Storage System Demo")
    print("=" * 60)
    
    # Create nodes
    print("\nInitializing distributed network...")
    nodes = {}
    
    for i, (node_id, port) in enumerate([
        ("node_alpha", 8000),
        ("node_beta", 8001), 
        ("node_gamma", 8002),
        ("node_delta", 8003),
        ("node_epsilon", 8004)
    ]):
        try:
            node = VirtualNode(node_id, capacity_gb=2, port=port, use_localhost=True)
            nodes[node_id] = node
            print(f"   SUCCESS: {node_id} created at {node.tcp_comm.ip}:{port}")
            time.sleep(0.3)
        except Exception as e:
            print(f"   FAILED: {node_id}: {e}")
    
    if len(nodes) < 5:
        print("FAILED to initialize complete network")
        return
    
    # Start heartbeat monitoring
    nodes["node_alpha"].network_manager.start_heartbeat_monitor()
    
    print(f"\nNetwork started with {len(nodes)} nodes")
    print(f"   Total storage: {len(nodes) * 2} GB")
    
    # Boot virtual OS on first node
    print(f"\nBooting CloudOS on {nodes['node_alpha'].node_id}...")
    virtual_os = VirtualOS("node_alpha", nodes["node_alpha"].virtual_disk)
    virtual_os.boot()
    
    # Demonstrate filesystem operations
    print(f"\nDemonstrating filesystem operations...")
    
    # Create some files and directories
    commands = [
        "mkdir /home/user",
        "mkdir /home/user/documents", 
        "touch /home/user/readme.txt",
        "echo 'Welcome to CloudOS!' > /home/user/readme.txt",
        "mkdir /tmp",
        "touch /tmp/test.dat",
        "echo 'Test data' > /tmp/test.dat",
        "ls /home/user",
        "cat /home/user/readme.txt",
        "df",
        "ps"
    ]
    
    for cmd in commands:
        if ">" in cmd:
            # Handle redirect
            parts = cmd.split(">")
            command = parts[0].strip()
            content = parts[1].strip()
            
            # For demo, just echo to file
            if "echo" in command:
                filename = content.strip()
                echo_content = command.replace("echo ", "").replace("'", "").strip()
                path = virtual_os.filesystem.get_absolute_path(filename)
                virtual_os.filesystem.create_file(path, echo_content.encode())
                print(f"$ {cmd}")
        else:
            result = virtual_os.execute_command(cmd)
            print(f"$ {cmd}")
            if result and result != "exit":
                print(result)
        time.sleep(0.2)
    
    # Demonstrate node discovery
    print(f"\nDemonstrating node discovery...")
    discovered = nodes["node_alpha"].discover_other_nodes()
    print(f"   Discovered {len(discovered)} other nodes:")
    for node_id in discovered:
        print(f"   ACTIVE: {node_id}")
    
    # Demonstrate RPC calls
    print(f"\nDemonstrating RPC communication...")
    try:
        # Ping other nodes
        for node_id in ["node_beta", "node_gamma"]:
            result = nodes["node_alpha"].call_remote_method(node_id, "ping")
            if result["success"]:
                print(f"   RPC {node_id}: Uptime {result['uptime']:.1f}s")
    except Exception as e:
        print(f"   RPC demo failed: {e}")
    
    # Show system statistics
    print(f"\nSystem Statistics:")
    for node_id, node in nodes.items():
        stats = node.get_node_stats()
        storage = stats["storage"]
        perf = stats["performance"]
        print(f"   NODE {node_id}:")
        print(f"      Storage: {storage['used_storage_gb']:.2f}/{storage['capacity_gb']:.1f} GB")
        print(f"      Files: {storage['files_stored']}")
        print(f"      Uploads: {perf['files_uploaded']}")
        print(f"      Downloads: {perf['files_downloaded']}")
    
    print(f"\nDemo completed successfully!")
    print(f"   Run 'python main.py' to start the interactive CLI")
    
    # Cleanup
    virtual_os.shutdown()
    for node in nodes.values():
        node.shutdown()

def run_tests():
    """Run system tests"""
    print("Running CloudSim System Tests")
    print("=" * 50)
    
    tests_passed = 0
    tests_total = 0
    
    def test(name, test_func):
        nonlocal tests_passed, tests_total
        tests_total += 1
        try:
            test_func()
            print(f"PASS: {name}")
            tests_passed += 1
        except Exception as e:
            print(f"FAIL: {name}: {e}")
    
    # Test 1: Virtual Disk Creation
    def test_virtual_disk():
        from virtual_disk import VirtualDisk
        disk = VirtualDisk("test_node", 1)  # 1GB test disk
        info = disk.get_storage_info()
        assert info["capacity_gb"] == 1.0
        assert info["used_storage_gb"] == 0.0
        disk.delete_file("test_file")  # Cleanup
    
    # Test 2: File System Operations
    def test_filesystem():
        from virtual_disk import VirtualDisk
        from virtual_os import VirtualFileSystem
        
        disk = VirtualDisk("test_fs", 1)
        fs = VirtualFileSystem(disk, "test_fs")
        
        # Test directory creation
        assert fs.create_directory("/test")
        assert fs.file_exists("/test")
        
        # Test file creation
        test_content = b"Hello, CloudOS!"
        assert fs.create_file("/test/hello.txt", test_content)
        assert fs.file_exists("/test/hello.txt")
        
        # Test file reading
        content = fs.read_file("/test/hello.txt")
        assert content == test_content
        
        # Test file listing
        files = fs.list_directory("/test")
        assert len(files) == 1
        assert files[0].name == "hello.txt"
    
    # Test 3: Network Manager
    def test_network_manager():
        from network_manager import NetworkManager
        
        net = NetworkManager(use_localhost=True)  # Use localhost to avoid binding issues
        ip = net.add_node("test_node", 9000)
        assert ip.startswith("127.0.0.1") or ip == "127.0.0.1"
        
        info = net.get_network_info()
        assert info["total_nodes"] == 1
        assert info["active_nodes"] == 1
        
        net.stop()
    
    # Test 4: Transfer Simulator
    def test_transfer_simulator():
        from transfer_simulator import TransferSimulator, TransferSpeed
        
        sim = TransferSimulator()
        transfer = sim.simulate_transfer("test_transfer", 1024)  # 1KB
        
        # Wait for completion
        time.sleep(0.5)
        
        stats = sim.get_transfer_statistics()
        assert stats["total_transfers"] >= 1
    
    # Test 5: Virtual OS
    def test_virtual_os():
        from virtual_disk import VirtualDisk
        from virtual_os import VirtualOS
        
        disk = VirtualDisk("test_os", 1)
        os = VirtualOS("test_os", disk)
        
        # Test boot
        assert os.boot()
        assert os.is_running
        
        # Test shell commands
        result = os.execute_command("pwd")
        assert result == "/"
        
        result = os.execute_command("mkdir /test")
        assert result == ""
        
        result = os.execute_command("ls /")
        assert "test" in result
        
        os.shutdown()
    
    # Run all tests
    test("Virtual Disk Creation", test_virtual_disk)
    test("File System Operations", test_filesystem)
    test("Network Manager", test_network_manager)
    test("Transfer Simulator", test_transfer_simulator)
    test("Virtual OS", test_virtual_os)
    
    print(f"\nTest Results: {tests_passed}/{tests_total} tests passed")
    
    if tests_passed == tests_total:
        print("All tests passed!")
        return True
    else:
        print("Some tests failed")
        return False

def main():
    """Main entry point"""
    args = sys.argv[1:] if len(sys.argv) > 1 else []
    
    if "--demo" in args:
        run_demo()
    elif "--test" in args:
        success = run_tests()
        sys.exit(0 if success else 1)
    elif "--help" in args or "-h" in args:
        print(__doc__)
        return
    else:
        # Start CLI interface
        print("Welcome to CloudSim Distributed Storage System")
        print("   Engineer Moone's Distributed Systems Project")
        print("   Type 'start' to begin or 'help' for commands")
        print()
        
        cli = DistributedStorageCLI()
        try:
            cli.cmdloop()
        except KeyboardInterrupt:
            print("\nGoodbye!")
            if cli.network_started:
                cli.do_shutdown("")

if __name__ == "__main__":
    main()