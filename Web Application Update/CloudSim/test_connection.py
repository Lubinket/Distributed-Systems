import socket
import time

def test_connection():
    """Test basic TCP connection between two ports"""
    # Start server on port 8001
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('127.0.0.1', 8001))
    server_socket.listen(1)
    print("Server listening on 127.0.0.1:8001")
    
    # Connect client to server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect(('127.0.0.1', 8001))
        print("Client connected to server")
        
        # Send test message
        message = b"Hello Server!"
        client_socket.send(message)
        print(f"Client sent: {message}")
        
        # Accept connection on server
        conn, addr = server_socket.accept()
        print(f"Server accepted connection from {addr}")
        
        # Receive message on server
        data = conn.recv(1024)
        print(f"Server received: {data}")
        
        # Send response
        response = b"Hello Client!"
        conn.send(response)
        print(f"Server sent: {response}")
        
        # Receive response on client
        data = client_socket.recv(1024)
        print(f"Client received: {data}")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()
        conn.close()
        server_socket.close()
        print("Connections closed")

if __name__ == "__main__":
    test_connection()
