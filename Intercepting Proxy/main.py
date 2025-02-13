import socket
import threading
import ssl
import requests
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import BytesIO

# Path to your self-signed certificate and key
CERT_PATH = 'proxy_cert.pem'
KEY_PATH = 'proxy_key.pem'

# Function to handle HTTP/HTTPS requests and responses
def handle_client(client_socket):
    try:
        # Wrap the socket for SSL/TLS interception (MITM)
        ssl_socket = ssl.wrap_socket(client_socket, keyfile=KEY_PATH, certfile=CERT_PATH, server_side=True)

        # Receive the initial request (client's HTTP/HTTPS request)
        request = ssl_socket.recv(1024)
        print(f"Request: {request.decode('utf-8', errors='ignore')}")  # Print the intercepted request

        # Forward the request to the target server (example.com)
        # In real-world use, this would be dynamic based on the host.
        url = "http://example.com"  # Replace with dynamic target or extract host from request
        response = requests.post(url, data=request)  # Sending to the server

        print(f"Response from target: {response.status_code}")

        # Send the server's response back to the client (browser)
        ssl_socket.send(response.content)
        ssl_socket.close()

    except Exception as e:
        print(f"Error handling client: {e}")
        ssl_socket.close()

# Function to create the server and accept client connections
def start_proxy(server_ip, server_port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((server_ip, server_port))
    server.listen(5)
    print(f"[*] Listening on {server_ip}:{server_port}")

    while True:
        client_socket, addr = server.accept()
        print(f"[*] Connection from {addr}")

        # Create a new thread to handle each client connection
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

# Start the proxy server
if __name__ == "__main__":
    target_ip = "127.0.0.1"  # Local IP for proxy
    target_port = 8080        # Port to listen on for proxy (HTTP or HTTPS traffic)
    start_proxy(target_ip, target_port)
