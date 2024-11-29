import socket
import threading
import ssl
import signal
import sys
import os
from flask import Flask, jsonify
from multiprocessing import Process
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

app = Flask(__name__)

# Server status storage (example for Flask)
server_status = {"connections": 0, "tasks_processed": 0}

# Flask route to monitor server status
@app.route('/status', methods=['GET'])
def status():
    return jsonify(server_status)


def run_flask():
    """Run the Flask app."""
    app.run(port=5000, debug=False, use_reloader=False)


# Encryption setup
SECRET_KEY = b'sixteen byte key'  # AES requires keys to be 16, 24, or 32 bytes long

def decrypt_data(encrypted_data):
    encrypted_bytes = base64.b64decode(encrypted_data)
    iv = encrypted_bytes[:16]
    ct = encrypted_bytes[16:]
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
    return decrypted


# Task processing function
# def handle_task(client_socket, client_address):
    global server_status
    try:
        print(f"Connection from {client_address} has been established.")
        server_status["connections"] += 1
        while True:
            # Receive encrypted data from client
            encrypted_data = client_socket.recv(1024).decode('utf-8')
            if not encrypted_data:
                print(f"Client {client_address} disconnected.")
                break

            # Decrypt the data
            try:
                task_data = decrypt_data(encrypted_data)
                print(f"Decrypted task from {client_address}: {task_data}")
            except Exception as e:
                print(f"Decryption error from {client_address}: {e}")
                break

            # Simulate task execution
            result = f"Processed: {task_data}"
            server_status["tasks_processed"] += 1

            # Send response
            client_socket.send(result.encode('utf-8'))
    except (ConnectionResetError, BrokenPipeError):
        print(f"Client {client_address} unexpectedly disconnected.")
    except Exception as e:
        print(f"Error handling task from {client_address}: {e}")
    finally:
        client_socket.close()
        print(f"Connection from {client_address} closed.")
def handle_task(client_socket, client_address):
    global server_status
    try:
        print(f"Connection from {client_address} has been established.")
        server_status["connections"] += 1
        while True:
            # Receive encrypted data from client
            encrypted_data = client_socket.recv(1024).decode('utf-8')
            if not encrypted_data:
                print(f"Client {client_address} disconnected.")
                break

            # Decrypt the data
            try:
                task_data = decrypt_data(encrypted_data)
                print(f"Decrypted task from {client_address}: {task_data}")
            except Exception as e:
                print(f"Decryption error from {client_address}: {e}")
                break

            # Simulate task execution
            if task_data.lower() == "check balance":
                result = "Balance: $500"
            elif task_data.lower().startswith("transfer"):
                result = "Transaction Successful"
            elif task_data.lower().startswith("update contact"):
                result = "Contact Information Updated"
            else:
                result = "Invalid Request"

            server_status["tasks_processed"] += 1

            # Send response
            client_socket.send(result.encode('utf-8'))
    except (ConnectionResetError, BrokenPipeError):
        print(f"Client {client_address} unexpectedly disconnected.")
    except Exception as e:
        print(f"Error handling task from {client_address}: {e}")
    finally:
        client_socket.close()
        print(f"Connection from {client_address} closed.")


# Signal handler for graceful shutdown
def signal_handler(sig, frame):
    print("Server shutting down...")
    sys.exit(0)


# Multi-threaded server setup with SSL
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 12345))  # Server listens on all interfaces at port 12345
    server_socket.listen(5)
    print("Server is listening on port 12345...")

    # Set absolute paths to the certificates
    certfile_path = os.path.join(os.getcwd(), "server.crt")
    keyfile_path = os.path.join(os.getcwd(), "server.key")

    try:
        # Wrap the server socket with SSL
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=certfile_path, keyfile=keyfile_path)
    except Exception as e:
        print(f"Failed to load certificate: {e}")
        sys.exit(1)

    while True:
        client_socket, client_address = server_socket.accept()

        # Secure the connection with SSL
        secure_socket = context.wrap_socket(client_socket, server_side=True)

        # Handle each client in a new thread
        client_thread = threading.Thread(target=handle_task, args=(secure_socket, client_address))
        client_thread.start()


if __name__ == "__main__":
    # Set up the signal handler for graceful shutdown on Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    # Start the Flask app for monitoring in a separate process
    flask_process = Process(target=run_flask)
    flask_process.start()

    # Start the main server
    start_server()
