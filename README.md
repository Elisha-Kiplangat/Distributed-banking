# Secure Banking Transaction Simulation

## Problem Statement

In the modern banking ecosystem, secure communication between clients (users) and servers (banks) is critical. This project aims to simulate a secure banking system where clients send encrypted requests (e.g., checking account balance, transferring funds) to a server. The server processes these requests and responds securely. Key requirements include:

- **Encryption**: Client-server communication must be encrypted to protect sensitive data.
- **Scalability**: The system should handle multiple clients simultaneously.
- **Real-Time Processing**: Requests must be processed promptly, and appropriate responses should be sent.
- **Monitoring**: The system should allow monitoring of server performance (e.g., number of connections and tasks processed).

## System Architecture and Design

### System Architecture

- **Client**: Represents banking users. Encrypts requests using AES encryption and communicates with the server over an SSL/TLS connection.
- **Server**: Acts as the backend for processing client requests. Decrypts incoming requests, processes them, and sends responses back to the client. Uses multi-threading to handle multiple clients.
- **Flask Monitoring**: Provides a REST API to monitor server performance metrics like active connections and tasks processed.

### System Workflow

1. **Secure Connection**: Clients establish an SSL/TLS connection with the server.
2. **Data Encryption**: Clients encrypt banking requests using AES encryption before sending.
3. **Request Handling**:
    - The server decrypts client requests.
    - Processes tasks like checking balance, transferring money, or updating contact information.
    - Sends appropriate responses back to clients.
4. **Real-Time Monitoring**: Flask app provides server statistics.

## Python Code Explanations

### Server Code

Key functionalities:

- **Secure Socket Initialization**:
  - Wraps the server socket with SSL for secure communication.
  - Uses certificates (server.crt and server.key).
- **Task Handling**:
  - Each client request is handled in a separate thread.
  - Tasks include:
     - "Check Balance": Responds with a simulated balance.
     - "Transfer $100 to Account XYZ": Simulates a successful transaction.
     - "Update Contact Information": Confirms contact update.
- **Flask Monitoring**:
  - Provides server status through a REST API.

#### Code snippet:

```python
def handle_task(client_socket, client_address):
     try:
          print(f"Connection from {client_address} has been established.")
          while True:
                # Receive encrypted data
                encrypted_data = client_socket.recv(1024).decode('utf-8')
                if not encrypted_data:
                     break
                
                # Decrypt request and process
                task_data = decrypt_data(encrypted_data)
                print(f"Task from {client_address}: {task_data}")
                
                # Simulate processing
                if task_data == "Check Balance":
                     result = "Balance: $500"
                elif task_data.startswith("Transfer"):
                     result = "Transaction Successful"
                elif task_data.startswith("Update Contact"):
                     result = "Contact Information Updated"
                else:
                     result = "Invalid Request"
                
                # Send response
                client_socket.send(result.encode('utf-8'))
     finally:
          client_socket.close()
          print(f"Connection from {client_address} closed.")
```

### Client Code

Key functionalities:

- **SSL Connection**:
  - Establishes a secure connection with the server using the certificate (server.crt).
- **AES Encryption**:
  - Encrypts banking tasks using AES with a pre-shared key.
- **Task Simulation**:
  - Simulates user actions like checking balance, transferring funds, and updating contact information.

#### Code snippet:

```python
async def client_task(client_id, tasks):
     try:
          # Establish SSL connection
          reader, writer = await asyncio.open_connection('localhost', 12345, ssl=context)
          print(f"Client {client_id}: Connected.")
          
          for task in tasks:
                # Encrypt and send task
                encrypted_task = encrypt_data(task)
                writer.write(encrypted_task.encode())
                await writer.drain()
                print(f"Client {client_id}: Sent task: {task}")
                
                # Receive and display server response
                response = await reader.read(1024)
                print(f"Client {client_id}: Server response: {response.decode()}")
          writer.close()
          await writer.wait_closed()
     except Exception as e:
          print(f"Client {client_id}: Error: {e}")
```

## Test Cases and Results

### Test Case 1: Single Client

**Input**:
Tasks:
- "Check Balance"
- "Transfer $100 to Account XYZ"
- "Update Contact Information"

**Expected Output**:
- "Balance: $500"
- "Transaction Successful"
- "Contact Information Updated"

**Result**:

```plaintext
Client 1: Sent task: Check Balance
Client 1: Server response: Balance: $500
Client 1: Sent task: Transfer $100 to Account XYZ
Client 1: Server response: Transaction Successful
Client 1: Sent task: Update Contact Information
Client 1: Server response: Contact Information Updated
```

### Test Case 2: Multiple Clients

**Input**:
3 Clients, each with the same tasks as above.

**Expected Output**:
All clients should receive appropriate responses without delay.

**Result**:
All clients successfully completed tasks concurrently.

### Test Case 3: Invalid Request

**Input**:
Task: "Invalid Task"

**Expected Output**:
"Invalid Request"

**Result**:

```plaintext
Client 1: Sent task: Invalid Task
Client 1: Server response: Invalid Request
```

### Test Case 4: Server Monitoring

**Input**:
Flask monitoring API endpoint: `http://localhost:5000/status`

**Expected Output**:
JSON response with current server status.

**Result**:

```json
{
  "connections": 3,
  "tasks_processed": 9
}
```

## Conclusion

This project demonstrates the secure and scalable handling of client-server communication using Python. The system handles encrypted requests, processes tasks efficiently, and provides real-time monitoring, making it suitable for applications like banking, e-commerce, and other sensitive operations.

Enhancements such as database integration, GUI development, and additional encryption layers can further extend its functionality.