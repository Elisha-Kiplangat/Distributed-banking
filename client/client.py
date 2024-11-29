import asyncio
import ssl
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# Configure SSL context
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.check_hostname = False  # Skip hostname check (optional for testing)
context.verify_mode = ssl.CERT_REQUIRED  # Enforce certificate verification
context.load_verify_locations("server.crt")  # Load the server's certificate

# Encryption setup
SECRET_KEY = b'sixteen byte key'  # AES requires keys to be 16, 24, or 32 bytes long

def encrypt_data(data):
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    iv = cipher.iv
    encrypted = base64.b64encode(iv + ct_bytes).decode('utf-8')
    return encrypted

def decrypt_data(encrypted_data):
    encrypted_bytes = base64.b64decode(encrypted_data)
    iv = encrypted_bytes[:16]
    ct = encrypted_bytes[16:]
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
    return decrypted

async def client_task(client_id, tasks):
    hostname = 'localhost'
    port = 12345
    try:
        reader, writer = await asyncio.open_connection(hostname, port, ssl=context)
        print(f"Client {client_id}: SSL connection established with the server.")
        for task in tasks:
            try:
                # Encrypt and send task
                encrypted_task = encrypt_data(task)
                writer.write(encrypted_task.encode())
                await writer.drain()
                print(f"Client {client_id}: Sent task: {task}")

                # Receive and decrypt response
                encrypted_response = await asyncio.wait_for(reader.read(1024), timeout=5.0)
                decrypted_response = encrypted_response.decode('utf-8')  # No need to decrypt plain responses
                print(f"Client {client_id}: Server response: {decrypted_response}")
            except Exception as e:
                print(f"Client {client_id}: Error during task processing: {e}")
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        print(f"Client {client_id}: Connection error: {e}")

# async def main():
    # Simulate multiple clients
    num_clients = int(input("Enter number of clients to simulate: "))
    tasks_per_client = [
        [f"Task {i + 1} from Client {client_id}" for i in range(3)] for client_id in range(num_clients)
    ]

    tasks = []
    for client_id, client_tasks in enumerate(tasks_per_client, start=1):
        task = asyncio.create_task(client_task(client_id, client_tasks))
        tasks.append(task)

    await asyncio.gather(*tasks)
async def main():
    # Simulate multiple clients
    num_clients = int(input("Enter number of clients to simulate: "))
    tasks_per_client = [
        [
            "Check Balance",
            "Transfer $100 to Account XYZ",
            "Update Contact Information"
        ]
        for client_id in range(num_clients)
    ]

    tasks = []
    for client_id, client_tasks in enumerate(tasks_per_client, start=1):
        task = asyncio.create_task(client_task(client_id, client_tasks))
        tasks.append(task)

    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())
