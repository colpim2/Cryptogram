import socket
import threading

# Andres Urbano Andrea  & 315133431 \\
# Aguilar Corona Fernanda & 317018549 \\
# Barrios López Francisco & 317165935 \\
# Castillo Montes Pamela & 317165935 \\
# Ramirez Gómez Maria Emilia & 317341612 \\

# Configure the server
HOST = '127.0.0.1'  # Local IP address
PORT = 65431        # Port to listen for connections

connected_clients = []
max_connections = 2  # Maximum concurrent connections
first_client = None

def handle_client(client, address):
    global first_client

    if first_client is None:
        first_client = client
        first_client.sendall(b"First")

    while True:
        try:
            message = client.recv(1024)
            if not message:
                print(f'[INFO] Client {address} disconnected.')
                connected_clients.remove(client)
                break
            #decoded_message = message.decode()
            print(f'Message received from {address}: {message}')
            # Forward the message to all connected clients except the sender
            for connected_client in connected_clients:
                if connected_client != client:
                    connected_client.sendall(message)
        except ConnectionResetError:
            print(f'[ERROR] Client {address} disconnected abruptly.')
            connected_clients.remove(client)
            break

# Create a TCP/IP socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    # Bind the socket to the specified port and address
    server.bind((HOST, PORT))
    # Listen for incoming connections (maximum 2 pending connections)
    server.listen(max_connections)

    print('Server listening on:', (HOST, PORT))

    while True:
        # Wait for a connection to arrive
        print('Waiting for connection...')
        connection, address = server.accept()
        if len(connected_clients) >= max_connections:
            print('Maximum number of connections reached. Rejecting new connection.')
            connection.close()
        else:
            print('Connected to:', address)
            connected_clients.append(connection)

            # Start a new thread to handle the client
            client_thread = threading.Thread(target=handle_client, args=(connection, address))
            client_thread.start()
