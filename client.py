import socket
import threading
import functions as func
import time

# Configure the client
HOST = '127.0.0.1'  
PORT = 65432        

listening = False 
createKeys = False
createSymmetric = False
publicKeyReceived = None 

# Function to handle receiving messages from the server and other clients
def receiveMessages(sock):

    global listening, createKeys, publicKeyReceived

    while True:
        try:
            message = sock.recv(1024)
            if not message:
                print('Disconnected from the server.')
                break

            message = message.decode()

            if not listening: # When we catch something we can start creating our keys
                if message == "First":
                    createSymmetric = True
                elif message == "Ok":
                    # 1 means there's someone listening
                    # We send our public key 
                    listening = True
                    createKeys = True

            if publicKeyReceived == None: 
                if message.startswith("-----BEGIN RSA PUBLIC KEY-----"):
                    publicKeyReceived = message

            print('Message received:', message)
        except ConnectionResetError:
            print('Connection closed abruptly.')
            break


# Create a TCP/IP socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    # Connect to the server
    client.connect((HOST, PORT))

    # Start a thread for receiving messages
    receive_thread = threading.Thread(target=receiveMessages, args=(client,))
    receive_thread.start()

    # Send messages to the server
    while True:
        if not listening: 
            time.sleep(5)
            message = "Ok"
            client.sendall(message.encode())
        else: 
            if createKeys: 
                publicKey, privateKey = func.generatingAsymmetricKeys()
                message = publicKey.save_pkcs1().decode()
                client.sendall(message.encode())
                createKeys = False

            #message = input('Enter a message to send to the server (type "exit" to quit): ')
            #client.sendall(message.encode())
        
        if message.lower() == 'exit':
            break

print('Connection closed.')
