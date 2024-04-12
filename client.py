import socket
import threading
import functions as func
import time
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Configure the client
HOST = '127.0.0.1'  
PORT = 65431     

listening = False 
createKeys = False
createSymmetric = False
publicKeyReceived = False 
symmetricKey = None

# Function to handle receiving messages from the server and other clients
def receiveMessages(sock):

    global listening, createKeys, publicKeyReceived, createSymmetric, symmetricKey, privateKey

    while True:
        try:
            message = sock.recv(1024)
            if not message:
                print('Disconnected from the server.')
                break

            if not listening: # When we catch something we can start creating our keys
                if message == b"First":
                    createSymmetric = True

                elif message == b"Ok":
                    # 1 means there's someone listening
                    # We send our public key 
                    listening = True
                    createKeys = True

            if not publicKeyReceived: 
                if message.startswith(b"-----BEGIN PUBLIC KEY-----"):
                    publicKeyReceived = RSA.import_key(message)
                    
            if not createSymmetric and symmetricKey is None: 
                if message.startswith(b"SymmetricKey:"):
                    encryptedSymmetricKey = message.split(b"SymmetricKey:", 1)[1]
                    encryptedSymmetricKey = base64.b64decode(encryptedSymmetricKey)
                    
                    symmetricKey = func.decryptMessage(privateKey,encryptedSymmetricKey )
         
                    print(symmetricKey)

            print('Message received:', message.decode('utf-8', 'ignore'))
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

    
    while True:
        # Send messages to the server until we get an Ok from another client. 
        if not listening: 
            time.sleep(5)
            message = "Ok"
            client.sendall(message.encode())
        else: 
            

            if createKeys: 
                publicKey, privateKey = func.generatingAsymmetricKeys()

                client.sendall(publicKey)
                createKeys = False

            if createSymmetric: 
                if isinstance(publicKeyReceived, RSA.RsaKey):
                    password = input("Enter the password: ")
                    symmetricKey = func.symmetricKeys_PBKDF(password)

                    print(symmetricKey)

                    encryptedKey = func.encryptMessage(publicKeyReceived, symmetricKey)
                    
                    # Convertir la clave simétrica cifrada a base64 para facilitar su envío
                    encryptedKey = base64.b64encode(encryptedKey)
                    encryptedKey = b"SymmetricKey:" + encryptedKey
                    client.sendall(encryptedKey)
                    createSymmetric = False

            #message = input('Enter a message to send to the server (type "exit" to quit): ')
            #client.sendall(message.encode())
        
        if message.lower() == 'exit':
            break

print('Connection closed.')
