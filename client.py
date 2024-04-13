import socket
import threading
import functions as func
import time
import base64
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

# Configure the client
HOST = '127.0.0.1'  
PORT = 65431     
cliente = {"A" : False, "B": False}

# Function to handle receiving messages from the server and other clients
def receiveInitMessages(sock, flags, keys):

    while flags["iniProtocol"]:
        try:
            message = sock.recv(1024)
            if not message:
                print('Disconnected from the server.')
                break

            if message == b"First":
                flags["createSymmetric"] = True
                cliente["A"] = True

            elif message == b"Ok" and not flags["listening"]:
                cliente["B"] = True
                flags["listening"] = True
                flags["createKeys"] = True

            elif keys["publicReceived"] is None and message.startswith(b"-----BEGIN PUBLIC KEY-----"):
                keys["publicReceived"] = RSA.import_key(message)
                    
            elif not flags["createSymmetric"] and keys["symmetric"] is None and message.startswith(b"SymmetricKey:"):
                    encryptedSymmetricKey = message.split(b"SymmetricKey:", 1)[1]
                    encryptedSymmetricKey = base64.b64decode(encryptedSymmetricKey)
                    
                    keys["symmetric"] = func.decryptMessage(keys["private"],encryptedSymmetricKey )

                    print(keys["symmetric"])

                    flags["iniProtocol"] = False
                    sock.sendall(b"got it")

            print('Message received:', message.decode('utf-8', 'ignore'))

        except ConnectionResetError:
            print('Connection closed abruptly.')
            break

def receiveMessages(sock, keys):

    while True:
        try:
            message = sock.recv(1024)
            if not message:
                print('Disconnected from the server.')
                break

            message = func.decryptMessageAES(keys["symmetric"], message)
            message = message.decode()
            print('\nMessage received:', message)

        except ConnectionResetError:
            print('Connection closed abruptly.')
            break

def main():

    flags = {
        "listening" : False, 
        "createKeys" : False,
        "createSymmetric" : False, 
        "iniProtocol" : True
    }

    keys = {
        "publicReceived" : None, 
        "symmetric" : None,
        "public" : None, 
        "private" : None,
        "key": None # Used to saved the key gave for RSA, to export the cipher private key using the user´s password and saved it into a file
    }


    # Create a TCP/IP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        # Connect to the server
        client.connect((HOST, PORT))

        # Start a thread for receiving init messages
        receive_thread = threading.Thread(target=receiveInitMessages, args=(client, flags, keys))
        receive_thread.start()

        while not flags["listening"]:
            # Send messages to the server until we get an Ok from another client. 
            time.sleep(5)
            message = "Ok"
            client.sendall(message.encode())

        if flags["createKeys"]: 
            keys["public"], keys["private"], keys["key"] = func.generatingAsymmetricKeys()
            client.sendall(keys["public"])
            flags["createKeys"] = False

        while flags["createSymmetric"]: 
            if isinstance(keys["publicReceived"], RSA.RsaKey):
                password = input("Enter the password: ")
                keys["symmetric"] = func.symmetricKeys_PBKDF(password)
                try:
                    if cliente["A"] == True:
                        func.saveCipherPrivateKey(keys["key"], password, 'private_key_encrypted_A.pem')
                    else:  
                        func.saveCipherPrivateKey(keys["key"], password, 'private_key_encrypted_B.pem')
                except Exception as e:
                    print("Something was wrong saving the private key")

                print(keys["symmetric"])

                encryptedKey = func.encryptMessage(keys["publicReceived"], keys["symmetric"])
                encryptedKey = base64.b64encode(encryptedKey)
                encryptedKey = b"SymmetricKey:" + encryptedKey

                client.sendall(encryptedKey)
                flags["iniProtocol"] = False
                flags["createSymmetric"] = False
                
        
        receive_thread.join()

        receive_thread = threading.Thread(target=receiveMessages, args=(client, keys))
        receive_thread.start()

        while True: 
            message = input('Enter a message to send to the server (type "exit" to quit): ')
        
            if message.lower() == 'exit':
                break
            else: 
                message = func.encryptMessageAES(keys["symmetric"], message)
                client.sendall(message)


main()
