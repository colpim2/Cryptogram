# pip install flask
# pip install flask-socketio

from flask import Flask, render_template, request, session, redirect, url_for
# Libraries for exchange of information
from flask_socketio import send,SocketIO,emit
import socket
import socketio
# Cryptography functions
import base64
import functions as func
import sys
from Cryptodome.PublicKey import RSA

# server_ip = sys.argv[1]
# server_port = sys.argv[2]
# target_ip = sys.argv[3]
# server_port = sys.argv[4]

share_symmetric_pass = False
sent_key = False

password = None

keys = {
        "publicReceived" : None, 
        "symmetric" : None,
        "public" : None, 
        "private" : None,
        "key": None # Used to saved the key gave for RSA, to export the cipher private key using the user´s password and saved it into a file
    }

sio = socketio.Client()
# sio.connect('http://127.0.0.1:5000')
conection = False

app = Flask(__name__)
app.config["SECRET_KEY"] = "secret!"
socketio = SocketIO(app)

def sendPublicKey(publicKey):
    """Function that sends the public key generated"""
    global conection
    global sent_key
    while sent_key == False:
        try:
            if conection == False:
                sio.connect('http://127.0.0.1:5000')
                conection = True
                print("Conexion establecida")
                sio.emit('public_key',publicKey)
                print("Llave publica enviada")
                sent_key = True
            else:
                sio.emit('public_key',publicKey)
                print("Llave pública enviada con conexion ya establecida")
                sent_key = True
        except Exception as e:
            print("Error")
            print(e)

def sendSymmetricKey(symmetrickKey):
    """Function that sends the encrypted symmetric key"""
    global conection
    try:
        if conection == False:
            conection = True
            sio.connect('http://192.168.94.127:5000')
            print("Conexion establecida")
        sio.emit('symmetrick_key',symmetrickKey)
    except Exception as e:
        print("Error")
        print(e)

@app.route("/", methods=["POST","GET"])   #Post & Get data
def home():
    """First function that show the login page to the users, generate the RSA keys and send the public key, takes a password and
    generated a key based on the password, and send it"""
    global password
    global keys

    # Generate asymmetric keys
    keys["public"], keys["private"], keys["key"] = func.generatingAsymmetricKeys()
    print("Llave privada: " + str(type(keys["private"])))
    print(keys["private"])
    func.saveCipherPrivateKey(keys["key"], password, 'private_key_encrypted_B.pem')
    sendPublicKey(keys["public"])

    session.clear()
    # If there is a request (insert password)
    if request.method == "POST":
        name = request.form.get("name")
        password = request.form.get("password")
        join = request.form.get("join")

        if not name:
            return render_template("home.html", error="Please enter a name.", password=password, name=name)

        if join != False and not password:
            return render_template("home.html", error="Please enter a password", password=password, name=name)
        
        if share_symmetric_pass == True:
            # Generate symmetric key based on a password
            keys["symmetric"] = func.symmetricKeys_PBKDF(password)
            while keys["publicReceived"] is None:
                continue

            encryptedKey = func.encryptMessage(RSA.import_key(keys["publicReceived"]), keys["symmetric"])
            encryptedKey = base64.b64encode(encryptedKey)
            sendSymmetricKey(encryptedKey)

        return redirect(url_for("chat"))

    return render_template("home.html")

@app.route("/chat")
def chat():
    password = session.get("password")
    return render_template("chat.html")

@socketio.on("connect")
def connect(auth):
    name = session.get("name")
    print(f"{name} joined")

@socketio.on("disconnect")
def disconnect():
    name = session.get("name")
    print(f"{name} has left")

@socketio.on("public_key")
def receivePublicKey(data_PK):
    """Function that receives a Public Key"""
    keys["publicReceived"] = data_PK
    print("Llave pública recibida")
    print(data_PK)

@socketio.on("symmetrick_key")
def receiveSymmetricKey(data_SK):
    """Function that receives the encrypted symmetric Key"""
    print("Llave simetrica recibida" + str(type(data_SK)))
    print(data_SK)
    encryptedSymmetricKey = data_SK.split(b"SymmetricKey:", 1)[1]
    print(encryptedSymmetricKey)
    encryptedSymmetricKey = base64.b64decode(encryptedSymmetricKey)
    print(encryptedSymmetricKey)
    keys["symmetric"] = func.decryptMessage(keys["private"], encryptedSymmetricKey)

@socketio.on("message")
def receiveMessageFromWeb(data):
    """Functions that receives the messages from the web page and encrypts it using the symmetric key"""
    # print(f"{session.get('name')} said:" + data)
    message = func.encryptMessageAES(keys["symmetric"], data)
    signature = func.signMessage(message, keys["private"])
    signature = base64.b64encode(signature)

    sendMessage(message+b"<delimiter>"+signature)
    socketio.emit('message', data)

@socketio.on("inter_message")
def receiveEncryptedMessage(data):
    """Functiont that receives a message from other host and decrypts it to send it to the web page"""
    # print(f"{session.get('name')} said:" + data)
    message, signature = data.split(b"<delimiter>")
    signature = base64.b64decode(signature)
    
    if func.verifySignature(message, signature, keys["publicReceived"]):
        message = func.decryptMessageAES(keys["symmetric"], message)
        message = message.decode()
        # print('\nVerified message received:', message)
        socketio.emit('message', message)
    else: 
        # print('\nThe message has been corrupted.')
        socketio.emit('message', "The message has been corrupted.")

def sendMessage(message):
    """Function that sends a message to the other host"""
    global conection
    try:
        if conection == False:
            conection = True
            sio.connect('http://127.0.0.1:5000')
            print("Conexion establecida")
        sio.emit('inter_message',message)
    except Exception as e:
        print("Error")
        print(e)

# Initialize app server
if __name__ == "__main__":
    # socketio.run(app, host='192.168.94.130', port=5000, debug=True, allow_unsafe_werkzeug=True)  #True: Automatic refresh
    socketio.run(app, host='127.0.0.1', port=5001, debug=True, allow_unsafe_werkzeug=True)  #True: Automatic refresh

# python3 main.py '192.168.94.130' '5000' '192.168.94.139' '5001'