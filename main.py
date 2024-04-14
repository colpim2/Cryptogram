# pip install flask
# pip install flask-socketio

from flask import Flask, render_template, request, session, redirect, url_for
from flask_socketio import send,SocketIO

app = Flask(__name__)
app.config["SECRET_KEY"] = "secret!"
socketio = SocketIO(app)

@app.route("/", methods=["POST","GET"])   #Post & Get data
def home():
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

@socketio.on("message")
def message(data):
    content = {
        "name": session.get("name"),
        #"message": data["data"]
    }
    #print(f"{session.get('name')} said: {data['data']}")
    print(f"{session.get('name')} said:" + data)
    socketio.emit('message', data)

# Initialize app server
if __name__ == "__main__":
  socketio.run(app,debug=True, allow_unsafe_werkzeug=True)  #True: Automatic refresh




