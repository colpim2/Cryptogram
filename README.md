# Cryptogram
First Project  “Secure Communication Protocol Implementation”  Cryptography 2024-2

## Table of Contents

0. [Authors](#authors)
1. [Requirements](#requirements)
2. [Download Project](#download-project)
3. [Execution](#execution)
4. [Video](#video)

## 0. Authors <a name="authors"></a>

- Andres Urbano Andrea
- Aguilar Corona Fernanda
- Barrios López Francisco
- Castillo Montes Pamela
- Ramirez Gómez Maria Emilia

## 1. Requirements <a name="requirements"></a>

- Must use Python 3.6 or above.
- Libraries used:
  - `pip install pycryptodome`
  - `pip install flask`
  - `pip install flask-socketio`

## 2. Download Project <a name="download-project"></a>

- Run the following command in a command line:

```bash
git clone https://github.com/colpim2/Cryptogram
```

## 3. Execution <a name="execution"></a>
### Web Interface Version 

- Run the following commands in the terminal:

```bash
python main_global.py
python main_global_B.py
```

**Note:** Both programs must be running simultaneously.

- Open your browser and connect as follows:
  - Connect User 1 to [http://127.0.0.1:5000](http://127.0.0.1:5000)
  - Connect User 2 to [http://127.0.0.1:5000](http://127.0.0.1:5000)
 
### Command-Line Interface (CLI) Version 
- Run the following commands on different terminals in the following order:

```bash
python server.py
```

```bash
python client.py
```

```bash
python client.py
```
The command-line interface (CLI) will prompt for a password. This will be used to generate the asymmetric key and create the key to encrypt the private key, which will then be stored in a file on our computer.

## 4. Video <a name="video"></a>

[Google Drive](https://drive.google.com/file/d/1yd7FLt54SdV4cJm7lVE69lV93GwPRGA-/view?usp=sharing)
