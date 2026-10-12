from websockets.sync import \
    client as ws              # same as xray's ws  transport
import socket                 # same as xray's TCP transport
from asyncio_socks_server import Flow
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class BADCONFIG(Exception): pass

def isinobj(vars, data): 
    for v in vars: 
        if v not in list(data): return False
    return True

def check_client_config(data: dict):
    try:
        if not isinobj(("server", "obfuscation", "security", "user"), data): raise BADCONFIG()
        if not isinobj(("host", "port"), data["server"]): raise BADCONFIG()
        if not type(data["server"]["host"]) is str: raise BADCONFIG()
        if not type(data["server"]["port"]) is int: raise BADCONFIG()
        if not (0 < data["server"]["port"] < 65536): raise BADCONFIG()
        if data["obfuscation"] is not None:
            if not isinobj(("transport", "padding", "data", "tu-data", "padding-data", "extra"), data["obfuscation"]): raise BADCONFIG()
            if data["obfuscation"]["transport"] not in ("http", "http-real", "ws", "grpc"): raise BADCONFIG()
            if data["obfuscation"]["padding"] is not None:
                if not isinobj(("min", "max"), data["obfuscation"]["padding"]): raise BADCONFIG()
                if not type(data["obfuscation"]["padding"]["min"]) is int: raise BADCONFIG()
                if not type(data["obfuscation"]["padding"]["max"]) is int: raise BADCONFIG()
                if not (data["obfuscation"]["padding"]["min"] < data["obfuscation"]["padding"]["max"]): raise BADCONFIG()
                if not (data["obfuscation"]["padding"]["min"] >= 0): raise BADCONFIG()
                if not (data["obfuscation"]["padding"]["max"] >= 0): raise BADCONFIG()
            if not isinobj(("position", "name", "encrypt"), data["obfuscation"]["data"]): raise BADCONFIG()
            if data["obfuscation"]["data"]["position"] not in ("body", "header"): raise BADCONFIG()
            if type(data["obfuscation"]["data"]["name"]) is not str: raise BADCONFIG()
            if data["obfuscation"]["data"]["encrypt"] not in (True, False): raise BADCONFIG()
            if not isinobj(("position", "name", "encrypt"), data["obfuscation"]["data"]): raise BADCONFIG()
            if data["obfuscation"]["tu-data"]["position"] not in ("body", "header"): raise BADCONFIG()
            if type(data["obfuscation"]["tu-data"]["name"]) is not str: raise BADCONFIG()
            if data["obfuscation"]["tu-data"]["encrypt"] not in (True, False): raise BADCONFIG()
            if not isinobj(("position", "name", "encrypt"), data["obfuscation"]["padding-data"]): raise BADCONFIG()
            if data["obfuscation"]["padding-data"]["position"] not in ("body", "header"): raise BADCONFIG()
            if type(data["obfuscation"]["padding-data"]["name"]) is not str: raise BADCONFIG()
            if data["obfuscation"]["padding-data"]["encrypt"] not in (True, False): raise BADCONFIG()
            if data["obfuscation"]["transport"] in ("http", "http-real"):
                if not isinobj(("method",), data["obfuscation"]["extra"]): raise BADCONFIG()
                if data["obfuscation"]["extra"]["method"] not in ("post", "get", "delete", "put"): raise BADCONFIG()
        if data["security"] not in (None, "aes256"): raise BADCONFIG()
        if not isinobj(("token", "key"), data["user"]): raise BADCONFIG()
        if not type(data["user"]["token"]) is str: raise BADCONFIG()
        if not type(data["user"]["key"]) is str: raise BADCONFIG()
    except: raise BADCONFIG()
    return 0

def check_server_config(data: dict):
    try:
        if not isinobj(("listen", "obfuscation", "security", "clients"), data): raise BADCONFIG()
        if not isinobj(("host", "port"), data["listen"]): raise BADCONFIG()
        if not type(data["listen"]["host"]) is str: raise BADCONFIG()
        if not type(data["listen"]["port"]) is int: raise BADCONFIG()
        if not (0 < data["listen"]["port"] < 65536): raise BADCONFIG()
        if data["obfuscation"] is not None:
            if not isinobj(("transport", "padding", "data", "tu-data", "padding-data", "extra"), data["obfuscation"]): raise BADCONFIG()
            if data["obfuscation"]["transport"] not in ("http", "http-real", "ws", "grpc"): raise BADCONFIG()
            if data["obfuscation"]["padding"] is not None:
                if not isinobj(("min", "max"), data["obfuscation"]["padding"]): raise BADCONFIG()
                if not type(data["obfuscation"]["padding"]["min"]) is int: raise BADCONFIG()
                if not type(data["obfuscation"]["padding"]["max"]) is int: raise BADCONFIG()
                if not (data["obfuscation"]["padding"]["min"] < data["obfuscation"]["padding"]["max"]): raise BADCONFIG()
                if not (data["obfuscation"]["padding"]["min"] >= 0): raise BADCONFIG()
                if not (data["obfuscation"]["padding"]["max"] >= 0): raise BADCONFIG()
            if not isinobj(("position", "name", "encrypt"), data["obfuscation"]["data"]): raise BADCONFIG()
            if data["obfuscation"]["data"]["position"] not in ("body", "header"): raise BADCONFIG()
            if type(data["obfuscation"]["data"]["name"]) is not str: raise BADCONFIG()
            if data["obfuscation"]["data"]["encrypt"] not in (True, False): raise BADCONFIG()
            if not isinobj(("position", "name", "encrypt"), data["obfuscation"]["data"]): raise BADCONFIG()
            if data["obfuscation"]["tu-data"]["position"] not in ("body", "header"): raise BADCONFIG()
            if type(data["obfuscation"]["tu-data"]["name"]) is not str: raise BADCONFIG()
            if data["obfuscation"]["tu-data"]["encrypt"] not in (True, False): raise BADCONFIG()
            if not isinobj(("position", "name", "encrypt"), data["obfuscation"]["padding-data"]): raise BADCONFIG()
            if data["obfuscation"]["padding-data"]["position"] not in ("body", "header"): raise BADCONFIG()
            if type(data["obfuscation"]["padding-data"]["name"]) is not str: raise BADCONFIG()
            if data["obfuscation"]["padding-data"]["encrypt"] not in (True, False): raise BADCONFIG()
            if data["obfuscation"]["transport"] in ("http", "http-real"):
                if not isinobj(("method",), data["obfuscation"]["extra"]): raise BADCONFIG()
                if data["obfuscation"]["extra"]["method"] not in ("post", "get", "delete", "put"): raise BADCONFIG()
        if data["security"] not in (None, "aes256"): raise BADCONFIG()
        for client in data["clients"]:
            if not isinobj(("token", "key"), data["clients"][client]): raise BADCONFIG()
            if not type(data["clients"][client]["token"]) is str: raise BADCONFIG()
            if not type(data["clients"][client]["key"]) is str: raise BADCONFIG()
    except: raise BADCONFIG()
    return 0

def suggest_transport(config):
    transport = "tcp"
    if check_client_config(config) != 0:
        raise BADCONFIG()
    if config["obfuscation"] is None: return transport
    return config["obfuscation"]["transport"]

def secure_data(config: dict, data: bytes):
    match config["security"]:
        case "aes256":
            aes = AESGCM(config["user"]["key"])
            nonce = os.urandom(12)
            ciphertext = aes.encrypt(
                nonce,
                data,
                None
            )
            return nonce + ciphertext
        case _:
            return data

def connect(to, transport):
    match transport:
        case "tcp" | "http": 
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(to)
            s.sendall("healthz".encode())
            if s.recv().decode() == "ok":
                s.setblocking(False)
                return "success", s
            else: raise RuntimeError("server anwered incorrecly")
        case "ws":
            s = ws.connect(f"ws://{to[0]}:{to[1]}")
            s.send("healthz")
            if s.recv().decode() == "ok":
                return "success", s
            else: raise RuntimeError("server anwered incorrecly")

def disconnect(s: socket.socket | ws.ClientConnection, transport):
    s.close()

def send_data(config: dict, s: socket.socket | ws.ClientConnection, flow: Flow):
    to = (flow.dst.host, flow.dst.port)
    transport = suggest_transport(config)
    match transport:
        case "tcp" | "http": 
            pass
        case "ws":
            pass