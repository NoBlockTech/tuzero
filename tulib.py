from websockets.sync import \
    client as ws              # same as xray's ws  transport
import socket                 # same as xray's TCP transport
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, random
import h11
import json
import base64

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
            if not isinobj(("transport", "padding", "data", "tu-data", "extra"), data["obfuscation"]): raise BADCONFIG()
            if data["obfuscation"]["transport"] not in ("http", "ws"): raise BADCONFIG()
            if data["obfuscation"]["padding"] is not None:
                if not isinobj(("min", "max"), data["obfuscation"]["padding"]): raise BADCONFIG()
                if not type(data["obfuscation"]["padding"]["min"]) is int: raise BADCONFIG()
                if not type(data["obfuscation"]["padding"]["max"]) is int: raise BADCONFIG()
                if not (data["obfuscation"]["padding"]["min"] <= data["obfuscation"]["padding"]["max"]): raise BADCONFIG()
                if not (data["obfuscation"]["padding"]["min"] >= 0): raise BADCONFIG()
                if not (data["obfuscation"]["padding"]["max"] >= 0): raise BADCONFIG()
            if data["obfuscation"]["transport"] == "http":
                if not isinobj(("position", "name", "encrypt"), data["obfuscation"]["data"]): raise BADCONFIG()
                if data["obfuscation"]["data"]["position"] not in ("body", "header"): raise BADCONFIG()
                if type(data["obfuscation"]["data"]["name"]) is not str: raise BADCONFIG()
                if data["obfuscation"]["data"]["encrypt"] not in (True, False): raise BADCONFIG()
                if not isinobj(("position", "name", "encrypt"), data["obfuscation"]["data"]): raise BADCONFIG()
                if data["obfuscation"]["tu-data"]["position"] not in ("body", "header"): raise BADCONFIG()
                if type(data["obfuscation"]["tu-data"]["name"]) is not str: raise BADCONFIG()
                if data["obfuscation"]["tu-data"]["encrypt"] not in (True, False): raise BADCONFIG()
                if data["obfuscation"]["transport"] in ("http"):
                    if not isinobj(("method",), data["obfuscation"]["extra"]): raise BADCONFIG()
                    if data["obfuscation"]["extra"]["method"] not in ("post", "get", "head", "delete", "put"): raise BADCONFIG()
        if data["security"] not in (None, "aes256"): raise BADCONFIG()
        if not isinobj(("token", "key"), data["user"]): raise BADCONFIG()
        if not type(data["user"]["token"]) is str: raise BADCONFIG()
        if not type(data["user"]["key"]) is str: raise BADCONFIG()
    except: raise BADCONFIG()
    return 0

def check_server_config(data: dict):
        if not isinobj(("listen", "obfuscation", "security", "user"), data): raise BADCONFIG()
        if not isinobj(("host", "port"), data["listen"]): raise BADCONFIG()
        if not type(data["listen"]["host"]) is str: raise BADCONFIG()
        if not type(data["listen"]["port"]) is int: raise BADCONFIG()
        if not (0 < data["listen"]["port"] < 65536): raise BADCONFIG()
        if data["obfuscation"] is not None:
            if not isinobj(("transport", "padding", "data", "tu-data", "extra"), data["obfuscation"]): raise BADCONFIG()
            if data["obfuscation"]["transport"] not in ("http", "ws"): raise BADCONFIG()
            if data["obfuscation"]["padding"] is not None:
                if not isinobj(("min", "max"), data["obfuscation"]["padding"]): raise BADCONFIG()
                if not type(data["obfuscation"]["padding"]["min"]) is int: raise BADCONFIG()
                if not type(data["obfuscation"]["padding"]["max"]) is int: raise BADCONFIG()
                if not (data["obfuscation"]["padding"]["min"] <= data["obfuscation"]["padding"]["max"]): raise BADCONFIG()
                if not (data["obfuscation"]["padding"]["min"] >= 0): raise BADCONFIG()
                if not (data["obfuscation"]["padding"]["max"] >= 0): raise BADCONFIG()
            if data["obfuscation"]["transport"] == "http":
                if not isinobj(("position", "name", "encrypt"), data["obfuscation"]["data"]): raise BADCONFIG()
                if data["obfuscation"]["data"]["position"] not in ("body", "header"): raise BADCONFIG()
                if type(data["obfuscation"]["data"]["name"]) is not str: raise BADCONFIG()
                if data["obfuscation"]["data"]["encrypt"] not in (True, False): raise BADCONFIG()
                if not isinobj(("position", "name", "encrypt"), data["obfuscation"]["data"]): raise BADCONFIG()
                if data["obfuscation"]["tu-data"]["position"] not in ("body", "header"): raise BADCONFIG()
                if type(data["obfuscation"]["tu-data"]["name"]) is not str: raise BADCONFIG()
                if data["obfuscation"]["tu-data"]["encrypt"] not in (True, False): raise BADCONFIG()
                if data["obfuscation"]["transport"] in ("http"):
                    if not isinobj(("method",), data["obfuscation"]["extra"]): raise BADCONFIG()
                    if data["obfuscation"]["extra"]["method"] not in ("post", "get", "head", "delete", "put"): raise BADCONFIG()
        if data["security"] not in (None, "aes256"): raise BADCONFIG()
        if not isinobj(("token", "key"), data["user"]): raise BADCONFIG()
        if not type(data["user"]["token"]) is str: raise BADCONFIG()
        if not type(data["user"]["key"]) is str: raise BADCONFIG()
    
        return 0

def suggest_transport(config):
    transport = "tcp"
    if config["obfuscation"] is None: return transport
    return config["obfuscation"]["transport"]

def secure_data(config: dict, data: bytes):
    if isinstance(data, str):
        data = data.encode()

    encoded = data

    match config["security"]:
        case "aes256":
            aes = AESGCM(bytes.fromhex(config["user"]["key"]))
            nonce = os.urandom(8)
            ciphertext = aes.encrypt(
                nonce,
                data,
                None
            )
            encoded = nonce + ciphertext

    return encoded

def unsecure_data(config: dict, data: bytes):
    if isinstance(data, str):
        data = data.encode()

    decoded = data

    match config["security"]:
        case "aes256":
            key = config["user"]["key"]
            if isinstance(key, str):
                key = bytes.fromhex(key)

            nonce = data[:8]
            ciphertext = data[8:]

            aes = AESGCM(key)

            decoded = aes.decrypt(
                nonce,
                ciphertext,
                None
            )

    return decoded

def connect(config):
    transport = suggest_transport(config)
    to = (config["server"]["host"], config["server"]["port"])
    match transport:
        case "tcp" | "http": 
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(to)
            return s
        case "ws":
            s = ws.connect(f"ws://{to[0]}:{to[1]}")
            return s

def disconnect(s: socket.socket | ws.ClientConnection):
    s.close()

def send_data(data: bytes, config: dict, s: socket.socket | ws.ClientConnection, tudata: tuple[tuple[str, int], str]):
    transport = suggest_transport(config)
    match transport:
        case "tcp" | "http": 
            s.sendall(bytes(pack_data(data, config, transport, tudata)))
        case "ws":
            s.send(str(pack_data(data, config, transport, tudata)))

def pack_data(data: bytes, config: dict, transport: str, tudata: tuple[tuple[str, int], str]):
    match transport:
        case "tcp": 
            return _pack_data_tcp(data, config, tudata)
        case "http" | "tls":
            return _pack_data_http(data, config, tudata)
        case "ws":
            return _pack_data_ws(data, config, tudata)

def _pack_data_tcp(data: bytes, config: dict, tudata: tuple[tuple[str, int], str]):
    proto = tudata[1].encode("ascii")
    host = tudata[0][0].encode("ascii")
    port = tudata[0][1].to_bytes(2)
    packed = secure_data(config, proto + len(host).to_bytes(1) + host + port + data)
     # 3 bytes proto + 1 byte host length + X bytes host + 2 bytes port + X bytes data
    return packed

def _pack_data_ws(data: bytes, config: dict, tudata: tuple[tuple[str, int], str]):
    proto = tudata[1].encode("ascii")
    host = tudata[0][0].encode("ascii")
    port = tudata[0][1].to_bytes(2)
    packed = {
        "token" : base64.urlsafe_b64encode(secure_data(config, proto)).decode().rstrip("="),
        "auth" : [
            base64.urlsafe_b64encode(secure_data(config, host)).decode().rstrip("="),
            base64.urlsafe_b64encode(secure_data(config, port)).decode().rstrip("=")
        ],
        "data" : base64.urlsafe_b64encode(secure_data(config, data)).decode().rstrip("=")
    }
    return json.dumps(packed, separators=(",",":"))

http_strings = (" ".join("abcdefghigklmnopqrstuvwxyzQWERTYUIOPASDFGHJKLZXCVBNM------")).split(" ")
def _pack_data_http(send_data: bytes, config: dict, tudata: tuple[tuple[str, int], str]):
    random.shuffle(http_strings)
    obfs = config["obfuscation"]

    method = obfs["extra"]["method"].upper()
    path = "/" + "".join(http_strings[:16])
    headers = [("Host", config["server"]["host"])]

    psize = random.randint(obfs["padding"]["min"], obfs["padding"]["max"])

    if obfs["padding"] is not None:
        for _ in range(psize):
            random.shuffle(http_strings)
            headers.append((
                "".join(http_strings[:8]),
                "".join(http_strings[12:24])
            ))

    body = dict()

    match obfs["data"]["position"]:
        case "body":
            dt = send_data
            if obfs["data"]["encrypt"] == True:
                dt = secure_data(config, dt)
            if isinstance(dt, bytes):
                dt = base64.b85encode(dt).decode()
            body[obfs["data"]["name"]] = dt
        case "header":
            dt = send_data
            if obfs["data"]["encrypt"] == True:
                dt = secure_data(config, dt)
            if isinstance(dt, bytes):
                dt = base64.urlsafe_b64encode(dt).decode()
            headers.append((
                obfs["data"]["name"],
                dt
            ))

    match obfs["tu-data"]["position"]:
        case "body":
            tudt = json.dumps({"to":tudata[0], "proto":tudata[1], "token":config["user"]["token"]}, separators=(",",":"))
            if obfs["tu-data"]["encrypt"] == True:
                tudt = secure_data(config, tudt)
            if isinstance(tudt, bytes):
                tudt = base64.b85encode(tudt).decode()
            body[obfs["tu-data"]["name"]] = tudt
        case "header":
            tudt = json.dumps({"to":tudata[0], "proto":tudata[1], "token":config["user"]["token"]}, separators=(",",":"))
            if obfs["tu-data"]["encrypt"] == True:
                tudt = secure_data(config, tudt)
            if isinstance(tudt, bytes):
                tudt = base64.urlsafe_b64encode(tudt).decode()
            headers.append((
                obfs["tu-data"]["name"],
                tudt
            ))

    outputjson = json.dumps(body, separators=(",",":"))

    outputjson = outputjson.encode()
    headers.append(("Content-Length", str(len(outputjson))))

    random.shuffle(headers)
    
    conn = h11.Connection(h11.CLIENT)

    finalheaders = list()
    for header in headers:
        finalheaders.append((header[0].lower(), header[1]))

    data = conn.send(h11.Request(
        method=method,
        target=path,
        headers=finalheaders,
    ))

    data += conn.send(h11.Data(data=outputjson))
    data += conn.send(h11.EndOfMessage())

    return data

def decode_data(data: bytes, config: dict):
    transport = suggest_transport(config)
    match transport:
        case "tcp":
            return _decode_data_tcp(data, config)
        case "http" | "tls":
            return _decode_data_http(data, config)
        case "ws":
            return _decode_data_ws(data, config)

def _decode_data_tcp(data: bytes, config: dict):
    # from _pack_data_tcp() upper
     # 3 bytes proto + 1 byte host length + X bytes host + 2 bytes port + X bytes data
    data = unsecure_data(config, data)
    proto = data[0:3].decode()
    hostlength = int.from_bytes(data[3:4])
    host = data[4:hostlength+4].decode()
    port = int.from_bytes(data[hostlength+4:hostlength+6])
    decoded = data[hostlength+6:]

    return host, port, proto, decoded

def _decode_data_ws(data: bytes, config: dict): 
    if isinstance(data, str):
        data = data.encode()

    djson = json.loads(data.decode())
    decoded = unsecure_data(config, base64.urlsafe_b64decode(djson["data"] + "=" * (-len(djson["data"]) % 4)))
    host = unsecure_data(config, base64.urlsafe_b64decode(djson["auth"][0] + "=" * (-len(djson["auth"][0]) % 4))).decode()
    port = int.from_bytes(unsecure_data(config, base64.urlsafe_b64decode(djson["auth"][1] + "=" * (-len(djson["auth"][1]) % 4))))
    proto = unsecure_data(config, base64.urlsafe_b64decode(djson["token"] + "=" * (-len(djson["token"]) % 4))).decode()
    return host, port, proto, decoded

def _decode_data_http(data: bytes, config: dict): 
    if isinstance(data, str):
        data = data.encode()

    conn = h11.Connection(h11.SERVER)
    conn.receive_data(data)

    method = path = None
    headers = {}
    body = bytearray()

    while True:
        event = conn.next_event()

        if isinstance(event, h11.Request):
            method = event.method.decode()
            path = event.target.decode()
            headers = dict(event.headers)

        elif isinstance(event, h11.Data):
            body.extend(event.data)

        elif isinstance(event, h11.EndOfMessage):
            break

        elif event is h11.NEED_DATA:
            raise ConnectionError("NEED_DATA")

    body = body.decode()
    bjson = json.loads(body)

    obfs = config["obfuscation"]

    decoded_data = None
    decoded_tudata = None

    match obfs["data"]["position"]:
        case "body":
            decoded_data = bjson[obfs["data"]["name"]].encode()
            decoded_data = base64.b85decode(decoded_data.decode())
        case "header":
            decoded_data = headers[obfs["data"]["name"].lower().encode()]
            decoded_data = base64.urlsafe_b64decode(decoded_data.decode())

    match obfs["tu-data"]["position"]:
        case "body":
            decoded_tudata = bjson[obfs["tu-data"]["name"]].encode()
            decoded_tudata = base64.b85decode(decoded_tudata.decode())
        case "header":
            decoded_tudata = headers[obfs["tu-data"]["name"].lower().encode()]
            decoded_tudata = base64.urlsafe_b64decode(decoded_tudata.decode())

    if obfs["tu-data"]["encrypt"]:
        decoded_tudata = unsecure_data(config, decoded_tudata)

    if obfs["data"]["encrypt"]:
        decoded_data = unsecure_data(config, decoded_data)

    decoded_tudata = decoded_tudata.decode()
    decoded = decoded_data

    decoded_tudata = json.loads(decoded_tudata)

    host = decoded_tudata["to"][0]
    port = decoded_tudata["to"][1]
    proto = decoded_tudata["proto"]

    return host, port, proto, decoded

if __name__ == "__main__":
    example_c = {'server': {'host': 'localhost', 'port': 2487}, 'obfuscation': {'transport': 'http', 'padding': {'min': 2, 'max': 16}, 'data': {'position': 'body', 'name': 'TU-Data', 'encrypt': True}, 'tu-data': {'position': 'header', 'name': 'TU-Cache', 'encrypt': True}, 'padding-data': {'position': 'header', 'name': 'Session', 'encrypt': True}, 'extra': {'method': 'get'}}, 'security': 'aes256', 'user': {'token': '758c3df3-38d1-4b2a-8921-cbb9fb6acc1b', 'key': '64c0e751444e37176a3c8395407ad6cf17fa5c92f273a5d9372ef88534f24adf'}}
    check_client_config(example_c)

    DATA_TO_PACK = b"hello, world!"

    tcp_packed = _pack_data_tcp(DATA_TO_PACK, example_c, (("1.1.1.1", 53), "udp"))
    http_packed = _pack_data_http(DATA_TO_PACK, example_c, (("1.1.1.1", 53), "udp")).decode()
    ws_packed = _pack_data_ws(DATA_TO_PACK, example_c, (("1.1.1.1", 53), "udp"))

    print(" ##### http packet:")
    print(http_packed)
    print("\n\n ##### http packet DECODED")
    print(_decode_data_http(http_packed, example_c))

    print("\n ##### tcp packet:")
    print(tcp_packed)
    print("\n\n ##### tcp packet DECODED")
    print(_decode_data_tcp(tcp_packed, example_c))

    print("\n\n ##### websocket packet:")
    print(ws_packed)
    print("\n\n ##### websocket packet DECODED")
    print(_decode_data_ws(ws_packed, example_c))