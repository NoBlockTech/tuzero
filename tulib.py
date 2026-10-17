from websockets.sync import \
    client as ws              # same as xray's ws  transport
import socket                 # same as xray's TCP transport
from asyncio_socks_server import Flow, Address
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, random
import h11
import json

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
            if data["obfuscation"]["transport"] not in ("http", "ws"): raise BADCONFIG()
            if data["obfuscation"]["padding"] is not None:
                if not isinobj(("min", "max"), data["obfuscation"]["padding"]): raise BADCONFIG()
                if not type(data["obfuscation"]["padding"]["min"]) is int: raise BADCONFIG()
                if not type(data["obfuscation"]["padding"]["max"]) is int: raise BADCONFIG()
                if not (data["obfuscation"]["padding"]["min"] < data["obfuscation"]["padding"]["max"]): raise BADCONFIG()
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
    try:
        if not isinobj(("listen", "obfuscation", "security", "clients"), data): raise BADCONFIG()
        if not isinobj(("host", "port"), data["listen"]): raise BADCONFIG()
        if not type(data["listen"]["host"]) is str: raise BADCONFIG()
        if not type(data["listen"]["port"]) is int: raise BADCONFIG()
        if not (0 < data["listen"]["port"] < 65536): raise BADCONFIG()
        if data["obfuscation"] is not None:
            if not isinobj(("transport", "padding", "data", "tu-data", "padding-data", "extra"), data["obfuscation"]): raise BADCONFIG()
            if data["obfuscation"]["transport"] not in ("http", "ws"): raise BADCONFIG()
            if data["obfuscation"]["padding"] is not None:
                if not isinobj(("min", "max"), data["obfuscation"]["padding"]): raise BADCONFIG()
                if not type(data["obfuscation"]["padding"]["min"]) is int: raise BADCONFIG()
                if not type(data["obfuscation"]["padding"]["max"]) is int: raise BADCONFIG()
                if not (data["obfuscation"]["padding"]["min"] < data["obfuscation"]["padding"]["max"]): raise BADCONFIG()
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
                if data["obfuscation"]["transport"] in ("http",):
                    if not isinobj(("method",), data["obfuscation"]["extra"]): raise BADCONFIG()
                    if data["obfuscation"]["extra"]["method"] not in ("post", "get", "head", "delete", "put"): raise BADCONFIG()
        if data["security"] not in (None, "aes256"): raise BADCONFIG()
        for client in data["clients"]:
            if not isinobj(("token", "key"), data["clients"][client]): raise BADCONFIG()
            if not type(data["clients"][client]["token"]) is str: raise BADCONFIG()
            if not type(data["clients"][client]["key"]) is str: raise BADCONFIG()
    except: raise BADCONFIG()
    return 0

def suggest_transport(config):
    transport = "tcp"
    check_client_config(config)
    if config["obfuscation"] is None: return transport
    return config["obfuscation"]["transport"]

def secure_data(config: dict, data: bytes):
    if isinstance(data, str):
        data = data.encode()

    encoded = data

    match config["security"]:
        case "aes256":
            aes = AESGCM(bytes.fromhex(config["user"]["key"]))
            nonce = os.urandom(12)
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

            nonce = data[:12]
            ciphertext = data[12:]

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

def disconnect(s: socket.socket | ws.ClientConnection):
    s.close()

def send_data(data: bytes, config: dict, s: socket.socket | ws.ClientConnection, flow: Flow):
    to = (flow.dst.host, flow.dst.port)
    transport = suggest_transport(config)
    match transport:
        case "tcp" | "http": 
            s.sendall(pack_data(data, config, transport, flow))
        case "ws":
            s.send(pack_data(data, config, transport, flow))

def pack_data(data: bytes, config: dict, transport: str, flow: Flow):
    match transport:
        case "tcp": 
            return _pack_data_tcp(data, config, flow)
        case "http":
            return _pack_data_http(data, config, flow)
        case "ws":
            return _pack_data_ws(data, config, flow)

def _pack_data_tcp(data: bytes, config: dict, flow: Flow):
    proto = flow.protocol.encode("ascii")
    host = flow.dst.host.encode("ascii")
    port = flow.dst.port.to_bytes(2)
    data = data
    packed = secure_data(config, proto + len(host).to_bytes(3) + host + port + data)
     # 3 bytes proto + 3 bytes host length + X bytes host + 2 bytes port + X bytes data
    return packed

def _pack_data_ws(data: bytes, config: dict, flow: Flow):
    _pack_data_tcp(data, config, flow)

http_strings = (" ".join("abcdefghigklmnopqrstuvwxyzQWERTYUIOPASDFGHJKLZXCVBNM------")).split(" ")
def _pack_data_http(send_data: bytes, config: dict, flow: Flow):
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
                dt = dt.hex()
            body[obfs["data"]["name"]] = dt
        case "header":
            dt = send_data
            if obfs["data"]["encrypt"] == True:
                dt = secure_data(config, dt)
            if isinstance(dt, bytes):
                dt = dt.hex()
            headers.append((
                obfs["data"]["name"],
                dt
            ))

    match obfs["tu-data"]["position"]:
        case "body":
            tudt = json.dumps({"to":[flow.dst.host, flow.dst.port], "token": config["user"]["token"]})
            if obfs["tu-data"]["encrypt"] == True:
                tudt = secure_data(config, tudt)
            if isinstance(tudt, bytes):
                tudt = tudt.hex()
            body[obfs["tu-data"]["name"]] = tudt
        case "header":
            tudt = json.dumps({"to":[flow.dst.host, flow.dst.port], "token": config["user"]["token"]})
            if obfs["tu-data"]["encrypt"] == True:
                tudt = secure_data(config, tudt)
            if isinstance(tudt, bytes):
                tudt = tudt.hex()
            headers.append((
                obfs["tu-data"]["name"],
                tudt
            ))

    outputjson = json.dumps(body)

    outputjson = outputjson.encode()
    headers.append(("Content-Length", str(len(outputjson))))

    random.shuffle(headers)
    
    conn = h11.Connection(h11.CLIENT)

    finalheaders = list()
    for header in headers:
        finalheaders.append((header[0].lower(), header[1].lower()))

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
            return _decode_data_tcp(data, config, transport)
        case "http":
            return _decode_data_http(data, config, transport)
        case "ws":
            return _decode_data_ws(data, config, transport)

def _decode_data_tcp(data: bytes, config: dict):
    # from _pack_data_tcp() upper
     # 3 bytes proto + 3 bytes host length + X bytes host + 2 bytes port + X bytes data
    data = unsecure_data(config, data)
    proto = data[0:3]
    hostlength = int.from_bytes(data[3:6])
    host = data[6:hostlength+6]
    port = int.from_bytes(data[hostlength+6:hostlength+8])
    decoded = data[hostlength+8:]

    return proto, hostlength, host, port, decoded

def _decode_data_ws(data: bytes, config: dict): 
    return _decode_data_tcp(data, config)

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
        case "header":
            decoded_data = headers[obfs["data"]["name"].lower().encode()]

    match obfs["tu-data"]["position"]:
        case "body":
            decoded_tudata = bjson[obfs["tu-data"]["name"]].encode()
        case "header":
            decoded_tudata = headers[obfs["tu-data"]["name"].lower().encode()]

    decoded_tudata = bytes.fromhex(decoded_tudata.decode())
    decoded_data = bytes.fromhex(decoded_data.decode())

    decoded_tudata = unsecure_data(config, decoded_tudata).decode()
    decoded_data = unsecure_data(config, decoded_data)

    decoded_tudata = json.loads(decoded_tudata)

    return decoded_data, decoded_tudata

if __name__ == "__main__":
    example_c = {'server': {'host': 'localhost', 'port': 2487}, 'obfuscation': {'transport': 'http', 'padding': {'min': 2, 'max': 16}, 'data': {'position': 'body', 'name': 'TU-Data', 'encrypt': True}, 'tu-data': {'position': 'header', 'name': 'TU-Cache', 'encrypt': True}, 'padding-data': {'position': 'header', 'name': 'Session', 'encrypt': True}, 'extra': {'method': 'get'}}, 'security': 'aes256', 'user': {'token': '758c3df3-38d1-4b2a-8921-cbb9fb6acc1b', 'key': '64c0e751444e37176a3c8395407ad6cf17fa5c92f273a5d9372ef88534f24adf'}}
    check_client_config(example_c)

    DATA_TO_PACK = "hello, world!".encode()

    tcp_packed = _pack_data_tcp(DATA_TO_PACK, example_c, Flow(123, Address("127.0.0.1", 65535), Address("1.1.1.1", 53), "udp", 0))
    http_packed = _pack_data_http(DATA_TO_PACK, example_c, Flow(123, Address("127.0.0.1", 65535), Address("1.1.1.1", 53), "udp", 0)).decode()

    print(" ##### http packet:")
    print(http_packed)
    print("\n ##### tcp packet:")
    print(tcp_packed)
    print("\n\n ##### tcp packet DECODED")
    print(_decode_data_tcp(tcp_packed, example_c))
    print("\n\n ##### http packet DECODED")
    print(_decode_data_http(http_packed, example_c))