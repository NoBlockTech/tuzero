from tulib import *
import threading

config = json.load(open("./example/server.json"))
check_server_config(config)
transport = suggest_transport(config)

def worker(cl: socket.socket, addr):
    try:
        while True:
            recvdata = cl.recv(4096)
            dt = decode_data(recvdata, config)
            dest = dt[0], dt[1]
            proto = dt[2]
            data = dt[3]
            print(f"got packet from {addr[0]}:{addr[1]}. transfer to {dest[0]}:{dest[1]}. using {proto}. data: {data[:36]}...")
    except Exception as e:
        cl.close()
        s.close()
        raise SystemExit(1)

def main():
    try:
        client_socket, addr = s.accept()
        threading.Thread(target=worker, args=(client_socket, addr), daemon=True).start()
    except:
        s.close()
        raise SystemExit(1)

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", config["listen"]["port"]))
    s.listen(1)
    while True:
        main()
except Exception as e:
    print(e)
    s.close()