from tulib import *

config = json.load(open("./example/user1.json"))
check_client_config(config)
transport = suggest_transport(config)

s = connect(config)

def main():
    send_data(input("data to send ->>> ").encode(), config, s, (("1.1.1.1", 53), "udp"))

while True:
    try:
        main()
    except Exception as e:
        print(e)
        s.close()
        break