import socket
from threading import Thread
import sys
import traceback
import logging

from client import *
from utils import log_parsing_error
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s:%(levelname)s:%(message)s")


def main():

    host = '127.0.0.1'

    port = 1883

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind((host, port))
    logging.info("Server started...")

    server_socket.listen(6)

    clients = []
    ips = []
    # IPs that have sent Connect packets
    ips_connect = []
    while True:

        client_socket, addr = server_socket.accept()
        ip, port = addr
        # logging.info("Got connection from: {} {}".format(ip, port))
        try:
            Thread(target=threaded, args=(
                client_socket, addr, clients, ips, ips_connect)).start()
        except:
            logging.info("Thread did not start.")
            traceback.print_exc()

    server_socket.shutdown(socket.SHUT_RDWR)
    server_socket.close()


def threaded(client_socket, addr, clients, ips, ips_connect):
    type = 0
    while type != 14:  # Disconnect is received

        msg = client_socket.recv(1024)
        if not msg:
            break
        type = (msg[0]) >> 4
        reserved = msg[0] & 15

        # Subscribe
        if type == 8:
            # Packet is ok
            ok = 1
            if addr[0] not in ips_connect and addr[0] not in ips:
                log_parsing_error(addr, msg, "Subscribe",
                                  "Connect packet wasn't sent.")
                ok = 0
                client = Client(addr[0], addr[1])
                clients.append(client)
                ips.append(addr[0])
            elif addr[0] not in ips_connect and addr[0] in ips:
                log_parsing_error(addr, msg, "Subscribe",
                                  "Connect packet wasn't sent.")
                ok = 0
                for client in clients:
                    if client.ip == addr[0] and client.port == addr[1]:
                        break
            else:
                for client in clients:
                    if client.ip == addr[0] and client.port == addr[1]:
                        break
            try:
                ok = client.got_subscribe(client_socket, addr, msg, ok)
                if ok == 0:
                    client.data.append(msg)
                else:
                    client.packets.append(("Subscribe", msg))
                    logging.info("{} Subscribe packet - ok".format(addr))
            except:
                traceback.print_exc()

        # Publish
        elif type == 3:
            ok = 1
            qos = (msg[0] >> 1) & 3
            if qos != 0 and qos != 1 and qos != 2:
                log_parsing_error(addr, msg, "Publish", "Invalid qos level")
                ok = 0

            if addr[0] not in ips_connect and addr[0] not in ips:
                log_parsing_error(addr, msg, "Publish",
                                  "Connect packet wasn't sent.")
                ok = 0
                client = Client(addr[0], addr[1])
                clients.append(client)
                ips.append(addr[0])
            elif addr[0] not in ips_connect and addr[0] in ips:
                log_parsing_error(addr, msg, "Publish",
                                  "Connect packet wasn't sent.")
                ok = 0
                for client in clients:
                    if client.ip == addr[0] and client.port == addr[1]:
                        break
            else:
                for client in clients:
                    if client.ip == addr[0] and client.port == addr[1]:
                        break
            try:
                ok = client.got_publish(client_socket, addr, msg, qos, ok)
                if ok == 0:
                    client.data.append(msg)
                else:
                    client.packets.append(("Publish", msg))
                    logging.info("{} Publish packet - ok".format(addr))
            except:
                traceback.print_exc()

        # Pingreq
        elif type == 12:

            ok = 1
            if reserved != 0:
                log_parsing_error(addr, msg, "Pingreq",
                                  "Invalid flags in fixed header")
                ok = 0

            if addr[0] not in ips_connect and addr[0] not in ips:
                log_parsing_error(addr, msg, "Pingreq",
                                  "Connect packet wasn't sent.")
                ok = 0
                client = Client(addr[0], addr[1])
                clients.append(client)
                ips.append(addr[0])
            elif addr[0] not in ips_connect and addr[0] in ips:
                log_parsing_error(addr, msg, "Pingreq",
                                  "Connect packet wasn't sent.")
                ok = 0
                for client in clients:
                    if client.ip == addr[0]:
                        break
            else:
                for client in clients:
                    if client.ip == addr[0]:
                        break
            try:
                ok = client.got_pingreq(client_socket, addr, msg, ok)
                if ok == 0:
                    client.data.append(msg)
                else:
                    client.packets.append(("Pingreq", msg))
                    logging.info("{} Pingreq packet - ok".format(addr))
            except:
                traceback.print_exc()

        # Unsubscribe
        elif type == 10:
            ok = 1
            if reserved != 2:
                log_parsing_error(addr, msg, "Unsubscribe",
                                  "Invalid flags in fixed header")
                ok = 0

            if addr[0] not in ips_connect and addr[0] not in ips:
                log_parsing_error(addr, msg, "Unsubscribe",
                                  "Connect packet wasn't sent.")
                ok = 0
                client = Client(addr[0], addr[1])
                clients.append(client)
                ips.append(addr[0])
            elif addr[0] not in ips_connect and addr[0] in ips:
                log_parsing_error(addr, msg, "Unsubscribe",
                                  "Connect packet wasn't sent.")
                ok = 0
                for client in clients:
                    if client.ip == addr[0] and client.port==addr[1]:
                        break
            else:
                for client in clients:
                    if client.ip == addr[0] and client.port==addr[1]:
                        break
            try:
                ok = client.got_unsubcribe(client_socket, addr, msg, ok)
                if ok == 0:
                    client.data.append(msg)
                else:
                    client.packets.append(("Unsubscribe", msg))
                    logging.info("{} Unsubscribe packet - ok".format(addr))
            except:
                traceback.print_exc()

        # Connect
        elif type == 1:
            ok = 1
            if reserved != 0:
                log_parsing_error(addr, msg, "Connect",
                                  "Invalid flags in fixed header")
                ok = 0

            new_client = Client(addr[0], addr[1])
            try:
                ok = new_client.got_connect(client_socket, addr, msg, ok)
                clients.append(new_client)
                ips.append(new_client.ip)
                ips_connect.append(new_client.ip)
                if ok == 0:
                    new_client.data.append(msg)
                else:
                    new_client.packets.append(("Connect", msg))
                    logging.info("{} Connect packet - ok".format(addr))
            except:
                traceback.print_exc()
        elif type == 14:
            ok = 1
            if reserved != 0:
                log_parsing_error(addr, msg, "Connect",
                                  "Invalid flags in fixed header")
                ok = 0
            for client in clients:
                if client.ip == addr[0] and client.port==addr[1]:
                    break
            try:
                ok = client.got_disconnect(client_socket, addr, msg, ok)
                if ok == 0:
                    client.data.append(msg)
                else:
                    client.packets.append(("Disconnect", msg))
                    logging.info("{} Disconnect packet - ok".format(addr))
            except:
                traceback.print_exc()

        else:
            if addr[0] not in ips:
                client = Client(addr[0], addr[1])
                clients.append(client)
                ips.append(addr[0])
            else:
                for client in clients:
                    if client.ip == addr[0] and client.port==addr[1]:
                        break
            client.data.append(msg)
            logging.info("{} Unexpected packet:{}".format(addr, msg))

    client_socket.close()
    found = 0
    for client in clients:
        if client.ip == addr[0] and client.port == addr[1]:
            found = 1
            break
    if found == 1:
        client.log_client(addr)

    # client_socket.close()
if __name__ == "__main__":
    main()
