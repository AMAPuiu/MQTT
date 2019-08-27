import socket
from threading import Thread
import sys
import traceback
import logging

from client import *
from utils import log_parsing_error
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s:%(levelname)s:%(message)s")
UNKNOWN_PACKET=0
CONNECT_PACKET=1
CONNACK_PACKET=2
PUBLISH_PACKET=3
PUBACK_PACKET=4
PUBREC_PACKET=5
PUBREL_PACKET=6
PUBCOMP_PACKET=7
SUBSCRIBE_PACKET=8
SUBACK_PACKET=9
UNSUBSCRIBE_PACKET=10
UNSUBACK_PACKET=11
PINGREQ_PACKET=12
PINGRESP_PACKET=13
DISCONNECT_PACKET=14

def main():

    host = '127.0.0.1'

    port = 1883

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind((host, port))
    logging.info("Server started...")

    server_socket.listen(6)

    while True:

        client_socket, addr = server_socket.accept()
        ip, port = addr
        try:
            Thread(target=threaded, args=(client_socket, addr,)).start()
        except:
            logging.info("Thread did not start.")
            traceback.print_exc()

    server_socket.shutdown(socket.SHUT_RDWR)
    server_socket.close()


def threaded(client_socket, addr):
    
    type = 0
    while type != DISCONNECT_PACKET:  # Disconnect is received

        msg = client_socket.recv(1024)
        if not msg:
            break
        type = (msg[0]) >> 4
        
        s=Switcher()
        try:
            s.got_packet(type,msg,addr,client_socket)
        except:
            traceback.print_exc()

    
    client_socket.close()

    # client_socket.close()
if __name__ == "__main__":
    main()
