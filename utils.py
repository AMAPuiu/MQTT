import socket
import logging
from scapy.contrib.mqtt import *

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s:%(levelname)s:%(message)s")


def send_connack(client_socket, addr, code):
    mqtt_pck = MQTT(type=2)
    payload = MQTTConnack(retcode=code)
    connack_pck = mqtt_pck/payload
    client_socket.send(bytes(connack_pck))

def send_suback(client_socket, addr, code, id):
    mqtt_pck = MQTT(type=9)
    payload = MQTTSuback(msgid=id, retcode=code)
    suback_pck = mqtt_pck/payload
    client_socket.send(bytes(suback_pck))

def send_unsuback(client_socket, addr, id):
    mqtt_pck = MQTT(type=11)
    payload = MQTTUnsuback(msgid=id)
    unsuback_pck = mqtt_pck/payload
    client_socket.send(bytes(unsuback_pck))

def send_puback(client_socket, addr, id):
    mqtt_pck = MQTT(type=4)
    payload = MQTTPuback(msgid=id)
    puback_pck = mqtt_pck/payload
    client_socket.send(bytes(puback_pck))

def send_pubrec(client_socket, addr, id):
    mqtt_pck = MQTT(type=5)
    payload = MQTTPubrec(msgid=id)
    pubrec_pck = mqtt_pck/payload
    client_socket.send(bytes(pubrec_pck))

def send_pubcomp(client_socket, addr, id):
    mqtt_pck = MQTT(type=7)
    payload = MQTTPubcomp(msgid=id)
    pubcomp_pck = mqtt_pck/payload
    client_socket.send(bytes(pubcomp_pck))

def send_pingresp(client_socket, addr):
    mqtt_pck = MQTT(type=13)
    client_socket.send(bytes(mqtt_pck))

def log_parsing_error(addr, msg, type, error):
    logging.info("{} Malformed packet: {}: {}: {}".format(
        addr, type, error, msg.decode))

def get_field(position, msg, size, matters):
    field_length = int.from_bytes(msg[position:(position+size)], "big")
    position += size
    field = msg[position:(position+field_length)]
    ok=1
    try:
        field = field.decode("utf-8")
    except:
        field = field.decode("cp855")
        if matters==1:
            ok=0

    position += field_length
    return position, field, ok
