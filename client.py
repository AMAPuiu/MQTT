from utils import *
import logging
import socket


class Client():

    def __init__(self, ip=None, port=None):

        self.ip = ip
        self.port = port
        self.packets = []
        self.subscribe_topics = []
        self.publish_topics = []
        self.unsubscribe_topics = []
        self.data = []
        self.password_flag = 0
        self.password = None
        self.user_flag = 0
        self.user = None
        self.will_flag = 0
        self.will_topic = None
        self.will_message = None
        self.client_id = None
        self.added_bytes = []

    def get_remaining_length(self, msg, addr, type, p):

        multiplier = 1
        value = 0
        while True:
            encodedByte = msg[p]
            value += (encodedByte & 127) * multiplier
            multiplier *= 128
            p += 1
            if multiplier > 128*128*128:
                log_parsing_error(
                    addr, msg, type, "Remaining_length is too big")
                value = -1
            if (encodedByte & 128) == 0:
                break

        return value

    def got_connect(self, client_socket, addr, msg, ok):

        # Gets remaining_length of packet from fixed header
        position = 1
        msg_length = self.get_remaining_length(msg, addr, "Connect", position)
        
        if msg_length == -1:
            return 0
        position+=1
        size = position-1
        # Checks if the length of received data is equal to the Remaining_length from fixed header+its size+the first byte
        if msg_length+size+1 != len(msg):
            log_parsing_error(addr, msg, "Connect",
                              "Remaining_length != length of packet")
            self.added_bytes.append(
                ("Connect", msg, msg[(msg_length+size+1):len(msg)]))

        # Checks protocol
        position, self.protocol, worked = get_field(position, msg, 2, 1)
        if self.protocol != "MQIsdp":
            log_parsing_error(addr, msg, "Connect", "Wrong protocol")
            send_connack(client_socket, addr, 1)
            return 0

        # Checks version
        self.version = msg[position]
        if msg[position] != 3:
            log_parsing_error(addr, msg, "Connect", "Wrong protocol version")
            send_connack(client_socket, addr, 1)
            return 0
        position += 1

        # Flags
        flags = msg[position]
        self.will_flag = (flags >> 2) & 1
        self.password_flag = (flags >> 6) & 1
        self.user_flag = (flags >> 7) & 1
        position += 1

        # Stores client ID
        position += 2
        position, self.client_id, worked = get_field(position, msg, 2, 1)
        if worked == 0:
            log_parsing_error(addr, msg, "Connect",
                              "Client ID is not utf-8 encoded")
            ok = 0
        # Checks if will flag is set
        if self.will_flag == 1:
            position, self.will_topic, worked = get_field(
                position, msg, 2, 1)
            if worked == 0:
                log_parsing_error(addr, msg, "Connect",
                                  "Will topic is not utf-8 encoded")
                ok = 0
            position, self.will_message, worked = get_field(
                position, msg, 2, 0)

        # Checks if username and password flags are set
        if (self.password_flag)*(self.user_flag) == 1:
            # Stores username and password
            position,  self.user, worked = get_field(position, msg, 2, 1)
            if worked == 0:
                log_parsing_error(addr, msg, "Connect",
                                  "User is not UTF-8 encoded")
                ok = 0
            position,  self.password, worked = get_field(position, msg, 2, 0)
        elif self.user_flag == 1:
            position,  self.user, worked = get_field(position, msg, 2, 1)
            if worked == 0:
                log_parsing_error(addr, msg, "Connect",
                                  "User is not UTF-8 encoded")
                ok = 0
        else:
            position,  self.password, worked = get_field(position, msg, 2, 0)
            log_parsing_error(addr, msg, "Connect",
                              "Password is given, but username is not")
            ok = 0

        # Sends Connack packet with retcode 5
        send_connack(client_socket, addr, 0)

        return ok

    def got_publish(self, client_socket, addr, msg, qos, ok):

        # Gets remaining_length of packet from fixed header
        position = 1
        msg_length = self.get_remaining_length(
            msg, addr, "Publish", position)
        if msg_length == -1:
            return 0
        position+=1
        size = position-1

        # Gets topic
        position, topic, worked = get_field(position, msg, 2, 1)
        if worked == 0:
            log_parsing_error(addr, msg, "Publish",
                              "Topic is not utf-8 encoded")
            ok = 0
        print(topic)
        if "+"  in topic:
            log_parsing_error(addr, msg, "Publish", "Contains wildcards")
            ok = 0
        #or "#" or "$SYS"
        # Gets packet_id
        if qos == 1 or qos == 2:
            packet_id = int.from_bytes(msg[position:position+2], "big")
            position += 2
        else:
            packet_id = None
        # Gets message
        message = msg[position:len(msg)]
        message = message.decode("cp855")
        # Append
        self.publish_topics.append((topic, qos, message))
        # Responds
        if qos == 1:
            send_puback(client_socket, addr, packet_id)
        elif qos == 2:
            send_pubrec(client_socket, addr, packet_id)
            # Receives pubrel
            msg = client_socket.recv(1024)
            type = (msg[0]) >> 4
            reserved = ((msg[0]) << 4) >> 4
            if type != 6:
                log_parsing_error(
                    addr, msg, "Pubrel", "Pubrel packet wasn't received although Publish happened")
                self.data.append(msg)
                return 0
            self.packets.append(("Pubrel", msg))
            if reserved != 2:
                log_parsing_error(addr, msg, "Pubrel",
                                  "Invalid flags in fixed header")
                ok = 0
            if len(msg) != 4:
                log_parsing_error(
                    addr, msg, "Pubrel", "Length of received data is bigger than it should be")
                self.added_bytes.append(("Pubrel", msg, msg[4:len(msg)]))
                ok = 0
            msg_length = msg[1]
            if msg_length != 2:
                log_parsing_error(addr, msg, "Pubrel", "Invalid length")
                ok = 0
            packet_id_response = int.from_bytes(msg[2:4], "big")
            if packet_id != packet_id_response:
                log_parsing_error(addr, msg, "Pubrel", "Packet ids differ")
                ok = 0
            send_pubcomp(client_socket, addr, packet_id_response)
        return ok

    def got_subscribe(self, client_socket, addr, msg, ok):

        # Gets remaining_length of packet from fixed header
        position = 1
        msg_length = self.get_remaining_length(
            msg, addr, "Subscribe", position)
        if msg_length == -1:
            return 0
        position+=1
        size = position-1
        # Checks if the length of received data is equal to the Remaining_length from fixed header+its size+the first byte
        if msg_length+size+1 != len(msg):
            log_parsing_error(addr, msg, "Subscribe",
                              "Remaining_length != length of packet")
            self.added_bytes.append(
                ("Subscribe", msg, msg[(msg_length+size+1):len(msg)]))
            ok = 0
        # Gets packet_ID
        packet_ID = int.from_bytes(msg[position:(position+2)], "big")
        position += 2
        # Gets topics and qos
        if position == msg_length+size+1:
            log_parsing_error(addr, msg, "Subscribe", "There are no topics")
            return 0
        topic = ""
        while position != msg_length+size+1:
            position, topic, worked = get_field(position, msg, 2, 1)
            if worked == 0:
                log_parsing_error(addr, msg, "Subscribe",
                                  "Topic is not utf-8 encoded")
                ok = 0
            qos = msg[position] & 3
            if msg[position] >> 2 != 0:
                log_parsing_error(addr, msg, "Subscribe",
                                  "Reserved bytes from qos are malformed")
                ok = 0

            self.subscribe_topics.append((topic, qos))

            if qos != 0 and qos != 1 and qos != 2:
                log_parsing_error(addr, msg, "Subscribe",
                                  "Qos is not 0, 1 or 2")
                qos = 0
                ok = 0

            position += 1
            # Sends Suback as respond
            send_suback(client_socket, addr, qos, packet_ID)
        return ok

    def got_unsubcribe(self, client_socket, addr, msg, ok):

        # Gets remaining_length of packet from fixed header
        position = 1
        msg_length = self.get_remaining_length(
            msg, addr, "Unsubscribe", position)
        if msg_length == -1:
            return 0
        position+=1
        size = position-1
        # Gets packet-id
        packet_ID = int.from_bytes(msg[position:(position+2)], "big")
        position += 2
        # Gets topics
        if position == msg_length+size+1:
            log_parsing_error(addr, msg, "Unsubscribe", "There are no topics")
            return 0
        while position != msg_length+size+1:
            position, topic, worked = get_field(position, msg, 2, 1)
            if worked == 0:
                log_parsing_error(addr, msg, "Unsubscribe",
                                  "Topic is not utf-8 encoded")
                ok = 0
            self.unsubscribe_topics.append(topic)

        # Checks if there are bytes that will remain unparsed
        if position < len(msg):
            log_parsing_error(addr, msg, "Unsubscribe",
                              "Bytes have been added to the packet")
            self.added_bytes.append(
                ("Unsubscribe", msg, msg[position:len(msg)]))
            ok = 0
        send_unsuback(client_socket, addr, packet_ID)
        return ok

    def got_pingreq(self, client_socket, addr, msg, ok):

        msg_length = msg[1]
        if msg_length != 0:
            log_parsing_error(addr, msg, "Pingreq", "Invalid length")
            self.added_bytes.append(("Pingreq", msg, msg[2:len(msg)]))
            ok = 0
        send_pingresp(client_socket, addr)
        return ok

    def got_disconnect(self, client_socket, addr, msg, ok):

        if len(msg)>2:
            log_parsing_error(addr, msg, "Disconnect","Bytes have been added to the packet")
            self.added_bytes.append(
                ("Unsubscribe", msg, msg[2:len(msg)]))
            ok=0
        if msg[1]!=0:
            log_parsing_error(addr, msg, "Disconnect", "Length is too big")
            ok=0
        return ok

    def log_client(self,addr):
        logging.info("{} Client disconnected. User:{} Pass:{} Client ID:{} Will topic:{} Will message:{} Good Packets:{} Malformed:{} Added bytes:{} Subscribe:{} Unsubscribe:{} Publish:{}".format(
                        addr,self.user,self.password,self.client_id,self.will_topic, self.will_message,self.packets,self.data,self.added_bytes,self.subscribe_topics,self.unsubscribe_topics,self.publish_topics))
