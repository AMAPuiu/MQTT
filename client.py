from utils import *
import logging
import socket


class Switcher():

    def got_packet(self, type, msg, addr, client_socket):
        name=return_type(type)
        method_name="got_" + name
        method=getattr(self, method_name, lambda: "Invalid")
        return method(client_socket, addr, msg)

    def got_connect(self, client_socket, addr, msg):

        # List of errors that might appear during parsing
        errors = []
        # List of extracted data
        data = []
        # Checks reserved bites from fixed header
        reserved = msg[0] & 15
        if reserved != 0:
            errors.append("Invalid flags in fixed header")

        # Gets remaining_length of packet from fixed header
        position = 1
        msg_length = get_remaining_length(msg, errors, position)
        
        if msg_length == -1:
            log_parsing_error(addr,msg,"Connect",errors)
            return 
        position+=1
        size = position-1

        # Checks if the length of received data is equal to the Remaining_length from fixed header+its size+the first byte
        if msg_length+size+1 != len(msg):
            errors.append("Remaining_length != length of packet")

        # Checks protocol
        position, protocol, worked = get_field(position, msg, 2, 1)
        if protocol != "MQIsdp":
            errors.append("Wrong protocol")
            log_parsing_error(addr, msg,"Connect",errors)
            send_connack(client_socket, addr, 1)
            return 
        data.append(("Protocol",protocol))
        # Checks version
        version = msg[position]
        if msg[position] != 3:
            errors.append("Wrong protocol version")
            log_parsing_error(addr, msg, "Connect", errors)
            send_connack(client_socket, addr, 1)
            return 
        data.append(("Version",version))
        position += 1
        
        # Flags
        flags = msg[position]
        will_flag = (flags >> 2) & 1
        password_flag = (flags >> 6) & 1
        user_flag = (flags >> 7) & 1
        position += 1
        
        # Stores client ID
        position += 2
        position, client_id, worked = get_field(position, msg, 2, 1)
        if worked == 0:
            errors.append("Client ID is not utf-8 encoded")
        data.append(("Client ID",client_id))
        # Checks if will flag is set
        if will_flag == 1:
            position, will_topic, worked = get_field(
                position, msg, 2, 1)
            if worked == 0:
                errors.append("Will topic is not utf-8 encoded")
            position, will_message, worked = get_field(
                position, msg, 2, 0)
            data.append(("Will topic",will_topic))
            data.append(("Will message",will_message))
        user=None
        password=None
        # Checks if username and password flags are set
        if (password_flag)*(user_flag) == 1:
            # Stores username and password
            position,  user, worked = get_field(position, msg, 2, 1)
            if worked == 0:
                errors.append("User is not utf-8 encoded")
            position,  password, worked = get_field(position, msg, 2, 0)

        elif user_flag == 1:
            position,  user, worked = get_field(position, msg, 2, 1)
            if worked == 0:
                errors.append("User is not utf-8 encoded")
                
        else:
            position,  password, worked = get_field(position, msg, 2, 0)
            errors.append("Password is given, but username is not")
        data.append(("User",user))
        data.append(("Password",password))
        # Sends Connack packet with retcode 5
        send_connack(client_socket, addr, 0)

        # Checks if any errors appeared
        if len(errors)==0:
            logging.info("{} Connect packet - ok. Data:{}".format(addr, data))
        else:
            log_parsing_error(addr,msg,"Connect",errors)

    def got_publish(self, client_socket, addr, msg):

        # List of errors that might appear during parsing
        errors = []

        # Gets qos level
        qos = (msg[0] >> 1) & 3
        if qos != 0 and qos != 1 and qos != 2:
            errors.append("Invalid qos level")

        # Gets remaining_length of packet from fixed header
        position = 1
        msg_length = get_remaining_length(
            msg, errors, position)
        if msg_length == -1:
            log_parsing_error(addr,msg,"Publish",errors)
            return 
        position+=1
        size = position-1

        # Gets topic
        position, topic, worked = get_field(position, msg, 2, 1)
        if worked == 0:
            errors.append("Topic is not utf-8 encoded")
        if "+"  in topic:
            errors.append("Contains wildcards:{}".format(topic))
        if "#" in topic:
            errors.append("Contains wildcards:{}".format(topic))
        if "$SYS" in topic:
            errors.append("Contains wildcards:{}".format(topic))

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
        publish_topic=(topic, qos, message)

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
                errors.append("Pubrel packet wasn't received although Publish happened")
                log_parsing_error(addr, msg, "Publish", errors)
                return 
            if reserved != 2:
                errors.append("Invalid flags in fixed header")
            if len(msg) != 4:
                errors.append("Length of received data is bigger than it should be")
            msg_length = msg[1]
            if msg_length != 2:
                errors.append("Pubrel:Invalid length")
            packet_id_response = int.from_bytes(msg[2:4], "big")
            if packet_id != packet_id_response:
                errors.append("Pubrel: Packet ids differ")
            send_pubcomp(client_socket, addr, packet_id_response)

        # Checks if any errors appeared
        if len(errors)==0:
            logging.info("{} Publish packet - ok. Packet id:{} Topic:{}".format(addr, packet_id, publish_topic))
        else:
            log_parsing_error(addr,msg,"Publish",errors)

    def got_subscribe(self, client_socket, addr, msg):

        # List of errors that might appear during parsing
        errors = []

        # Checks reserved bites from fixed header
        reserved = msg[0] & 15
        if reserved != 2:
            errors.append("Invalid flags in fixed header")

        # Gets remaining_length of packet from fixed header
        position = 1
        msg_length = get_remaining_length(msg, errors, position)
        if msg_length == -1:
            log_parsing_error(addr,msg,"Subscribe",errors)
            return 
        position+=1
        size = position-1

        # Checks if the length of received data is equal to the Remaining_length from fixed header+its size+the first byte
        if msg_length+size+1 != len(msg):
            errors.append("Bytes have been added")

        # Gets packet_ID
        packet_ID = int.from_bytes(msg[position:(position+2)], "big")
        position += 2

        # Gets topics and qos
        subscribe_topics = []
        if position == msg_length+size+1:
            errors.append("There are no topics")
            log_parsing_error(addr,msg,"Subscribe",errors)
            return 

        topic = ""

        while position != msg_length+size+1:

            position, topic, worked = get_field(position, msg, 2, 1)
            if worked == 0:
                errors.append("Topic is not utf-8 encoded")

            qos = msg[position] & 3
            if (msg[position] >> 2) != 0:
                errors.append("Reserved bytes from qos are malformed")

            subscribe_topics.append((topic, qos))

            if qos != 0 and qos != 1 and qos != 2:
                errors.append("Qos is not 0, 1 or 2")
                qos = 0

            position += 1
            # Sends Suback as respond
            send_suback(client_socket, addr, qos, packet_ID)

            # Checks if any errors appeared
            if len(errors)==0:
                logging.info("{} Subscribe packet - ok. Packet id:{} Topics:{}".format(addr, packet_ID, subscribe_topics))
            else:
                log_parsing_error(addr,msg,"Subscribe",errors)
                
        

    def got_unsubcribe(self, client_socket, addr, msg):

        # List of errors that might appear during parsing
        errors = []

        # Checks reserved bites from fixed header
        reserved = msg[0] & 15
        if reserved != 2:
            errors.append("Invalid flags in fixed header")

        # Gets remaining_length of packet from fixed header
        position = 1
        msg_length = get_remaining_length(
            msg, errors, position)
        if msg_length == -1:
            log_parsing_error(addr,msg,"Unsubscribe",errors)
            return 
        position+=1
        size = position-1

        # Gets packet-id
        packet_ID = int.from_bytes(msg[position:(position+2)], "big")
        position += 2

        # Gets topics
        if position == msg_length+size+1:
            errors.append("There are no topics")

        unsubscribe_topics = []
        while position != msg_length+size+1:
            position, topic, worked = get_field(position, msg, 2, 1)
            if worked == 0:
                errors.append("Topic is not utf-8 encoded")

        unsubscribe_topics.append(topic)

        # Checks if there are bytes that will remain unparsed
        if position < len(msg):
            errors.append("Bytes have been added to the packet")

        send_unsuback(client_socket, addr, packet_ID)

        # Checks if any errors appeared
        if len(errors)==0:
            logging.info("{} Unsubscribe packet - ok. Packet id:{} Topics:{}".format(addr, packet_ID, unsubscribe_topics))
        else:
            log_parsing_error(addr,msg,"Unsubscribe",errors)
        

    def got_pingreq(self, client_socket, addr, msg):
        # List of errors that might appear during parsing
        errors = []

        # Checks reserved bites from fixed header
        reserved = msg[0] & 15
        if reserved != 0:
            errors.append("Invalid flags in fixed header")

        msg_length = msg[1]
        if msg_length != 0:
            errors.append("Invalid length")

        send_pingresp(client_socket, addr)

        # Checks if any errors appeared
        if len(errors)==0:
            logging.info("{} Pingreq - ok.".format(addr))
        else:
            log_parsing_error(addr,msg,"Pingreq",errors)

    def got_disconnect(self, client_socket, addr, msg):
        # List of errors that might appear during parsing
        errors = []

        # Checks reserved bites from fixed header
        reserved = msg[0] & 15
        if reserved != 0:
            errors.append("Invalid flags in fixed header")
        
        if len(msg)>2:
            errors.append("Bytes have been added to the packet")
        if msg[1]!=0:
            errors.append("Length is too big")

        # Checks if any errors appeared
        if len(errors)==0:
            logging.info("{} Disconnect - ok.".format(addr))
        else:
            log_parsing_error(addr,msg,"Disconnect",errors)

    def got_unknown(self, client_socket, addr, msg):
        log_parsing_error(addr,msg,"Unknown","Unexpected packet")
    