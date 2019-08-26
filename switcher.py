import utils


class Switcher():
    def number_to_packets(self, arg, client_socket, addr, msg):
        func_name = "pack_"+str(arg)
        func = getattr(self, func_name, lambda: "Invalid")
        return func(client_socket, addr, msg)

    def pack_1(self, client_socket, addr, msg):
        position = 0
        length = msg[1]
        protocol_length = int.from_bytes(msg[2:4], "big")
        # Checks version
        if msg[3+protocol_length+1] != 3:
            utils.send_connack(client_socket, addr, 1)
            return

        position = 3+protocol_length+2
        flags = msg[position]
        position += 1
        # Checks if username and password flags are set
        if ((flags >> 7) & 1)*((flags >> 6) & 1) == 0:
            utils.send_connack(client_socket, addr, 5)
            return
        # Stores client ID
        position += 2
        position, client_length, client_id = utils.get_field(position, msg, 2)
        # Checks if will flag is set
        if ((flags >> 2) & 1) == 1:
            position, will_topic_length, will_topic = utils.get_field(
                position, msg, 2)
            position, will_message_length, will_message = utils.get_field(
                position, msg, 2)
        # Stores username and password
        position, user_length, user = utils.get_field(position, msg, 2)
        position, pass_length, password = utils.get_field(position, msg, 2)
        # Sends Connack packet with retcode 5
        utils.send_connack(client_socket, addr, 5)
        client_socket.close()
        utils.logger("Connect", addr, client_id, user, password)

    def pack_2(self):
        print("Connack")

    def pack_3(self):
        print("Publish")

    def pack_4(self):
        print("Puback")

    def pack_5(self):
        print("Pubrec")

    def pack_6(self):
        print("Pubrel")

    def pack_7(self):
        print("Pubcomp")

    def pack_8(self):
        print("Subscribe")

    def pack_9(self):
        print("Suback")

    def pack_10(self):
        print("Unsubscribe")

    def pack_11(self):
        print("Unsuback")

    def pack_12(self):
        print("Pingreq")

    def pack_13(self):
        print("Pingresp")

    def pack_14(self, client_socket, addr, msg):
        utils.logger("Disconnect",addr,)
        
