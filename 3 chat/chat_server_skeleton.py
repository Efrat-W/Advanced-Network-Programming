import socket
import select
import chat_protocol as protocol



def error_response(err=protocol.UNKNOWN_ERROR):
    return "ERROR: {}".format(err)


def name_response(data, clients_names, current_socket):
    if len(data) >= 2:
        name = data[1]
        
        for name_key, socket, in clients_names.items():
            print(clients_names)
            print(name_key, " ", socket)
            if socket is current_socket:
                if name_key == name:
                    return protocol.HELLO("again, " + name)
                else:
                    return error_response(protocol.RE_LOGIN_ATTEMPT)

            elif (not socket is current_socket) and name_key == name:
                return error_response(protocol.DUPLICATE_NAME(name))

        #if not reply:
        clients_names[name] = current_socket
        return protocol.HELLO(name)
    else:
        return error_response(protocol.NULL_COMMAND)
        

def get_names_response(clients_names):
    return " ".join(clients_names.keys())


def msg_response(data, clients_names, current_socket):
    if len(data) >= 3: # all parameters are filled in
        name, msg = data[1], data[2]
        if name not in clients_names.keys():
            return error_response(protocol.UNKNOWN_CLIENT(name)), current_socket
        elif len(msg) > 0:
            for name_key, socket, in clients_names.items():
                if socket is current_socket:
                    sender_client = name_key
                    reply = sender_client + " sent " + msg
                    dest_socket = clients_names[name]
                    return reply, dest_socket
    else:
        return error_response(protocol.EMPTY_MSG), current_socket


def handle_client_request(current_socket, data, clients_names):
    if not data:
        return error_response(protocol.NULL_COMMAND)
    
    dest_socket = current_socket
    data = data.split(' ')
    instr = data[0]
    #print(instr)
    reply = ""
    # NAME <name> will set name. Server will reply error if duplicate
    if instr == "NAME":
        reply = name_response(data, clients_names, current_socket)
        
    # GET_NAMES will get all names
    elif instr == "GET_NAMES":
        reply = get_names_response(clients_names)

    # MSG <NAME> <message> will send message to client name
    elif instr == "MSG":
        reply, dest_socket = msg_response(data, clients_names, current_socket)

    # EXIT will close client
    elif instr == "EXIT":
        data = ""

    else:
        reply = error_response(protocol.UNKNOWN_ERROR)

    return reply, dest_socket


def print_client_sockets(client_sockets):
    for c in client_sockets:
        print("\t", c.getpeername())


def main():
    print("Setting up server...")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((protocol.SERVER_IP, protocol.SERVER_PORT))
    server_socket.listen()
    print("Listening for clients...")
    client_sockets = []
    messages_to_send = []
    clients_names = {}
    while True:
        read_list = client_sockets + [server_socket]
        ready_to_read, ready_to_write, in_error = select.select(read_list, client_sockets, [])
        for current_socket in ready_to_read:
            if current_socket is server_socket:
                client_socket, client_address = server_socket.accept()
                print("New client joined!\n", client_address)
                client_sockets.append(client_socket)
                print_client_sockets(client_sockets)
            else:
                print("New data from client\n")
                try:
                    data = current_socket.recv(protocol.MAX_MSG_LENGTH).decode()
                except ConnectionResetError:
                    error_response(protocol.FORCED_EXIT)
                    data = ""
                
                if data == "":
                    print("Connection closed\n")
                    for entry in clients_names.keys():
                        if clients_names[entry] == current_socket:
                            sender_name = entry
                    try:
                        clients_names.pop(sender_name)
                    except:
                        error_response(protocol.FORCED_EXIT)
                    client_sockets.remove(current_socket)
                    current_socket.close()
                    
                
                else:
                    print(data)
                    (response, dest_socket) = handle_client_request(current_socket, data, clients_names)
                    messages_to_send.append((dest_socket, response))

        # write to everyone (note: only ones which are free to read...)
        for message in messages_to_send:
            current_socket, data = message
            if current_socket in ready_to_write:
                current_socket.send(data.encode())
                messages_to_send.remove(message)


if __name__ == '__main__':
    main()