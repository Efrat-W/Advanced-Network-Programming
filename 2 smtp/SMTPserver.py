import socket
import SMTP_protocol
import base64

IP = '127.0.0.1'
SOCKET_TIMEOUT = 1
MAX_MSG_LENGTH = 1024
SERVER_NAME = "test_SMTP_server.com"

user_names = {"shooki": "abcd1234", "barbie": "helloken"}
curr_user = ""
sender = ""
recepient = ""

# Fill in the missing code
def create_initial_response():
    return "{} {}\nWelcome to our SMTP server!\r\n".format(SMTP_protocol.SMTP_SERVICE_READY, SERVER_NAME).encode()

def error_response(err="An unkown error has occurred :/"):
    return("{} {}".format(SMTP_protocol.COMMAND_SYNTAX_ERROR, err)).encode()


# Example of how a server function should look like
def create_EHLO_response(client_message):
    """ Check if client message is legal EHLO message
        If yes - returns proper Hello response
        Else - returns proper protocol error code"""
    if not client_message.startswith("EHLO"):
        return error_response("...hello?")
    client_name = client_message.split()[1]
    return "{}-{} Hello {}\r\n".format(SMTP_protocol.REQUESTED_ACTION_COMPLETED, SERVER_NAME, client_name).encode()


def create_AUTH_LOGIN_response(client_message):
    if not client_message.startswith("AUTH LOGIN"):
        return error_response("No AUTH LOGIN instruction")
    return "{} {}\r\n".format(SMTP_protocol.AUTH_INPUT, base64.b64encode("Username:".encode()).decode()).encode()

def create_AUTH_LOGIN_USER_response(client_message):
    global curr_user
    if not client_message in user_names.keys():
        return error_response("Unrecognized user")
    curr_user = client_message
    return "{} {}\r\n".format(SMTP_protocol.AUTH_INPUT, base64.b64encode("Password:".encode()).decode()).encode()

def create_AUTH_LOGIN_PASSWRD_response(client_message):
    if not curr_user or client_message == user_names[curr_user]:
        return error_response("Incorrect password")
    return "{} Authentication succeeded\r\n".format(SMTP_protocol.AUTH_SUCCESS).encode()

def create_MAIL_FROM_response(client_message):
    global sender
    if not client_message.startswith("MAIL FROM"):
        return error_response("No set sender of mail")
    sender = client_message.split(' ')[2]
    print(sender)
    return "{} OK\r\n".format(SMTP_protocol.REQUESTED_ACTION_COMPLETED).encode()

def create_RCPT_TO_response(client_message):
    global recepient
    if not client_message.startswith("RCPT TO"):
        return error_response("No set recepient of mail")
    recepient = client_message.split(' ')[2]
    print(recepient)
    return "{} Accepted\r\n".format(SMTP_protocol.REQUESTED_ACTION_COMPLETED).encode()

def create_DATA_response(client_message):
    if not client_message.startswith("DATA"):
        return error_response("No DATA instruction sent.")
    return '{} Enter message, ending with "." on a line by itself\r\n'.format(SMTP_protocol.ENTER_MESSAGE).encode()

def create_MESSAGE_response(client_message):
    print("last message packet recv:\n" + client_message)
    if not client_message.endswith(".\r\n"):
        return error_response("Failed to receive last packet or the content wasn't sent according to SMTP protocol.")
    return '{} OK\r\n'.format(SMTP_protocol.REQUESTED_ACTION_COMPLETED).encode()

def create_QUIT_response(client_message):
    if not client_message.startswith("QUIT"):
        return error_response("Client didn't quit.")
    return '{} {}\r\n'.format(SMTP_protocol.GOODBYE, SERVER_NAME).encode()


def handle_SMTP_client(client_socket):
    # 1 send initial message
    message = create_initial_response()
    client_socket.send(message)

    # 2 receive and send EHLO
    message = client_socket.recv(MAX_MSG_LENGTH).decode()
    print(message)
    response = create_EHLO_response(message)
    client_socket.send(response)
    if not response.decode().startswith(SMTP_protocol.REQUESTED_ACTION_COMPLETED):
        print("Error client EHLO")
        return

    # 3 receive and send AUTH Login (recv AUTH LOGIN, send encrypted username request)
    message = client_socket.recv(MAX_MSG_LENGTH).decode()
    print(message)
    response = create_AUTH_LOGIN_response(message)
    client_socket.send(response)
    if not response.decode().startswith(SMTP_protocol.AUTH_INPUT):
        print(response.decode()[3:])
        return
    

    # 4 receive and send USER message
    message = client_socket.recv(MAX_MSG_LENGTH).decode()
    dec_message = base64.b64decode(message).decode()
    print('{} (decoded: {})'.format(message, dec_message))
    response = create_AUTH_LOGIN_USER_response(dec_message)
    client_socket.send(response)
    if not response.decode().startswith(SMTP_protocol.AUTH_INPUT):
        print(response.decode()[3:])
        return
    
    # 5 password
    message = client_socket.recv(MAX_MSG_LENGTH).decode()
    dec_message = base64.b64decode(message).decode()
    print('{} (decoded: {})'.format(message, dec_message))
    response = create_AUTH_LOGIN_PASSWRD_response(dec_message)
    client_socket.send(response)
    if not response.decode().startswith(SMTP_protocol.AUTH_SUCCESS):
        print(response.decode()[3:])
        return

    # 6 mail from
    message = client_socket.recv(MAX_MSG_LENGTH).decode()
    print(message)
    response = create_MAIL_FROM_response(message)
    client_socket.send(response)
    if not response.decode().startswith(SMTP_protocol.REQUESTED_ACTION_COMPLETED):
        print(response.decode()[3:])
        return

    # 7 rcpt to
    message = client_socket.recv(MAX_MSG_LENGTH).decode()
    print(message)
    response = create_RCPT_TO_response(message)
    client_socket.send(response)
    if not response.decode().startswith(SMTP_protocol.REQUESTED_ACTION_COMPLETED):
        print(response.decode()[3:])
        return

    # 8 DATA
    message = client_socket.recv(MAX_MSG_LENGTH).decode()
    print(message)
    response = create_DATA_response(message)
    client_socket.send(response)
    if not response.decode().startswith(SMTP_protocol.ENTER_MESSAGE):
        print(response.decode()[3:])
        return

    # 9 email content
    # The server should keep receiving data, until the sign of end email is received
    #end_sign = False
    
    messages = []
    while True:
        print("\npackets recv so far: " + str(len(messages)))
        message = client_socket.recv(MAX_MSG_LENGTH).decode()
        print(message)
        messages += [message]
        print(messages[-1])
        if messages[-1].endswith('.\r\n'):
            break
    
    response = create_MESSAGE_response(messages[-1])
    client_socket.send(response)
    if not response.decode().startswith(SMTP_protocol.REQUESTED_ACTION_COMPLETED):
        print(response.decode()[3:])
        return

    # 10 quit
    message = client_socket.recv(MAX_MSG_LENGTH).decode()
    print(message)
    response = create_QUIT_response(message)
    client_socket.send(response)
    if not response.decode().startswith(SMTP_protocol.GOODBYE):
        print(response.decode()[3:])
        return
    #print("Finished SMTP sequence with client successfully :)")
    #return

def main():
    global curr_user, sender, recepient
    # Open a socket and loop forever while waiting for clients
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((IP, SMTP_protocol.PORT))
    server_socket.listen()
    print("Listening for connections on port {}".format(SMTP_protocol.PORT))

    while True:
        client_socket, client_address = server_socket.accept()
        print('New connection received')
        client_socket.settimeout(SOCKET_TIMEOUT)
        handle_SMTP_client(client_socket)
        # re-initialize global variables
        curr_user = ""
        sender = ""
        recepient = ""
        print("Connection closed")


if __name__ == "__main__":
    # Call the main handler function
    main()