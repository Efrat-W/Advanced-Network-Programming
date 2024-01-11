import socket
import SMTP_protocol
import base64

IP = '127.0.0.1'
SOCKET_TIMEOUT = 1
SERVER_NAME = "test_SMTP_server.com"

user_names = {"shooki": "abcd1234", "barbie": "helloken"}
curr_user = ""

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
        return error_response()
    client_name = client_message.split()[1]
    return "{}-{} Hello {}\r\n".format(SMTP_protocol.REQUESTED_ACTION_COMPLETED, SERVER_NAME, client_name).encode()


def create_AUTH_LOGIN_response(client_message):
    if not client_message.startswith("AUTH LOGIN"):
        return error_response()
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


def handle_SMTP_client(client_socket):
    # 1 send initial message
    message = create_initial_response()
    client_socket.send(message)

    # 2 receive and send EHLO
    message = client_socket.recv(1024).decode()
    print(message)
    response = create_EHLO_response(message)
    client_socket.send(response)
    if not response.decode().startswith(SMTP_protocol.REQUESTED_ACTION_COMPLETED):
        print("Error client EHLO")
        return

    # 3 receive and send AUTH Login (recv AUTH LOGIN, send encrypted username request)
    message = client_socket.recv(1024).decode()
    print(message)
    response = create_AUTH_LOGIN_response(message)
    client_socket.send(response)
    if not response.decode().startswith(SMTP_protocol.AUTH_INPUT):
        print(response.decode()[3:])
        return
    

    # 4 receive and send USER message
    message = client_socket.recv(1024).decode()
    dec_message = base64.b64decode(message).decode()
    print('{} (decoded: {})'.format(message, dec_message))
    response = create_AUTH_LOGIN_USER_response(dec_message)
    client_socket.send(response)
    if not response.decode().startswith(SMTP_protocol.AUTH_INPUT):
        print(response.decode()[3:])
        return
    
    # 5 password
    message = client_socket.recv(1024).decode()
    dec_message = base64.b64decode(message).decode()
    print('{} (decoded: {})'.format(message, dec_message))
    response = create_AUTH_LOGIN_PASSWRD_response(dec_message)
    client_socket.send(response)
    if not response.decode().startswith(SMTP_protocol.AUTH_SUCCESS):
        print(response.decode()[3:])
        return

    # 6 mail from

    # 7 rcpt to

    # 8 DATA

    # 9 email content
    # The server should keep receiving data, until the sign of end email is received

    # 10 quit

def main():
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
        print("Connection closed")


if __name__ == "__main__":
    # Call the main handler function
    main()