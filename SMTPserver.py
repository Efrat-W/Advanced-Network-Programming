import socket
import SMTP_protocol
import base64

IP = '0.0.0.0'
SOCKET_TIMEOUT = 1
SERVER_NAME = "test_SMTP_server.com"

user_names = {"shooki": "abcd1234", "barbie": "helloken"}

# Fill in the missing code
def create_initial_response():
    pass


# Example of how a server function should look like
def create_EHLO_response(client_message):
    """ Check if client message is legal EHLO message
        If yes - returns proper Hello response
        Else - returns proper protocol error code"""
    if not client_message.startswith("EHLO"):
        return("{}".format(SMTP_protocol.COMMAND_SYNTAX_ERROR)).encode()
    client_name = client_message.split()[1]
    return "{}-{} Hello {}\r\n".format(SMTP_protocol.REQUESTED_ACTION_COMPLETED, SERVER_NAME, client_name).encode()


# More fucntions should follow, in the form of create_EHLO_response, for every server response
# ...


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

    # 3 receive and send AUTH Login

    # 4 receive and send USER message

    # 5 password

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