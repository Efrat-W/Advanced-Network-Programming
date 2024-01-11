import socket
import SMTP_protocol
import base64

IP = '127.0.0.1'
CLIENT_NAME = "client.com"

# Add the minimum required fields to the email
EMAIL_TEXT =   \
    "From: ...\r\n" \
    "To: ..." \
    "Subject: ..." \
    "Date: ..." \
    "Message-ID: ..." \
    ""

def check_response(res):
    print(res)
    return not res.startswith(SMTP_protocol.COMMAND_SYNTAX_ERROR) or res.startswith(SMTP_protocol.INCORRECT_AUTH)

def create_EHLO():
    return "EHLO {}\r\n".format(CLIENT_NAME).encode()

def create_AUTH_LOGIN():
    return "AUTH LOGIN\r\n".encode()

def create_AUTH_USERNAME(username):
    base64.b64encode("{}\r\n".format(username).encode())
    res = "{}\r\n".format(base64.b64encode(username.encode()).decode()).encode()
    print(res)
    return res

def create_AUTH_PASSWRD(password):
    return base64.b64encode("{}\r\n".format(password).encode())    

def create_MAIL_FROM(client):
    return "MAIL FROM: <{}>\r\n".format(client).encode()

def create_RCPT_TO(reciver):
    return "RCPT TO: <{}>\r\n".format(reciver).encode()

def create_DATA():
    return "DATA\r\n".encode()

def create_QUIT():
    return "QUIT\r\n".encode()


def main():
    # Connect to server
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    my_socket.connect((IP, SMTP_protocol.PORT))
    print("connected to server")
    # 1 server welcome message
    # Check that the welcome message is according to the protocol
    response = my_socket.recv(1024).decode()
    print(response)
    if not response.startswith(SMTP_protocol.SMTP_SERVICE_READY):
        my_socket.close()

    # 2 EHLO message
    message = create_EHLO()
    my_socket.send(message)
    response = my_socket.recv(1024).decode()
    if not check_response(response):
        #print("Error connecting")
        my_socket.close()
        return

    # 3 AUTH LOGIN
    message = create_AUTH_LOGIN()
    my_socket.send(message)
    response = my_socket.recv(1024).decode()
    if not check_response(response):
        my_socket.close()
        return

    # 4 User
    user = "barbie"
    
    response = response[3:]
    if base64.b64decode(response).decode().lower().startswith("username"):
        #user = input("Input username: ")
        print("DONE USER")
        my_socket.send(create_AUTH_USERNAME(user))
    
    # 5 password
    password = "helloken"

    response = my_socket.recv(1024).decode()

    if base64.b64decode(response[3:]).decode().lower().startswith("password"):
        #password = input("Input password: ")
        print("DONE PASSWRD")
        my_socket.send(create_AUTH_PASSWRD(password))

    # 6 mail from
    my_socket.send(create_MAIL_FROM(CLIENT_NAME))
    response = my_socket.recv(1024).decode()
    if not check_response(response):
        print("Error setting sender")

    # 7 rcpt to
    my_socket.send(create_MAIL_FROM(CLIENT_NAME))
    response = my_socket.recv(1024).decode()
    if not check_response(response):
        print("Error setting recepient")

    # 8 data

    # 9 email content

    # 10 quit

    print("Closing\n")
    my_socket.close()


if __name__ == "__main__":
    main()