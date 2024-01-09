import socket
import SMTP_protocol
import base64

IP = '0.0.0.0'
CLIENT_NAME = "client.com"
# Add the minimum required fields to the email
EMAIL_TEXT =   \
    "From: ...\r\n" \
    "To: ..." \
    "Subject: ..." \
    "Date: ..." \
    "Message-ID: ..." \
    ""


def create_EHLO():
    return "EHLO {}\r\n".format(CLIENT_NAME).encode()

def create_AUTH_LOGIN():
    return "AUTH LOGIN\r\n".encode()

def create_AUTH_USERNAME():
    return base64.b64encode("{}\r\n".format(username).encode())

def create_AUTH_PASSWRD():
    return base64.b64encode("{}\r\n".format(password).encode())    

def create_MAIL_FROM():
    return "MAIL FROM: <{}>\r\n".format(CLIENT_NAME).encode()

def create_RCPT_TO():
    return "RCPT TO: <{}>\r\n".format(CLIENT_NAME).encode()

def create_DATA():
    return "DATA\r\n".encode()

def create_QUIT():
    return "QUIT\r\n".encode()


def main():
    # Connect to server
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    my_socket.connect((IP, SMTP_protocol.PORT))

    # 1 server welcome message
    # Check that the welcome message is according to the protocol
    response = my_socket.recv(1024).decode()
    print(response)
    if not response.startswith(SMTP_protocol.SMTP_SERVICE_READY):
        print("Error connecting")
        my_socket.close()
        return

    # 2 EHLO message
    message = create_EHLO()
    my_socket.send(message)
    response = my_socket.recv(1024).decode()
    print(response)
    if not response.startswith(SMTP_protocol.REQUESTED_ACTION_COMPLETED):
        print("Error connecting")
        my_socket.close()
        return

    # 3 AUTH LOGIN
    message = create_AUTH_LOGIN()
    my_socket.send(message)
    response = my_socket.recv(1024).decode()
    print(response)
    if not response.startswith(SMTP_protocol.AUTH_INPUT):
        print("Error connecting")
        my_socket.close()
        return
    
    response = response[3:]
    if base64.b64decode(response).decode().lower() == "username:":
        my_socket.send(create_AUTH_USERNAME())
    
    response = my_socket.recv(1024).decode()[3:]
    if base64.b64decode(response).decode().lower() == "password:":
        my_socket.send(create_AUTH_PASSWRD())

    # 4 User
    user = "barbie"

    # 5 password
    password = "helloken"

    # 6 mail from

    # 7 rcpt to

    # 8 data

    # 9 email content

    # 10 quit

    print("Closing\n")
    my_socket.close()


if __name__ == "__main__":
    main()