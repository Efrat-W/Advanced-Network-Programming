import socket
import SMTP_protocol
import base64

IP = '127.0.0.1'
MAX_MSG_LENGTH = 1024
CLIENT_NAME = "client.com"

# Add the minimum required fields to the email
EMAIL_TEXT = ""

def is_valid_response(res):
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
    global EMAIL_TEXT
    EMAIL_TEXT = "From: {}\r\n".format(client)
    return "MAIL FROM: <{}>\r\n".format(client).encode()

def create_RCPT_TO(reciver):
    global EMAIL_TEXT
    EMAIL_TEXT += "To: {}\r\n".format(reciver)
    return "RCPT TO: <{}>\r\n".format(reciver).encode()

def create_DATA():
    return "DATA\r\n".encode()

def create_MESSAGE_CONTENT(content = ""):
    global EMAIL_TEXT
    EMAIL_TEXT += "\n" + content + ".\r\n"
    print(EMAIL_TEXT)
    return EMAIL_TEXT.encode()

def create_QUIT():
    return "QUIT\r\n".encode()


def main():
    def quit_connection(log: str = ""):
        print(log + "\nClosing\n")
        my_socket.close()
        return
    
    # Connect to server
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    my_socket.connect((IP, SMTP_protocol.PORT))
    print("connected to server")
    # 1 server welcome message
    # Check that the welcome message is according to the protocol
    response = my_socket.recv(MAX_MSG_LENGTH).decode()
    print(response)
    if not response.startswith(SMTP_protocol.SMTP_SERVICE_READY):
        quit_connection("Error establishing connection with server.")

    # 2 EHLO message
    message = create_EHLO()
    my_socket.send(message)
    response = my_socket.recv(MAX_MSG_LENGTH).decode()
    if not is_valid_response(response):
        quit_connection("Error sending EHLO.")

    # 3 AUTH LOGIN
    message = create_AUTH_LOGIN()
    my_socket.send(message)
    response = my_socket.recv(MAX_MSG_LENGTH).decode()
    if not is_valid_response(response):
        quit_connection("Error initiating AUTH LOGIN sequence.")

    # 4 User
    user = "barbie"
    
    response = response[3:]
    if base64.b64decode(response).decode().lower().startswith("username"):
        #user = input("Input username: ")
        my_socket.send(create_AUTH_USERNAME(user))
    else:
        quit_connection("Failed to deliver username.")
    
    # 5 password
    password = "helloken"

    response = my_socket.recv(MAX_MSG_LENGTH).decode()

    if base64.b64decode(response[3:]).decode().lower().startswith("password"):
        #password = input("Input password: ")
        my_socket.send(create_AUTH_PASSWRD(password))
    else:
        quit_connection("Failed to deliver password.")

    # 6 mail from
    user_name = user + "@jct.co.il"
    my_socket.send(create_MAIL_FROM(user_name))
    response = my_socket.recv(MAX_MSG_LENGTH).decode()
    if not is_valid_response(response):
        quit_connection("Error setting sender")


    # 7 rcpt to
    rcpt_name = "recepient" + "@jct.co.il"
    my_socket.send(create_RCPT_TO(rcpt_name))
    response = my_socket.recv(MAX_MSG_LENGTH).decode()
    if not is_valid_response(response):
        quit_connection("Error setting recepient")


    # 8 data
    my_socket.send(create_DATA())
    response = my_socket.recv(MAX_MSG_LENGTH).decode()
    if not is_valid_response(response):
        quit_connection("Failed to initiate data sending sequence.")

    # 9 email content
    content = """
Subject: SMTP demo

    Good evening,

    The SMTP demo assignment is complete. Hopefully it's not too messy.

    Thanks for reviewing.
    """
    for i in range(0, len(content), MAX_MSG_LENGTH):
        print(content[i:i+MAX_MSG_LENGTH])
        my_socket.send(create_MESSAGE_CONTENT(content[i:i+MAX_MSG_LENGTH]))
    response = my_socket.recv(MAX_MSG_LENGTH).decode()
    if not is_valid_response(response):
        quit_connection("Failed to deliver email content.")

    # 10 quit
    my_socket.send(create_QUIT())
    response = my_socket.recv(MAX_MSG_LENGTH).decode()
    if not is_valid_response(response):
        quit_connection("Failed to terminate connection correctly.")
    quit_connection("Ending SMTP client sequence.")


if __name__ == "__main__":
    main()