import socket
import SMTP_protocol
import base64

CLIENT_NAME = "client.com"
# Add the minimum required fields to the email
EMAIL_TEXT =   \
    "From: ...\r\n" \
    "..." \
    "..." \
    "..." \
    "..." \
    ""


def create_EHLO():
    return "EHLO {}\r\n".format(CLIENT_NAME).encode()

# More functions should follow, in the form of create_EHLO, for every client message
# ...

def main():
    # Connect to server

    # 1 server welcome message
    # Check that the welcome message is according to the protocol

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