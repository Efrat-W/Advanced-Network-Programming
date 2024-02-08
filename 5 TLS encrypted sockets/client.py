"""Encrypted socket client implementation
   Author:
   Date:
"""
RSA_PUBLIC_KEY = 1229 #prime(randint(17, (protocol.RSA_P - 2) * (protocol.RSP_Q - 2)))
RSA_PRIVATE_KEY = 11669 #protocol.calc_RSA_private_key(RSA_PUBLIC_KEY)

import socket
import protocol


def main():
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    my_socket.connect(("127.0.0.1", protocol.PORT))

    # Diffie Hellman
    # 1 - choose private key
    private_key = protocol.diffie_hellman_choose_private_key()
    # 2 - calc public key
    public_key = protocol.diffie_hellman_calc_public_key(private_key)
    # 3 - interact with server and calc shared secret
    my_socket.send((protocol.create_msg(public_key)).encode())
    valid, server_public = protocol.get_msg(my_socket)
    if not valid:
        return server_public #error msg
    secret = protocol.diffie_hellman_calc_shared_secret(int(server_public), private_key)


    # RSA
    # Exchange RSA public keys with server
    my_socket.send(protocol.create_msg(RSA_PUBLIC_KEY).encode())
    valid, server_public_RSA = protocol.get_msg(my_socket)

    while True:
        user_input = input("Enter command\n")
        # Add MAC (signature)
        # 1 - calc hash of user input
        hashed = protocol.calc_hash(user_input)

        # 2 - calc the signature
        signature = str(pow(hashed, RSA_PRIVATE_KEY, protocol.RSA_P * protocol.RSP_Q)).zfill(5)
        
        # Encrypt
        # apply symmetric encryption to the user's input
        user_input = protocol.symmetric_encryption(user_input, secret)

        # Send to server
        # Combine encrypted user's message to MAC, send to server
        msg = protocol.create_msg(user_input + signature)
        my_socket.send(msg.encode())

        if user_input == 'EXIT':
            break

        # Receive server's message
        valid_msg, message = protocol.get_msg(my_socket)
        if not valid_msg:
            print("Something went wrong with the length field")
            continue

        # Check if server's message is authentic
        # 1 - separate the message and the MAC
        mac = message[-5:]
        try:
            mac = int(mac)
        except:
            print("Invalid MAC added.")
            continue
        # 2 - decrypt the message
        message = message[:-5]
        message = protocol.symmetric_encryption(message, secret)
        # 3 - calc hash of message
        hashed = protocol.calc_hash(message)
        # 4 - use server's public RSA key to decrypt the MAC and get the hash
        signature = pow(int(mac), int(server_public_RSA), protocol.RSA_P * protocol.RSP_Q)
        # 5 - check if both calculations end up with the same result
        if signature != hashed:
            print("Authentication failed.")
            print(signature)
            print(mac)
            continue
        # Print server's message
        print(message)

    print("Closing\n")
    my_socket.close()

if __name__ == "__main__":
    main()
