"""EX 2.6 server implementation
   Author: Efrat Weksler
   Date: february 2024
"""
RSA_PUBLIC_KEY = 2731 #prime(randint(17, (protocol.RSA_P - 2) * (protocol.RSP_Q - 2)))
RSA_PRIVATE_KEY = 7171 #protocol.calc_RSA_private_key(RSA_PUBLIC_KEY)


import socket
import protocol


def create_server_rsp(cmd):
    """Based on the command, create a proper response"""
    return "Server response:\t" + cmd


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", protocol.PORT))
    server_socket.listen()
    print("Server is up and running")
    (client_socket, client_address) = server_socket.accept()
    print("Client connected")

    # Diffie Hellman
    # 1 - choose private key
    private_key = protocol.diffie_hellman_choose_private_key()
    # 2 - calc public key
    public_key = protocol.diffie_hellman_calc_public_key(private_key)
    # 3 - interact with client and calc shared secret
    client_socket.send((protocol.create_msg(public_key)).encode())
    valid, client_public = protocol.get_msg(client_socket)
    print(client_public)
    if not valid:
        return client_public
    secret = protocol.diffie_hellman_calc_shared_secret(int(client_public), private_key)


    # RSA
    # Exchange RSA public keys with client
    client_socket.send(protocol.create_msg(RSA_PUBLIC_KEY).encode())
    valid, client_public_RSA = protocol.get_msg(client_socket)

    while True:
        # Receive client's message
        valid_msg, message = protocol.get_msg(client_socket)
        if not valid_msg:
            print("Something went wrong with the length field")

        # Check if client's message is authentic
        # 1 - separate the message and the MAC
        mac = message[-5:]
        message = message[:-5]
        try:
            mac = int(mac)
        except:
            print("Invalid MAC.")
            continue
        # 2 - decrypt the message
        message = protocol.symmetric_encryption(message, secret)
        # 3 - calc hash of message
        hashed = protocol.calc_hash(message)
        # 4 - use client's public RSA key to decrypt the MAC and get the hash
        client_hash = pow(int(mac), int(client_public_RSA), protocol.RSA_P * protocol.RSP_Q)
        # 5 - check if both calculations end up with the same result
        if client_hash != hashed:
            print("Authentication failed.")
            continue

        if message == "EXIT":
            break

        # Create response. The response would be the echo of the client's message
        response = create_server_rsp(message)
        # Encrypt
        # apply symmetric encryption to the server's message
        hashed = protocol.calc_hash(response)
        signature = str(pow(hashed, RSA_PRIVATE_KEY, protocol.RSA_P * protocol.RSP_Q)).zfill(5)

        response = protocol.symmetric_encryption(response, secret)

        # Send to client
        # Combine encrypted user's message to MAC, send to client
        msg = protocol.create_msg(response + signature)
        client_socket.send(msg.encode())

    print("Closing\n")
    client_socket.close()
    server_socket.close()


if __name__ == "__main__":
    main()
