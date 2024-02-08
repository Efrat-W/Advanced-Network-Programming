"""Encrypted sockets implementation
   Author:
   Date:
"""
from random import randint


LENGTH_FIELD_SIZE = 2
PORT = 8820

DIFFIE_HELLMAN_P = 673
DIFFIE_HELLMAN_G = 821

RSA_P = 137
RSP_Q = 151

def calc_RSA_private_key(public_key):
    T = (RSA_P - 1) * (RSP_Q - 1)
    for i in range(T):
        if public_key * i % T == 1:
            return i
    return "Error, no valid private key found."

def symmetric_encryption(input_data, key):
    """Return the encrypted / decrypted data
    The key is 16 bits. If the length of the input data is odd, use only the bottom 8 bits of the key.
    Use XOR method"""
    key_lo = key & 0x00FF 
    key_hi = (key & 0xFF00) >> 8
    key = [key_hi, key_lo]
    #key = [str(key_hi).encode(), str(key_lo).encode()]
    input_data = input_data.encode()

    data_arr = bytearray((b ^ key[i%2]) for i, b in enumerate(input_data))
    return data_arr.decode(errors='replace')

    if len(input_data) % 2:
        key &= 0xFF
    return [data_byte ^ key for data_byte in input_data]


def diffie_hellman_choose_private_key() -> int:
    """Choose a 16 bit size private key """
    return randint(1, 2**16 - 1)


def diffie_hellman_calc_public_key(private_key: int) -> int:
    """G**private_key mod P"""
    return pow(DIFFIE_HELLMAN_G, private_key, DIFFIE_HELLMAN_P)


def diffie_hellman_calc_shared_secret(other_side_public, my_private) -> int:
    """other_side_public**my_private mod P"""
    return pow(other_side_public, my_private, DIFFIE_HELLMAN_P)


def calc_hash(message):
    """Create some sort of hash from the message
    Result must have a fixed size of 16 bits"""
    return sum([ord(c) for c in message]) % (2**16)


def calc_signature(hash, RSA_private_key):
    """Calculate the signature, using RSA alogorithm
    hash**RSA_private_key mod (P*Q)"""
    return pow(hash, RSA_private_key, (RSA_P*RSP_Q)) #% 20687?


def create_msg(data) -> str:
    """Create a valid protocol message, with length field
    For example, if data = data = "hello world",
    then "11hello world" should be returned"""
    data = str(data)
    return str(len(data)).zfill(LENGTH_FIELD_SIZE) + data


def get_msg(my_socket) -> (bool, str):
    """Extract message from protocol, without the length field
       If length field does not include a number, returns False, "Error" """
    length = my_socket.recv(LENGTH_FIELD_SIZE).decode()
    print("Debug length " + length)
    try:
        length = int(length)
        if not length:
            assert ""
        data = my_socket.recv(length).decode()
        return True, data
    except:
        return False, "Error"


