# python c:\networks\work\networksbook\multiclient\chat_client.py
#Efrat Weksler
import socket
import select
import msvcrt
import chat_protocol as protocol


my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
my_socket.connect((protocol.SERVER_IP, protocol.SERVER_PORT))
print("Pls enter commands\n")
msg = ""
while msg != "EXIT":
    rlist, wlist, xlist = select.select([my_socket], [my_socket], [], 0.1)
    if rlist:
        response = my_socket.recv(protocol.MAX_MSG_LENGTH).decode()
        print("\nServer sent:\t" + response)

    if msvcrt.kbhit():
        ch = msvcrt.getch().decode()
        
        if ch == '\r':
            #send message
            my_socket.send((msg).encode())
            msg = ""
            print('\n')
        else:
            msg += ch
            print(ch, end='', flush=True)

my_socket.send(("").encode()) # EXIT

my_socket.close()

