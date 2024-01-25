MAX_MSG_LENGTH = 1024
SERVER_PORT = 5555
SERVER_IP = "127.0.0.1"


def UNKNOWN_CLIENT(name):
    return f"{name} is currently offline, and can't be contacted."

def DUPLICATE_NAME(name):
    return f"An instance of user {name} is currently running on another machine, apparently."

def HELLO(name):
    return f"Hello {name}"

NULL_COMMAND = "No command nor data received."
EMPTY_MSG = "An empty message cannot be sent. (If you want to act as a ghost, try 'Boo!' instead.)"
RE_LOGIN_ATTEMPT = "You cannot change user once logged in. <EXIT> and log in again."
FORCED_EXIT = "The client has forcibly closed the connection."
UNKNOWN_ERROR = "An unkown error has occurred... Try again."