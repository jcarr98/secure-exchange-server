import sys
from server import SecureExchangeServer

if __name__ == "__main__":
    # Run server
    server = SecureExchangeServer()

    server.start()