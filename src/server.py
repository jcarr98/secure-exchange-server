# Python files
import socket
import os
import sys
import json

# Crypto files
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# My files
from src.register import register
from src.auth import auth
from src.packet import Packet
import src.crypto as crypto
import src.db as db

class SecureExchangeServer:
    def __init__(self):
        # Class variables
        self.SERVER_IP = "127.0.0.1"
        self.SERVER_PORT = 8008
        self.privateName = "serverprivate.pem"
        self.publicName = "serverpublic.pem"
        self.database = "{cwd}/database".format(cwd=os.getcwd())
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self):
        # Load keys from file
        __private = crypto.get_server_private_key()
        public = crypto.get_server_public_key()

        # Check keys exist
        keySuccess = False
        if __private is None or public is None:
            # Check if key generation was successful
            keySuccess = crypto.generate_rsa()
            # If key generation fails, exit
            if not keySuccess:
                raise("Error generating server keys")
            else:
                # If generation is successful, get new keys
                __private = crypto.get_server_private_key()
                public = crypto.get_server_public_key()
            
        # Delete private key from memory as soon as possible
        del __private

        # Start socket
        self.sock.bind((self.SERVER_IP, self.SERVER_PORT))
        self.sock.listen(10)
        while True:
            self.__welcome()

    def __welcome(self):
        # Wait for connection
        print("Waiting for connection...")
        connection, client_addr = self.sock.accept()

        # Attempt handshake
        handshake = self.__handshake(connection, client_addr)

        if not handshake:
            print("Bad handshake from {loc}, be suspicious".format(loc=client_addr))
            return
        
        # Log successful handshake
        print("Successful handshake from {loc}".format(loc=client_addr))

        # Receive request packet
        req, data = self.__recv_pkt(connection)

        # Pass request to hub
        self.__hub(connection, req, data)

        # Job over, close connection and return
        connection.close()
        return

    
    def __handshake(self, connection, client_addr):
        print("Receiving connection from {loc}".format(loc=client_addr))

        # Receive first packet
        # Format: HELLO,SecureClient
        header, data = self.__recv_pkt(connection)
        initPack = Packet("HANDSHAKE", data)

        if initPack.get_fields(0) != "HELLO":
            return False
        else:
            print("Successful hello from {loc}".format(loc=client_addr))

        # Create response message
        # Format: HELLO,SecureServer,<public key>
        publicKey = crypto.get_server_public_key()

        # Serialize key
        pem = publicKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Craft response packet
        respPack = Packet("HANDSHAKE", "HELLO,SecureServer")
        respPack.add_encrypted(pem)

        # Send response packet
        print("Sending my public key to {loc}".format(loc=client_addr))
        print(respPack.send().decode('utf-8'))
        connection.sendall(respPack.send())

        return True

    
    def __hub(self, connection, request, data):
        options = {
            "USER": self.__check_user,
            "REGISTER": register,
            "AUTH": auth,
        }

        # Pass information to correct handler
        action = options.get(request)

        if action is None:
            print("Illegal request")
            return
        else:
            action(connection, data)

        # Job over, end connection and return
        connection.close()
        return

    
    def __check_user(self, connection, data):
        # Data should be encrypted with public RSA key
        try:
            data = crypto.decrypt_rsa(data)
        except:
            print(sys.exc_info())
            return
        
        # Create packet from data
        reqPack = Packet("USER", data)
        # Packet should be:
        # <username>
        user = reqPack.get_fields(0)

        # Check if user exists
        if db.get_valid_user(user):
            exists = "YES"
        else:
            exists = "NO"

        # Craft response packet
        # Format: USER,<exists>
        pack = Packet("USER", exists)

        # Send packet to user, end connection
        connection.sendall(pack.send())

    def __recv_pkt(self, connection):
        # Receive first chunk of packet
        pkt = connection.recv(1024)

        # Separate by comma, but can't decode encrypted data
        separator = ",".encode('utf-8')

        # Get length of header
        headerLength = int(pkt.split(separator, 1)[0].decode('utf-8'))

        try:
            # Get entire header, should not be more than 1024 bytes
            header = pkt[0:headerLength]

            # Header should be in format header_length, data_length, packet_type
            header = header.decode('utf-8').split(",")

            # Get length of data
            length = int(header[1])

            # Get request
            req = header[2]
        except:
            print("Header error")
            return None
        
        # Separate data
        try:
            data = pkt[headerLength+1:]
        except IndexError:
            # If header was exactly 1024 (should never happen)
            data = bytes(0)

        # Get bytes left to collect
        remaining = length - len(data)

        # Keep collecting bytes until there are none left
        while remaining > 0:
            # Collect new data
            newData = connection.recv(1024)
            # Updated bytes remaining
            remaining -= len(newData)
            # Append onto already collected data
            data += newData

        return req, data
