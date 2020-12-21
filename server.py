# Python files
import socket
import os
import json

# Crypto files
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# My files
from register import register
from auth import auth
import crypto

class SecureExchangeServer:
    def __init__(self):
        # Class variables
        self.SERVER_IP = "127.0.0.1"
        self.SERVER_PORT = 8008
        self.privateName = "serverprivate.pem"
        self.publicName = "serverpublic.pem"
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self):
        # Load keys from file
        __private = crypto.get_server_private_key(self.privateName)
        public = crypto.get_server_public_key(self.publicName)

        # Check keys exist
        keySuccess = False
        if __private is None or public is None:
            # Check if key generation was successful
            keySuccess = crypto.generate_rsa(self.privateName, self.publicName)
            # If key generation fails, exit
            if not keySuccess:
                raise("Error generating server keys")
            else:
                # If generation is successful, get new keys
                __private = crypto.get_server_private_key("serverprivate.pem")
                public = crypto.get_server_public_key("serverpublic.pem")

        # Start socket
        self.sock.bind((self.SERVER_IP, self.SERVER_PORT))
        self.sock.listen(10)
        self.__welcome()

    def __welcome(self):
        # Wait for connection
        print("Waiting for connection...")
        connection, client_addr = self.sock.accept()

        # Start talking
        self.__talk(connection, client_addr)

    def __talk(self, connection, client_addr):
        """Receive and read data sent by client

                Parameters:
                    connection: The connection with client via tcp
                    client_addr: information about client address
        """
        # Receive first message, should be 'HELLO,SecureClient'
        data = connection.recv(1024).decode('utf-8')

        parsedData = data.split(",")
        if parsedData[0] != "HELLO":
            self.__err("Bad greeting", connection)
            return
        else:
            print("Client connected...")
    
        # Craft second packet, should be 'HELLO,SecureServer,<public key>'
        publicKey = crypto.get_server_public_key(self.publicName)
        
        # Serialize key
        pem = publicKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        print("Sending public key")
        msg = ("HELLO,SecureServer,%s" % pem).encode('utf-8')

        # Send packet
        connection.sendall(msg)

        # Wait for second message, should be '<FUNCTION>,<parameters>'
        data = connection.recv(1024)

        # Decrypt data
        data = crypto.decrypt_rsa(data, crypto.get_server_private_key(self.privateName))

        # Parse data
        parsedData = data.split(",")

        # Find options
        if parsedData[0] == "REGISTER":
            # Packet should look like REGISTER,username,password
            print("User attempting to register")
            # Enter user into database
            successfulRegister = register(connection, parsedData[1], parsedData[2])
            
            # Check if entered successfully
            if successfulRegister:
                msg = "DONE,OK".encode('utf-8')
            else:
                msg = "DONE,ERR".encode('utf-8')

            connection.sendall(msg)
        elif parsedData[0] == "AUTH":
            # Authenticate user
            user = parsedData[1]
            pwd = parsedData[2]

            key = auth(user, pwd)
            if key is None:
                # Bad message
                msg = "BAD"

                # Encrypt message
                msgEnc = crypto.encrypt_rsa(msg, crypto.get_user_public_key(user))

                connection.sendall(msgEnc)
                self.__err("Issue authenticating user.", connection)
            else:
                msg = "OK,%s" % key

            # Encrypt message with user's public key
            msgEnc = crypto.encrypt_rsa(msg, crypto.get_user_public_key(user))

            # Send message
            connection.sendall(msgEnc)
        else:
            self.__err("Not implemented yet", connection)

        connection.close()
        self.__welcome()

    def __err(self, msg, connection):
        print(msg)
        connection.close()
        self.__welcome()