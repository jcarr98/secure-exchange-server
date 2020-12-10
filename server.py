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
import db
import checksum
from register import register

class SecureExchangeServer:
    def __init__(self):
        # Class variables
        self.SERVER_IP = "127.0.0.1"
        self.SERVER_PORT = 8008
        self._private = None
        self.public = None
        self.keyName = "serverRSA.pem"
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self):
        # Load key
        self.__load_key()

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
        print(data)

        parsedData = data.split(",")
        if parsedData[0] != "HELLO":
            self.__err("Bad greeting", connection)
            return
    
        # Craft second packet, should be 'HELLO,SecureServer,<public key>'
        print("Sending public key")
        msg = ("HELLO,SecureServer,%s" % self.__getPublicKey()).encode('utf-8')

        # Send packet
        connection.sendall(msg)

        # Wait for second message, should be '<FUNCTION>,<parameters>'
        data = connection.recv(1024)
        print("data received: %s" % data)

        # Decrypt data
        data = self._private.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        data = data.decode('utf-8')
        print(data)

        # Parse data
        parsedData = data.split(",")

        # Find options
        if parsedData[0] == "REGISTER":
            # Packet should look like REGISTER,username,password
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
            if not self.__auth(user, pwd):
                # Create bad authentication packet
                msg = ("BAD").encode('utf-8')
            else:
                # Generate session key
                key = Fernet.generate_key()

                # Save key to user
                with open("%s/database/users/%s/keys/session.key" % (os.getcwd(), user), "wb") as f:
                    f.write(key)
                    f.close()
                msg = "OK".encode('utf-8')

                # Encrypt message with user's public key

            # Send message
            connection.sendall(msg)
        else:
            self.__err("Not implemented yet", connection)

        connection.close()
        self.__welcome()

    def __auth(self, username, password):
        # Get password from db
        pwd = db.get_password(username)

        # Check if username exists
        if pwd is None:
            return False
        else:
            return password == pwd

    def __err(self, msg, connection):
        print(msg)
        connection.close()
        self.__welcome()

    def __load_key(self):
        files = os.listdir()
        # Check if key exists
        if self.keyName in files:
            # Load key
            print("Key found, loading...")
            with open("%s/%s" % (os.getcwd(), self.keyName), "rb") as f:
                self._private = serialization.load_pem_private_key(f.read(), backend=default_backend(), password=None)
                self.public = self._private.public_key()
                f.close()

            print("Key loaded!")
        else:
            # Create key
            self._private = self.__create_key()
            self.public = self._private.public_key()
            print("No key found... generating new one")

    def __create_key(self):
        # Generate key
        key = rsa.generate_private_key(
            public_exponent=65537,
            backend=default_backend(),
            key_size=2048,
        )

        # Save key
        with open("%s/%s" % (os.getcwd(), self.keyName), "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
            f.close()

        return key

    def __getPublicKey(self):
        return self.public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    def __encrypt_message(self, msg):
        pass