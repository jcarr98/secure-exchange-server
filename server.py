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
from packet import Packet
import crypto

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
        data = self.__recv_pkt(connection)
        pack = Packet(data)

        if pack.get_fields(0) != "HELLO":
            self.__err("Bad greeting", connection)
            return
        else:
            print("Successful connection from {user}".format(user=client_addr))
    
        # Craft second packet, should be 'HELLO,SecureServer,<public key>'
        publicKey = crypto.get_server_public_key(self.publicName)
        
        # Serialize key
        pem = publicKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        print("Sending my public key to {user}".format(user=client_addr))
        # Create key packet
        pack = Packet("HELLO,SecureServer,{key}".format(key=pem))

        # Send packet
        connection.sendall(pack.send())

        # Wait for second message, should be '<FUNCTION>,<parameters>'
        data = self.__recv_pkt(connection)

        # Decrypt data
        data = crypto.decrypt_rsa(data, crypto.get_server_private_key(self.privateName))

        # Create packet
        pack = Packet(data)

        # Find options
        if pack.get_fields(0) == "REGISTER":
            # Packet should look like REGISTER,<username>,<password>,<pKey>
            print("{user} attempting to register".format(user=client_addr))
            # Enter user into database
            successfulRegister = register(connection, pack.get_fields(1), pack.get_fields(2), pack.get_fields(3))
            
            # Check if entered successfully
            if successfulRegister:
                print("{user} successfully registered as {username}".format(user=client_addr, username=pack.get_fields(1)))
                msg = "DONE,OK"
            else:
                print("{user} failed to register".format(user=client_addr))
                msg = "DONE,ERR"

            # Craft response packet
            pack = Packet(msg)

            connection.sendall(pack.send())
        elif pack.get_fields(0) == "AUTH":
            # Decrypt message
            # Authenticate user
            user = pack.get_fields(1)
            pwd = pack.get_fields(2)

            key = auth(user, pwd)
            if key is None:
                # Bad message
                msg = "BAD"

                # Encrypt message
                msgEnc = crypto.encrypt_rsa(msg, crypto.get_user_public_key(user))

                # Create packet
                pack = Packet()
                pack.add_encrypted(msgEnc)

                connection.sendall(pack.send())
                self.__err("Issue authenticating user.", connection)
                return

            # Create packet
            pack = Packet("OK")

            # Create session key
            key = crypto.generate_fernet()

            # Encrypt key
            safeKey = crypto.encrypt_rsa(key, crypto.get_user_public_key(user))

            # Add session key to packet
            pack.add_encrypted(safeKey)

            # Send message
            connection.sendall(pack.send())
        elif pack.get_fields(0) == "USER":
            # Packet should be USER,<username>
            self.__check_user(pack.get_fields(1), connection)  # Pass info to check method
        else:
            self.__err("Not implemented yet", connection)

        connection.close()
        self.__welcome()

    
    def __check_user(self, user, connection):
        # Access user masterfile
        masterList = None
        with open("{database}/users/masterfile.json".format(database=self.database), "r") as f:
            masterList = json.loads(f.read())
            f.close()
        
        # Check if user exists
        if user in masterList:
            exists = "YES"
        else:
            exists = "NO"

        # Craft response packet
        # Format: USER,<exists>
        pack = Packet("USER,{exists}".format(exists=exists))

        # Send packet to user, end connection
        connection.sendall(pack.send())

    def __recv_pkt(self, connection):
        # Receive first chunk of packet
        pkt = connection.recv(1024)

        # Separate by comma, but can't decode encrypted data
        separator = ",".encode('utf-8')

        # Get length of packet
        length = int(pkt.split(separator, 1)[0].decode('utf-8'))
        
        # Separate data, encode back into bytes to maintain size counter
        data = pkt.split(separator, 1)[1]

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

        return data

    def __err(self, msg, connection):
        print(msg)
        connection.close()
        self.__welcome()