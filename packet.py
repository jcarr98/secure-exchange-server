class Packet:
    def __init__(self, pkt=None) -> None:
        # Either create new packet or load existing packet
        self.data = ""
        self.enc = bytes(0)  # An empty bytes object, since encrypted data can't be decoded
        if pkt is not None:
            self.add_data(self.__parse_packet(pkt))
    
    def add_data(self, fields) -> None:
        """Adds fields to the existing data
        
                Parameters:
                    fields (str []): An array of strings to add to the existing packet
        """
        # Go through all provided fields and format into packet
        data = ""
        for i in fields:
            if len(data) == 0:
                data = "{new}".format(new=i)
            else:
                data = "{existing},{new}".format(existing=data, new=i)

        # Update existing data
        self.data = data

    def add_encrypted(self, data):
        self.enc += data

    def send(self) -> bytes:
        """Finishes crafting the packet and returns the bytes to send
        
                Returns:
                    Bytes of created packet
        """
        # Get size of message
        length = len(self.data.encode('utf-8') + self.enc)

        # Add length to message
        final = "{length},{message}".format(length=length, message=self.data)

        # Add encrypted data to message
        final = "{full},".format(full=final).encode('utf-8')  # Add , to separate encrypted data into its own field
        final += self.enc

        # Return final bytes
        return final


    def get_fields(self, idx=None):
        """Gets the fields of the packet

                Parameters:
                    idx (int, optional): The specific index of the field to return
        """
        if idx is None:
            return self.__parse_packet(self.data)
        else:
            return self.__parse_packet(self.data)[idx]

    
    def __parse_packet(self, pkt):
        """Parse the given packet from string or bytes format
        
                Parameters:
                    pkt (str|bytes): The packet to parse

                Return:
                    String representation of packet
        """
        if type(pkt) is bytes:
            pkt = pkt.decode('utf-8')

        # Parse packet
        msg = pkt.split(",")

        # Return array
        return msg