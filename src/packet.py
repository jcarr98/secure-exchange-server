class Packet(object):
    def __init__(self, category, pkt=None) -> None:
        # Create new packet
        self.data = ""
        self.category = category
        self.enc = bytes(0)  # An empty bytes object, since encrypted data can't be decoded
        if pkt is not None:  # If text is provided
            self.add_data(self.__parse_packet(pkt))

    
    def create_header(self):
        # Header is:
        # header_length,packet_length,packet_type
        data_len = len(self.data.encode('utf-8'))
        packet_type = self.category
        tempHead = ",{data},{pType}".format(data=data_len, pType=packet_type).encode('utf-8')
        header_len = len(tempHead)
        header_len = len(str(header_len).encode('utf-8') + tempHead) # Header length includes the header_len value

        return "{h},{pl},{pt}".format(h=header_len, pl=data_len, pt=packet_type)
    

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
        # Add comma to current encrypted data
        if len(self.enc) > 0:
            self.enc += ",".encode('utf-8')
            
        self.enc += data


    def send(self) -> bytes:
        """Finishes crafting the packet and returns the bytes to send
        
                Returns:
                    Bytes of created packet
        """
        final = ""

        header = self.create_header()

        # Add header to message
        if len(self.data) > 0:
            final = "{head},{message}".format(head=header, message=self.data)
        else:
            final = "{head}".format(head=header)

        # Add encrypted data to message
        if len(self.enc) > 0:
            final = "{full},".format(full=final).encode('utf-8')  # Add , to separate encrypted data into its own field
            final += self.enc
        else:
            final = final.encode('utf-8')

        # Return final bytes
        return final


    def get_fields(self, idx=None):
        """Gets the fields of the packet

                Parameters:
                    idx (int, optional): The specific index of the field to return

                Returns:
                    Either the specified field or the entire (unencrypted) dataset in packet
        """
        if idx is None:
            return self.__parse_packet(self.data)
        else:
            return self.__parse_packet(self.data)[idx]

    
    def get_encrypted_fields(self, idx=None):
        """Gets the fields of the encrypted parts of the packet

                Parameters:
                idx (int, optional): The specific index of the field to return

                Returns:
                    Either the specified field or the entire (encrypted) dataset in packet
        """
        if idx is None:
            return self.__parse_encrypted()
        else:
            return self.__parse_encrypted()[idx]

    
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

    
    def __parse_encrypted(self):
        if len(self.enc) > 0:
            return self.enc.split(",".encode('utf-8'))
        else:
            return None
