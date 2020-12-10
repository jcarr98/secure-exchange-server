def generate_checksum(packet):
    # Convert packet into bytes
    packet = packet.encode('utf-8')

    # Add up bytes
    total = 0
    for i in range(0, len(packet)):
        total += packet[i]

    # Return as hex string
    return format(total, '05d')

def verify_checksum(msg):
    # Separate message and checksum
    msg = msg.rsplit(",", 1)
    
    # Generate checksum
    newChecksum = generate_checksum(msg[0])

    # Compare the checksums
    return newChecksum == msg[1]