import re
import socket
from scapy.all import send, IP, TCP, ICMP, UDP

# Send custom packet function
def send_packet(src_addr: str, src_port: int, dest_addr: str,
                dest_port: int, pkt_type: str, pkt_data: str) -> bool:
    """Sends a packet

    Args:
        src_addr (str): source address
        src_port (int): source port
        dest_addr (str): destination address
        dest_port (int): destination port
        pkt_type (str): packet type
        pkt_data (str): packet data

    Returns:
        bool: Returns True if the packet was sent successfully, False otherwise
    """
    # Type of packet
    if pkt_type == "T":
        pkt = IP(dst=dest_addr, src=src_addr) / \
            TCP(dport=dest_port, sport=src_port)/pkt_data
    # Type of packet
    elif pkt_type == "U":
        pkt = IP(dst=dest_addr, src=src_addr) / \
            UDP(dport=dest_port, sport=src_port)/pkt_data
    # Type of packet
    elif pkt_type == "I":
        pkt = IP(dst=dest_addr, src=src_addr)/ICMP()/pkt_data

    # Return false if the packet type is invalid
    else:
        return False
    # Send the packet
    try:
        # Send the packet and don't print the details
        send(pkt, verbose=False)
        return True
    except:
        return False

# Function to get the IP address of a domain name
def get_ip_addr(domain):
    """Gets the IP address of a domain name

    Args:
        domain (str): The domain name 

    Returns:
        int: The IP address of the domain name
    """
    try:
        # Get the IP address of the domain name
        return socket.gethostbyname(domain)
    # If the domain name is invalid
    except socket.gaierror as error:
        print(f"Error resolving domain name: {error}")
        return None

# Function to get a valid URL from the user
def get_valid_url(getaddr):
    """Gets a valid URL from the user

    Args:
        getaddr (str): Gets the URL from the user

    Returns:
        int: The IP address of the domain name 
    """
    while True:
        # Request user input for the URL
        url = input(getaddr)
        # Regex to validate the URL
        regex = re.compile(
            r'^https?://'  # Either http:// or https://
            r'(?:[a-zA-Z0-9]+\.)*'  # Zero or more subdomains (www.)
            r'[a-zA-Z0-9]+\.'  # Domain name (youtube.)
            r'[a-zA-Z]{2,}', re.IGNORECASE)  # Top-level domain (.com)
        # Check if the URL is valid
        match = regex.match(url)
        # If the URL is valid
        if match:
            # Get the domain name from the URL
            domain_name = url.split('://')[-1]
            # Get the IP address of the domain name
            ip_address = get_ip_addr(domain_name)
            # Return the IP address
            if ip_address:
                return ip_address
        # If the URL is invalid print an error message
        else:
            print(f"{url} is not a valid URL")

# Function to get a valid port number from the user
def get_valid_port(getport):
    """Gets a valid port number from the user

    Args:
        getport (int): Gets the port number from the user

    Returns:
        int: Returns the port number
    """
    while True:
        try:
            # Request user input for the port number
            port = int(input(getport))
            # Check if the port number is between 1 and 65535
            if port > 0 and port < 65536:
                # Return the port number
                return port
            # If the port number is invalid print an error message
            else:
                print("Port number must be between 1 and 65535")
        # If the port number is invalid print an error message
        except ValueError:
            print("Port number must be an integer")

# Function to get a valid packet count from the user
def get_valid_pkt_count():
    """Gets a valid packet count from the user

    Returns:
        int: Returns the packet count
    """
    while True:
        try:
            # Request user input for the packet count
            pkt_count = int(input("No of Packet to send (1-65535): "))
            # Check if the packet count is between 1 and 65535
            if pkt_count > 0 and pkt_count < 65536:
                # Return the packet count
                return pkt_count
            # If the packet count is invalid print an error message
            else:
                print("Packet count must be between 1 and 65535")
        # If the packet count is invalid print an error message
        except ValueError:
            print("Packet count must be an integer")

# Get a valid packet type from the user
def get_valid_pkt_type():
    """Gets a valid packet type from the user

    Returns:
        str: Returns the packet type (T, U or I)
    """
    while True:
        # Request user input for the packet type
        pkt_type = input(
            "Enter Type (T/t) TCP, (U/u) UDP, (I/i) ICMP echo request: ").upper()
        # Check if the packet type is valid
        if pkt_type == "T" or pkt_type == "U" or pkt_type == "I":
            # Return the packet type
            return pkt_type
        # If the packet type is invalid print an error message
        else:
            print("Packet type must be T, U or I")

# Send a custom packet
def send_custom_pkt():
    """Sends a custom packet

    Returns:
        null: Returns the user to the main menu
    """
    print("------------------------")
    print("** Send Custom Packet **")
    print("------------------------")
    # Gets the source address
    src_addr = get_valid_url("Enter Source address of Packet: ")
    # Gets the destination address
    dest_addr = get_valid_url("Enter Destination address of Packet: ")
    # Gets the packet type
    pkt_type = get_valid_pkt_type()
    # If the packet type is TCP or UDP, get the source and destination ports
    if pkt_type == "T" or pkt_type == "U":
        src_port = get_valid_port("Enter Source Port of Packet: ")
        dest_port = get_valid_port("Enter Destination Port of Packet: ")
    # If the packet type is ICMP, set the source and destination ports to 0
    else:
        src_port = 0
        dest_port = 0
    # Gets the packet data
    pkt_data = input(
        "Packet RAW Data (optional, DISM-DISM-DISM-DISM left blank): ")
    # If the packet data is blank, set the packet data to DISM-DISM-DISM-DISM
    if pkt_data == "":
        pkt_data = "DISM-DISM-DISM-DISM"
    # Gets the packet count
    pkt_count = get_valid_pkt_count()
    # Asks the user if they want to start sending the packet
    start_now = input(
        "Enter Y or y to Start, any other inputs to return to main menu: ").upper()
    # If the user selects Y or y, start sending the packet
    if start_now == "Y":
        count = 0
        for i in range(pkt_count):
            send_packet(src_addr, src_port, dest_addr,
                        dest_port, pkt_type, pkt_data)
            count = count + 1
        print(f"{count} packet(s) sent")
        return
    # If the user types anything else, return to the main menu
    else:
        return


# Testing

# send_custom_pkt()
