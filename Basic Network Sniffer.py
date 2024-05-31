#Basic Network Sniffer
import socket
import struct
import textwrap


TAB_1 = "\t - "
TAB_2 = "\t\t - "
TAB_3 = "\t\t\t - "
TAB_4 = "\t\t\t\t - "

DATA_TAB_1 = "\t "
DATA_TAB_2 = "\t\t "
DATA_TAB_3 = "\t\t\t "
DATA_TAB_4 = "\t\t\t\t "

def printmac():
    host = socket.gethostbyname(socket.gethostname())  # gets ipV4 address of internet
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    # used to create a raw socket for packet manipulation

    while True:
        rawData, address = conn.recvfrom(65536)
        destMac, srcMac, ethProto, data = ethernet_frame(rawData)
        print("\n Ethernet Frame: ")
        print("Destination: {}, Source: {}, Protocol: {}".format(destMac, srcMac, ethProto))

        if ethProto == 8:
            (version, header_length, ttl, proto, src, target, data) = ip_data(data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            #Check ICMP:
            if proto == 1:
                icmp_type, code, checksum, data = icmppacket(data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))

            #Check TCP:
            elif proto == 6: 
                src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcpsegment(data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
                print(TAB_2 + "Flags:")
                print(TAB_3 + 'URG: {}, ACK {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, (data)))

            #Check UDP:
            elif proto == 17:
                src_port, dest_port, length, data = udp_packet(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port:, Length {}'.format(src_port, dest_port, length))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3, data))

            else:
                print(TAB_1 + 'Data:')
                print(format_multi_line(DATA_TAB_2, data))

        else:
            print('Data:')
            print(format_multi_line(DATA_TAB_1, data))



def ethernet_frame(data):
    destMac, srcMac, proto = struct.unpack('! 6s 6s H', data[:14])  # ! is how bytes are arranged on computer
    # first 6bytes is receiver, next 6 bytes is sender, proto is a small unsigned integer.
    # This is from the first 14 bytes from data
    return get_mac(destMac), get_mac(srcMac), socket.htons(proto), data[14:]
    # socket.htons takes your byte and make sure you can read it. Determines if it's little indian or big indian


def get_mac(address):
    # returns formatted mac address ex: AA:BB:CC:DD:EE:FF
    string= map('{:02x}'.format, address)  # formats them with 2 decimals for each one
    return ':'.join(string).upper()  # concatenates all parts of address and makes sure they're all capital


# Unpack IPv4 data
def ip_data(data):
    version_headerlength = data[0]
    version = version_headerlength >> 4  # bit shift 4 to the right
    headerlength = (version_headerlength & 15) * 4  # compare 2 bytes and get the result when both are 1
    # we multiply by 4 to get 4 bits
    timetolive, proto ,src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])  # format data will be unpacked into
    #8x means skip 8 bytes, B means read byte, 4s reads the next 4 bytes as a string
    return  version, headerlength, timetolive, proto, ipv4(src), ipv4(target), data[headerlength:]


# formats source and target into ip format
def ipv4(address):
    return '.'.join(map(str, address))  # takes all chunks and converts them to string and concatenate them with .

#unpack icmp packet
def icmppacket(data): #internet control message protocol
    icmptype, code, checksum = struct.unpack('! B B H',data[:4])

    #grab first 4 bytes from data
    return icmptype, code, checksum, data[4:]

#unpack tcp (Ip address)
def tcpsegment(data):
    (src_port,dst_port,sequence,acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H',data[:14])
    #H stands for 2 bytes and L stands for 4 bytes
    offset=(offset_reserved_flags >> 12) * 4# bit shift 12 the entire chunk to get rid of flag and reserved part
    flag_urg= (offset_reserved_flags & 32) >>5
    flag_ack= (offset_reserved_flags & 16) >>4
    flag_psh= (offset_reserved_flags & 8) >>3
    flag_rst= (offset_reserved_flags & 4) >>2
    flag_syn= (offset_reserved_flags & 2) >>1
    flag_fin= (offset_reserved_flags & 1)
    return src_port,dst_port,sequence,acknowledgement, flag_psh, flag_ack, flag_fin, flag_rst, flag_syn, flag_urg, data[offset:]


def udp_packet(data):
    src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, length, data[8:]


#Formats multi-line data 
def format_multi_line(prefix, string, size=20):
    if isinstance(string, bytes):
        lines = []
        for i in range(0, len(string), size):
            chunk = string[i:i + size]
            hex_part = ' '.join(f'{byte:02x}' for byte in chunk)
            text_part = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in chunk)
            lines.append(f"{prefix} {hex_part.ljust(size * 3)}  {text_part}")
        return '\n'.join(lines)
    
    #The overall purpose of this function is to format byte data in a way that resembles the output of 
    #a typical TCP stream in tools like Wireshark or Burp Suite. It displays both the hexadecimal and 
    #ASCII representations of the byte data in a structured and alligned manner. Adjusting the size 
    #parameter allows you to control the length of each line.



if __name__ == "__main__":
    printmac()