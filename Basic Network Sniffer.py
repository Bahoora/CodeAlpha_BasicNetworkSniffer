#Basic Network Sniffer
import socket
import struct
import textwrap


def printmac():
    host = socket.gethostbyname(socket.gethostname())  # gets ipV4 address of internet
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    # used to create a raw socket for packet manipulation
    conn.bind((host, 0))  # include IP headers
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)  # receives all packets
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    while True:
        rawData, address = conn.recvfrom(65536)
        destMac, srcMac, ethProto, data = ethernet_frame(rawData)
        print("\n Ethernet Frame: ")
        print("Destination: {}, Source: {}, Protocol: {}".format(destMac, srcMac, ethProto))


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
    (src_port,dst_port,sequence,acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L',data[14:])
    offset=(offset_reserved_flags >> 12) * 4# bit shift 12 the entire chunk to get rid of flag and reserved part
    flag_urg= (offset_reserved_flags & 32) >>5
    flag_ack= (offset_reserved_flags & 16) >>4
    flag_psh= (offset_reserved_flags & 8) >>3
    flag_rst= (offset_reserved_flags & 4) >>2
    flag_syn= (offset_reserved_flags & 2) >>1
    flag_fin= (offset_reserved_flags & 1)
    return src_port,dst_port,sequence,acknowledgement, flag_psh, flag_ack, flag_fin, flag_rst, flag_syn, flag_urg, data[offset:]




if __name__ == "__main__":
    printmac()