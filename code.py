import board
import busio
import digitalio
import time
from micropython import const
from adafruit_wiznet5k.adafruit_wiznet5k import WIZNET5K, SNMR_MACRAW, SNMR2_MBBLK, SNMR2_MMBLK, SNMR2_IPV6BLK, SNMR_MF

ETYPE_IPV4 = const(0x0800)
ETYPE_IPV6 = const(0x86DD)
ETYPE_ATALK = const(0x809B)
ETYPE_AARP = const(0x80F3)

# Signature of an EtherTalk packet
MAC_ATALK_SIG = b'\x09\x00\x07'
MAC_ATALK_BCAST = b'\x09\x00\x07\xff\xff\xff'

# My AppleTalk network and node
MY_NETWORK = 20
MY_NODE = 234

def timed_function(f, *args, **kwargs):
    myname = str(f).split(' ')[1]
    def new_func(*args, **kwargs):
        t = time.monotonic_ns()
        result = f(*args, **kwargs)
        delta = time.monotonic_ns() - t
        print('Function {} Time = {:6.3f}ms'.format(myname, delta/1000000))
        return result
    return new_func

@timed_function
def ddp_checksum(data):
    cksum = 0
    for b in data:
        cksum = (cksum + b) & 0xffff
        # Rotate left 1 bit
        cksum = ((cksum << 1) | (cksum >> 15)) & 0xffff
    
    if cksum == 0:
        return 0xffff
    else:
        return cksum



print("Wiznet5k WebClient Test")

cs = digitalio.DigitalInOut(board.GP17)
spi_bus = busio.SPI(board.GP18, MOSI=board.GP19, MISO=board.GP16)

# Initialize ethernet interface with DHCP
eth = WIZNET5K(spi_bus, cs)

print("Chip Version:", eth.chip)
print("MAC Address:", eth.pretty_mac(eth.mac_address))
print("My IP address is:", eth.pretty_ip(eth.ip_address))

eth._debug = False

# Put into MACRAW mode
sock_num = eth.get_socket()

# Open socket
eth.socket_open(sock_num, SNMR_MACRAW, SNMR2_MBBLK|SNMR2_MMBLK|SNMR2_IPV6BLK)

while True:
    # Wait for a packet
    while eth._get_rx_rcv_size(sock_num) == 0:
        continue

    
    # START TIMER HERE

    # Receive the packet
    # Start with 16 bytes containing the frame length,
    # src MAC, dest MAC, and EtherType
    (dataLength, data) = eth.socket_read(sock_num, 16)
    data_mv = memoryview(data)

    # Display packet info: Src MAC, Dest MAC, Length, etc.
    #print ("Src:", eth.pretty_mac(data_mv[8:14]))
    #print ("Dest:", eth.pretty_mac(data_mv[2:8]))
    ethertype = (data[14] << 8) + data[15]
    #print ("EtherType: %04x" % ethertype)

    # Get frame length from first two bytes.
    # The remainging length is frameLength - 16
    frameLength = (data[0] << 8) + data[1]

    # 14 MS
    

    # Get rest of frame
    (dataLength, payload) = eth.socket_read(sock_num, frameLength - 16)
    # print("Payload:", " ".join("%02x" % b for b in payload))
    payload_mv = memoryview(payload)

    # 27 MS

    # Decode an IP packet
    if ethertype == ETYPE_IPV4:
        continue
        # It's an IPv4 packet
        print("Total length:", (payload[2] << 8) + payload[3])
        print("Protocol:", payload[9])
        print("IP src:", eth.pretty_ip(payload[12:16]))
        print("IP dest:", eth.pretty_ip(payload[16:20]))

    elif ethertype == ETYPE_AARP:
        # AARP packet
        print("*** AARP ***")

    elif ethertype == ETYPE_ATALK:
        # AppleTalk packet
        print("*** AppleTalk ***")

    elif ethertype < 0x0800 and payload_mv[0:8] == b'\xaa\xaa\x03\x00\x00\x00\x80\xf3':
        print("*** AARP Packet ***")
        print ("Src:", eth.pretty_mac(data_mv[8:14]))
        print ("Dest:", eth.pretty_mac(data_mv[2:8]))
        print ("EtherType: %04x" % ethertype)
        print("Payload:", " ".join("%02x" % b for b in payload))

        # Construct AARP response packet
        response = bytearray(46)
        response[0:8] = b'\xAA\xAA\x03\x00\x00\x00\x80\xF3'     # SNAP Header
        response[8:10] = b'\x00\x01'    # Type = ethernet
        response[10:12] = b'\x80\x9B'
        response[12] = 6
        response[13] = 4
        response[14:16] = b'\x00\x02'   # Function = response
        response[16:22] = bytes(eth.mac_address)  # Source HW addr
        response[22:26] = bytes([0, 0, MY_NETWORK, MY_NODE])
        response[26:32] = payload_mv[16:22]   # Copy src HW address into destination
        response[32:36] = payload_mv[22:26]   # Copy src proto address into destination
        
        print("Response:", " ".join("%02x" % b for b in response))

        # Assemble into Ethernet frame
        frame = bytearray(len(response) + 14)
        frame[0:6] = data_mv[2:8]       # Copy ethernet address from incoming packet
        frame[6:12] = bytes(eth.mac_address)   # Copy my ethernet address into src field
        frame[12:14] = len(response).to_bytes(2, 'big')
        frame[14:] = response[0:]

        # Queue it up to be sent
        eth.socket_write(0, frame)



    elif ethertype < 0x0800 and payload_mv[0:8] == b'\xaa\xaa\x03\x08\x00\x07\x80\x9b':
        print("*** AppleTalk Data Packet ***")
        #print ("Src:", eth.pretty_mac(data_mv[8:14]))
        #print ("Dest:", eth.pretty_mac(data_mv[2:8]))
        #print ("EtherType: %04x" % ethertype)
        #print("Payload:", " ".join("%02x" % b for b in payload))

        # Verify checksum
        #print("Checksum: %04x" % ddp_checksum(payload[12:34]))

        # START TIMER HERE
        start = time.monotonic_ns()

        
        # Construct AEP response
        response = bytearray(46)
        resp_view = memoryview(response)
        resp_view[0:8] = b'\xAA\xAA\x03\x08\x00\x07\x80\x9B'
        resp_view[8:10] = (26).to_bytes(2, 'big')
        # Checksum in bytes 10-11
        resp_view[12:14] = payload_mv[14:16]      # Copy src network into dest
        resp_view[14:16] = payload_mv[12:14]     # Copy dest network into src
        resp_view[16] = payload_mv[17]           # Copy src node into dest
        resp_view[17] = payload_mv[16]           # Copy dest node into src
        resp_view[18] = payload_mv[19]           # Copy src socket into dest
        resp_view[19] = payload_mv[18]           # Copy dest socket into src
        resp_view[20] = 4                        # DDP type
        resp_view[21] = 2                        # AEP reply
        resp_view[22:34] = payload_mv[22:34]     # Copy AEP data

        resp_view[10:12] = ddp_checksum(resp_view[12:34]).to_bytes(2, 'big')

        # 4 MS

        delta = time.monotonic_ns() - start
        print('Function {} Time = {:6.3f}ms'.format("Echo response", delta/1000000))

       

        #print("Response:", " ".join("%02x" % b for b in response))

        # Assemble into Ethernet frame
        frame = bytearray(len(response) + 14)
        frame[0:6] = data_mv[8:14]       # Copy ethernet address from incoming packet into dest
        frame[6:12] = bytes(eth.mac_address)   # Copy my ethernet address into src field
        frame[12:14] = (34).to_bytes(2, 'big')
        frame[14:] = resp_view[0:]

        # 5 MS

        #print("Frame:", " ".join("%02x" % b for b in frame))

        
        
        

        # Queue it up to be sent
        eth.socket_write(0, frame)

        

        # 40 MS

        

   
