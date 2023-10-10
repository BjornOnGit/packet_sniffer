import socket
import struct
import binascii
import sys
def main():
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except socket.error as e:
        print(f"Socket Creation Error: {str(e)}")
        sys.exit()

    while True:
        try:
            data, addr = sock.recvfrom(65535)
            eth = (data)
            print(eth)

            eth_header = struct.unpack("!6s6s2s", data[:14])
            source_mac = binascii.hexlify(eth_header[0]).decode('utf-8')
            dest_mac = binascii.hexlify(eth_header[1]).decode('utf-8')
            eth_type = eth_header[2].hex()

            if eth.type == 8:
                ip = (eth.data)
                print(ip)
            elif eth.type == 1544:
                arp = (eth.data)
                print(arp)
            elif eth.type == 56710:
                rarp = (eth.data)
                print(rarp)
        
        except KeyboardInterrupt:
            print("Exiting...")
            break
        except Exception as e:
            print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
