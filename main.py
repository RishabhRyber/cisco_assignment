import sys

import pyshark

def load_packets(filename):
    pack=pyshark.FileCapture(filename,display_filter='dns')
    return pack


def print_details(packet):
    print(f"Report for{packet.dns.qry_name}\n\n")
    print(f"URL Requested:{packet.dns.qry_name}")
    print(f"IP Resolved:{packet.ip.dst}")


    print("\n\n------------------------------------------------------")
def main():
    if len(sys.argv) !=2:
        print("Invalid argument format found")
        quit()
    fileName=sys.argv[1]

    print(fileName)
    cap = load_packets(fileName)
    for i in cap:
        print(i.dns)


main()