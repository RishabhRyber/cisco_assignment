import sys

import pyshark

def load_packets(filename):
    pack=pyshark.FileCapture(filename,display_filter='dns')
    return pack


def print_details(packet):
    print(f"Report for{packet.qry_name}\n\n")
    print(f"URL Requested:{packet.dns.qry_name}")
    print(f"IP Resolved:{packet.ip.dst}")


    print("\n\n------------------------------------------------------")

def print_report(request_response):
    for dic in request_response.values():
        req=dic[0]
        res=dic[1]
        print(f"Summary for {dic[0].id}")
        print(f"URL requested: {req.qry_name}")
        try:
            print(f"IPv4 Resolved to : {res.a_all}")
        except:
            pass
        # print(req,res)



# will return dictionary of list containg dic{indexed by id of packets}[0-req,1-response]  
def request_response_attach(pack):
 
    res=dict()
    for p in pack:
        # Request type
        id=str(p.dns.id)
        # print(p.dns.flags)
        if p.dns.flags=="0x00000100":
            if id in res.keys():
                res[id][0]=p.dns
            else:
                res[id]=[p.dns,10]
        
        # Response type
        elif p.dns.flags=="0x00008180":
            if id in res.keys():
                res[id][1]=p.dns
            else:
                res[id]=[10,p.dns]
    return res

def main():
    if len(sys.argv) !=2:
        print("Invalid argument format found")
        quit()
    fileName=sys.argv[1]
    print(fileName)
    cap = load_packets(fileName)
    request_response = request_response_attach(cap)
    # for i in request_response:
    #     print(request_response[i][1])
    # print_report(request_response)
    print(request_response)
main()