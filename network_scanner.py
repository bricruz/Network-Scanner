import scapy.all as scapy
import optparse


# Step 1 create a packet that is directed to the broadcast MAC address so that it is delivered to all clients on the
# same network the packet asks for a specific IP
# Step 2 send packet and receive response scapy.srp (send and receive packet)
# Step 3 parse the response

def scan(ip):
    # create packet
    # create ARP request asking who has IP address in a specific IP address range
    arp_request = scapy.ARP(pdst = ip)
    # Set destination MAC to broadcast MAC address to make sure request is sent to all clients on network
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    # variable that stores packet to be sent across network
    arp_request_broadcast = broadcast/arp_request
    # send packet, return and store answered responses in variable (srp = send and receive packet)
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    # iterate over answered_list create list of dictionaries of clients' IP and MAC
    clients_list = []
    for element in answered_list:
        client_dict = {"IP": element[1].psrc, "MAC": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def print_result(results_list):
    print("IP\t\t\tMAC Address\n---------------------------------------------------------------")
    for client in results_list:
        print(client["IP"] + "\t\t" + client["MAC"])

def get_ip():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="IP", help="Target IP address")
    (options, arguments) = parser.parse_args()
    if not options.IP:
        parser.error("[-] Please specify a target IP address")
    return options


options = get_ip()
scan_result = scan(options.IP)
print_result(scan_result)