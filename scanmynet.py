# >>>>> TESTADO APENAS EM AMBIENTE KALI LINUX <<<<<<<
# >>>>> NECESSÁRIO SUDO PARA EXECUTAR POR CONTA DA BIBLIOTECA SCAPY <<<<<<<
# ---------------------------------------------------------------------------
# 
#    _____                   __  __         _   _      _   
#   / ____|                 |  \/  |       | \ | |    | |  
#  | (___   ___ __ _ _ __   | \  / |_   _  |  \| | ___| |_ 
#   \___ \ / __/ _` | '_ \  | |\/| | | | | | . ` |/ _ \ __|
#   ____) | (_| (_| | | | | | |  | | |_| | | |\  |  __/ |_ 
#  |_____/ \___\__,_|_| |_| |_|  |_|\__, | |_| \_|\___|\__|
#                                    __/ |                 
#                                   |___/                  
#    
# Software Developed by: Gabriel Freitas
# Matricula: 201520391
#
# Engenharia da Computação - UFSM
#
# >>>>> IMPORTANTE <<<<<
#
# > Use o argumento -s para simular a descoberta de novos IPs na rede.
#
# > Use o argumento -j para pular esta mensagem.)
#
# Todos os comentários do código estão em inglês, porque quero deixa-lo
# no github depois.
#
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# IMPORTS


import scapy.all as scapy
import requests
import argparse
import time
from datetime import datetime
import os

# ---------------------------------------------------------------------------
# GLOBAL VARIABLES

net_id = 0  # NET ID'S
discovered_nets = [] # Array of Discovered Nets

# ---------------------------------------------------------------------------
# ARGS

# Implemented to help future development
def get_args():

    # Initialising Argparse
    parser = argparse.ArgumentParser()

    # Def arguments

    # Default value to scan all network from 10.0.2.1 to 10.0.2.254
    parser.add_argument('-t', '--target', 
                        dest='target', 
                        help='Target IP Address/Adresses.', 
                        required = False, 
                        default = '10.0.2.1/24')

    # Jump Mode
    parser.add_argument('-j', 
                        dest='jump', 
                        const = True, 
                        default = False, 
                        nargs = '?',
                        help='Use to jump inital notes.',
                        required = False)

    # Enter in Simulate Mode
    parser.add_argument('-s', '--simulate_mode', 
                        dest='simulate_mode', 
                        const = True, 
                        default = False, 
                        nargs = '?',
                        help='Simulate new IPs discovers every single scan. The idea is to show that discovered IPs memory, works.',
                        required = False)

    # Enter in Debug Mode
    parser.add_argument('-d', '--debug', 
                        dest='debug_mode', 
                        const = True, 
                        default = False, 
                        nargs = '?',
                        help='Enter in Debug Mode, and show notes.',
                        required = False)
                        

    # Parsing Args to Options
    options = parser.parse_args()

    return options

# ---------------------------------------------------------------------------
# NETWORK SCAN FUNCTION
  
def scan(ip):

    # Some Scarpy used variables
    # hwsrc = Source MAC Address.
    # psrc = Source IP Address.
    # hwdst = Destination MAC Address.
    # pdst = Destination IP Address.
    # dst = Destination Address.
    # ptype = Show protocol type (IPv4 or IPV6)

    # Using Scapy ARP function
    # https://scapy.readthedocs.io/en/latest/usage.html?highlight=arp#arp-ping
    # Sending pdst with ip definied as Arg (Default: 10.0.2.1/24)
    arp_req_frame = scapy.ARP(pdst = ip) 

    # Using Scarpy, we create an Ethernet frame with destination address as ff:ff:... that is the broadcast MAC Address
    # http://deptal.estgp.pt:9090/cisco/ccna1/course/module5/5.1.3.4/5.1.3.4.html
    broadcast_ether_frame = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    
    # Here we're just combining the Broadcast Ethernet Frame with ARP Frame, previously created, and build a "block"
    broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame

    # Now we use scapy.srp() function to send the "block" and listen the responses
    # scapy.srp(combined_frame, response timeout limit, verbose false not show console log)
    answered_list = scapy.srp(broadcast_ether_arp_req_frame, timeout = 1, verbose = False)[0]


    # With answered_list in hands, we can extract these responses using the following function, 
    # and using the Scarpy variables previously described

    result = []

    # Results Array Builder
    for i in range(0,len(answered_list)):

        client_dict = {"dtime" : datetime.now().strftime('%d-%m-%Y %H:%M:%S'), 
                        
                        "ip" : answered_list[i][1].psrc, 
                        
                        "mac" : answered_list[i][1].hwsrc, 
                        
                        "mac_vendor" : get_api_vendor(answered_list[i][1].hwsrc), 
                        
                        "is_router" : is_router(answered_list[i][1].psrc),
                        
                        "id" : None}

        result.append(client_dict)

    return result

# ---------------------------------------------------------------------------
# DATA TREATMENT FUNCTION

def data_treatment(scan_result, simulate_mode):

    # Now we gonna make a data treatment to let we know when new addresses being discovered

    print("\n@@@ SCAN RESULT >BEFORE< CLEAN @@@\n")
    print(scan_result)
    print("\n@@@ @@@ @@@ @@@ @@@ @@@\n")

    # First we call the global variables
    global net_id
    global discovered_nets

    # At first time, we'll just fill the Discovered Net array, and return itself
    if net_id == 0:

        print("\nIT'S THE FIRST TIME TREATMENT\n")

        for result_index in range(0,len(scan_result)):
            net_id += 1
            scan_result[result_index]["id"] = net_id
            discovered_nets.append(scan_result[result_index])

    # After first time, we'll always compare element by element in Result Array vs Already Discovered Array
    # we'll remove idetical values and then append the remains
    else:

        
        identical_ips = [] # In this variable will be armazened the identical IPs that we'll remove after loop
        identical_ips_n = 0 # The total of identical IPs

        for result_index in range(0,len(scan_result)):

            for discovered_index in range(0,len(discovered_nets)):

                if scan_result[result_index]["ip"] == discovered_nets[discovered_index]["ip"]:
                    identical_ips.append(scan_result[result_index]["ip"] ) # We save the identical IPs
                    identical_ips_n += 1 #Increment total of identical indexes                    
                    break;

        # Now we gonna clean the Results array from all identical ip values  
        # Simulate Mode   
        if (simulate_mode):
            for remove in range(identical_ips_n-1):
                scan_result.pop("ip" == identical_ips[remove])  

        # Normal Mode
        else:
            for remove in range(identical_ips_n):
                scan_result.pop("ip" == identical_ips[remove])

        print("\n@@@ SCAN RESULT >AFTER< CLEAN  @@@\n")
        print(scan_result)
        print("\n@@@ @@@ @@@ @@@ @@@ @@@\n")

        print("\n@@@ DISCOVERED NETS >BEFORE< APPEND @@@\n")
        print(discovered_nets)
        print("\n@@@ @@@ @@@ @@@ @@@ @@@\n")


        # And then, finally add to Discovered Nets, any new remaining IP in Results Array
        if scan_result is not None:
            for result_index in range(0,len(scan_result)):
                net_id += 1
                scan_result[result_index]["id"] = net_id
                discovered_nets.append(scan_result[result_index])
        
        print("\n@@@ DISCOVERED NETS >AFTER< APPEND @@@\n")
        print(discovered_nets)
        print("\n@@@ @@@ @@@ @@@ @@@ @@@\n")

    return discovered_nets

# ---------------------------------------------------------------------------
# GETTING LOCAL MAC ADDRESS

# def get_local_mac(self, ip):

#         # get the interface associated with the ip

#         grep_ip = str(ip) + "/" # this is necessary for grep

#         ip_interface = filter_string(str(os.popen("ip addr show" 

#                                         "| grep "+grep_ip+" | awk \'{print $NF}\'").read()))

#         # get interface mac

#         mac = filter_string(str(os.popen("ip link show "+ip_interface+""

#                                         "| awk \'{print $2}\' | tail -n +2").read()))

#         if mac == "":

#             raise ValueError("Could not find MAC addr for local IP: "+str(ip) + " via ip link")

#         return mac
# ---------------------------------------------------------------------------
# GETTING API VENDOR BY MAC ADDRESS

def get_api_vendor(mac):

    url = "https://api.macvendors.com/"

    api_key = " \ -H \"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiIsImp0aSI6IjYwNDI4NTNjLWE2ODEtNGJjMC1hYWEwLTQ4NmViNjg4YzY5MyJ9.eyJpc3MiOiJtYWN2ZW5kb3JzIiwiYXVkIjoibWFjdmVuZG9ycyIsImp0aSI6IjYwNDI4NTNjLWE2ODEtNGJjMC1hYWEwLTQ4NmViNjg4YzY5MyIsImlhdCI6MTYwNTg1NDQyMywiZXhwIjoxOTIwMzUwNDIzLCJzdWIiOiI3OTM0IiwidHlwIjoiYWNjZXNzIn0.0QcT4oFqWzDltiFT2TUfindClv4nCANiJoqtoQgf4xJWz1hBMZTqpLeNcpJWo2qmXaMubLkIWtn59-qVMAc98Q\""

    try:

        response = requests.get(url+mac+api_key)

    except Exception as e:

        print(e)

    if response.status_code != 200:

        vendor = "Unknown"

    else:

        vendor = response.content.decode()

    return vendor

# ---------------------------------------------------------------------------
# IS ROUTER FUNCTION
# This function verify if ip has router's flag on (UG) then return true or false.

def is_router(ip):

    check_flag = os.popen("route -n | grep "+str(ip)+" | awk '{print $4}' | head -1").read()

    return (check_flag == "UG\n")


# ---------------------------------------------------------------------------
# SCREEN CLEAR FUNCTION
  
def clear():

    # for windows
    if os.name == 'nt':
        _ = os.system('cls')
  
    # for mac and linux(here, os.name is 'posix')
    else:
        _ = os.system('clear')

# ---------------------------------------------------------------------------
# PRINTING FUNCTION
  
def display_result(result, scanned_times):

    print("---------------------------------------------------------------------------------------------------\n"
    "SCANNED TIMES = "+str(scanned_times))
    print("---------------------------------------------------------------------------------------------------\n"
            "ID\tDiscovery Time\t\tIP Address\tType\t\tMAC Address\t\tMAC Vendor\n"
            "---------------------------------------------------------------------------------------------------")

    for i in result:
        print("{}\t{}\t{}\t{}\t{}\t{}".format(i["id"],
                                            "("+i["dtime"]+")", 
                                            i["ip"], 
                                            ("Router" if i["is_router"] else "Host"),
                                            "\t"+i["mac"], 
                                            i["mac_vendor"]
                                            ))

# ---------------------------------------------------------------------------
# WELCOME MESSAGE

def welcome_message():
    clear()

    print("---------------------------------------------------------------------------------------------------\n")
    print('''
   _____                   __  __         _   _      _   
  / ____|                 |  \/  |       | \ | |    | |  
 | (___   ___ __ _ _ __   | \  / |_   _  |  \| | ___| |_ 
  \___ \ / __/ _` | '_ \  | |\/| | | | | | . ` |/ _ \ __|
  ____) | (_| (_| | | | | | |  | | |_| | | |\  |  __/ |_ 
 |_____/ \___\__,_|_| |_| |_|  |_|\__, | |_| \_|\___|\__|
                                   __/ |                 
                                  |___/                  
    ''')
    print("Software Developed by: Gabriel Giacomini de Freitas\n")
    print("Matricula: 201520391\n\n")

    print("Engenharia da Computação - UFSM\n\n")

    print(">>>>> IMPORTANTE <<<<<\n\n")

    print("> Use o argumento -s para simular a descoberta de novos IPs na rede.\n\n")

    print("> Use o argumento -j para pular esta mensagem.\n\n\n")

    print("Todos os comentários do código estão em inglês, porque quero deixar este código do github depois.\n\n")


    print("---------------------------------------------------------------------------------------------------\n")

    input("Press any key to continue...")
    input("Make sure you read the text...")


# ---------------------------------------------------------------------------
# MAIN FUNCTION

def main():

    options = get_args()
    scanned_output = scan(options.target)

    if not options.jump:
        welcome_message()


    scanned_times = 1

    while(1):

        scanned_output = scan(options.target)
        treated_data = data_treatment(scanned_output, options.simulate_mode)

        if not options.debug_mode:
            clear()

        display_result(treated_data, scanned_times)
        scanned_times += 1

        time.sleep(1)



# ---------------------------------------------------------------------------

main()

# options = get_args()
# scanned_output = scan(options.target)
# display_result(scanned_output)