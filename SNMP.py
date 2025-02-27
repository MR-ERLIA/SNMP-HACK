#CODED BY MR ERLIA
import os
import sys
import socket
import ipaddress
from pysnmp.hlapi import *
from datetime import datetime

class Colors:
    kir = '\033[95m'
    kos = '\033[96m'
    DARKkos = '\033[36m'
    tanafos = '\033[94m'
    dishab = '\033[92m'
    toobagh = '\033[93m'
    ferods = '\033[91m'
    dadmizadamhikos = '\033[1m'
    hikos = '\033[4m'
    END = '\033[0m'

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def show_banner():
    print(f"""{Colors.kir}

   *    (           (   (    (             
 (  `   )\ )        )\ ))\ ) )\ )   (      
 )\))( (()/(    (  (()/(()/((()/(   )\     
((_)()\ /(_))   )\  /(_))(_))/(_)|(((_)(   
(_()((_|_))    ((_)(_))(_)) (_))  )\ _ )\  
|  \/  | _ \   | __| _ \ |  |_ _| (_)_\(_) 
| |\/| |   /   | _||   / |__ | |   / _ \   
|_|  |_|_|_\___|___|_|_\____|___| /_/ \_\  
          |_____|                          

{Colors.END}
{Colors.tanafos}       CODED BY: MR_ERLIA{Colors.END}
{Colors.DARKkos}       Telegram: @DARK_MICE{Colors.END}
{Colors.DARKkos}       Github: https://github.com/MR-ERLIA{Colors.END}
""")

def show_menu():
    print(f"""{Colors.dishab}
        [1] HACKING
        [2] BS
        [0] Exit
{Colors.END}""")

def validate_ip(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

def resolve_target(target):
    try:
        if validate_ip(target):
            return target
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"{Colors.ferods}[-] DNS Resolution Failed!{Colors.END}")
        sys.exit(1)

def snmp_get(target, port, community, oids, snmp_version='v2c', timeout=5, retries=2):
    if snmp_version == 'v1':
        mp_model = 0
    elif snmp_version == 'v2c':
        mp_model = 1
    elif snmp_version == 'v3':
        mp_model = 3
        auth_protocol = usmHMACSHAAuthProtocol
        priv_protocol = usmAesCfb128Protocol
        security_engine = SnmpEngine()
        security_data = UsmUserData(
            userName=community,
            authKey='authkey123',
            privKey='privkey123',
            authProtocol=auth_protocol,
            privProtocol=priv_protocol
        )
        return getCmd(
            security_engine,
            security_data,
            UdpTransportTarget((target, port), timeout=timeout, retries=retries),
            ContextData(),
            *oids
        )
    else:
        raise ValueError(f"{Colors.ferods}[-] Unsupported SNMP version: {snmp_version}{Colors.END}")

    return getCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=mp_model),
        UdpTransportTarget((target, port), timeout=timeout, retries=retries),
        ContextData(),
        *oids
    )

def snmp_scan(target, port, community, snmp_version='v2c', timeout=5):
    oids = [
        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)),
        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0)),
        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysContact', 0)),
        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysLocation', 0)),
        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysUpTime', 0)),
        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysServices', 0)),
        ObjectType(ObjectIdentity('IF-MIB', 'ifNumber', 0)),
        ObjectType(ObjectIdentity('IP-MIB', 'ipAdEntAddr')),
        ObjectType(ObjectIdentity('TCP-MIB', 'tcpConnState')),
        ObjectType(ObjectIdentity('HOST-RESOURCES-MIB', 'hrSWRunName')),
    ]

    print(f"\n{Colors.toobagh}[*] Starting SNMP Scan on {target}:{port} (SNMP {snmp_version}){Colors.END}")
    
    try:
        start_time = datetime.now()
        error_indication, error_status, error_index, var_binds = next(
            snmp_get(target, port, community, oids, snmp_version, timeout)
        )
        elapsed = (datetime.now() - start_time).total_seconds()
        
        if error_indication:
            print(f"{Colors.ferods}[-] Error: {error_indication}{Colors.END}")
            return False
            
        if error_status:
            print(f"{Colors.ferods}[-] SNMP Error: {error_status.prettyPrint()}{Colors.END}")
            return False

        print(f"{Colors.dishab}[+] SNMP Scan Completed in {elapsed:.2f}s{Colors.END}")
        print(f"{Colors.kos}{'-'*55}{Colors.END}")
        for var in var_binds:
            oid, value = var
            print(f"{Colors.tanafos}{oid.prettyPrint():<40}{Colors.END} | {value.prettyPrint()}")
        print(f"{Colors.kos}{'-'*55}{Colors.END}")
        return True

    except Exception as e:
        print(f"{Colors.ferods}[-] Critical Error: {str(e)}{Colors.END}")
        return False

def koslis(wordlist_path):
    try:
        with open(wordlist_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Colors.ferods}[-] Wordlist file not found!{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.ferods}[-] File Error: {str(e)}{Colors.END}")
        sys.exit(1)

def bruteforce_community(target, port, wordlist_path, snmp_version='v2c', timeout=3):
    communities = load_wordlist(wordlist_path)
    valid_communities = []
    
    print(f"\n{Colors.toobagh}[*] Starting Bruteforce with {len(communities)} community strings (SNMP {snmp_version}){Colors.END}")
    
    for idx, community in enumerate(communities, 1):
        print(f"{Colors.toobagh}[*] Trying ({idx}/{len(communities)}): {community.ljust(20)}{Colors.END}", end='\r')
        
        if snmp_scan(target, port, community, snmp_version, timeout):
            valid_communities.append(community)
            print(f"{Colors.dishab}[+] Valid Community Found: {community.ljust(20)}{Colors.END}")

    print("\n" + "-"*55)
    if valid_communities:
        print(f"{Colors.dishab}[+] Valid Communities:{Colors.END}")
        for com in valid_communities:
            print(f" - {Colors.tanafos}{com}{Colors.END}")
    else:
        print(f"{Colors.ferods}[-] No valid communities found{Colors.END}")

def main():
    clear_screen()
    show_banner()
    
    while True:
        try:
            show_menu()
            choice = input(f"{Colors.dishab}[+] Select option: {Colors.END}").strip()
            
            if choice == '1':
                target = input(f"{Colors.dishab}[+] Target IP/Host: {Colors.END}").strip()
                port = int(input(f"{Colors.dishab}[+] Port [161]: {Colors.END}") or 161)
                community = input(f"{Colors.dishab}[+] Community [public]: {Colors.END}") or "public"
                snmp_version = input(f"{Colors.dishab}[+] SNMP Version [v2c]: {Colors.END}") or "v2c"
                target_ip = resolve_target(target)
                snmp_scan(target_ip, port, community, snmp_version)
                
            elif choice == '2':
                target = input(f"{Colors.dishab}[+] Target IP/Host: {Colors.END}").strip()
                port = int(input(f"{Colors.dishab}[+] Port [161]: {Colors.END}") or 161)
                wordlist = input(f"{Colors.dishab}[+] Wordlist path: {Colors.END}").strip()
                snmp_version = input(f"{Colors.dishab}[+] SNMP Version [v2c]: {Colors.END}") or "v2c"
                target_ip = resolve_target(target)
                bruteforce_community(target_ip, port, wordlist, snmp_version)
                
            elif choice == '0':
                print(f"\n{Colors.dishab}[+] Exiting...{Colors.END}")
                sys.exit(0)
                
            else:
                print(f"{Colors.ferods}[-] Invalid choice!{Colors.END}")
            
            input(f"\n{Colors.toobagh}[Press Enter to continue...]{Colors.END}")
            clear_screen()
            show_banner()
            
        except KeyboardInterrupt:
            print(f"\n{Colors.ferods}[-] Operation cancelled!{Colors.END}")
            sys.exit(1)
        except ValueError:
            print(f"{Colors.ferods}[-] Invalid port number!{Colors.END}")
            sys.exit(1)

if __name__ == "__main__":
    main()
