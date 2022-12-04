#!/usr/bin/python3
# ad-enumerator.py - Windows Active Directory enumeration tool for Linux.
# Copyright (C) 2022 Incendium.
#
# This tool may be used for legal purposes only. Users take full responsibility
# for any actions performed using this tool. The author accepts no liability
# for damage caused by this tool. If these terms are not acceptable to you, then
# you are not permitted to use this tool.
#
# In all other respects the GPL version 2 applies:
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# TO DO 
# - RPC enumerator
# - Kerberos authentication
#
import os
import ldap3
from ldap3 import NTLM
import argparse
import textwrap
import sys
import time
import smbclient
import dns.resolver
import socket
from contextlib import closing

class bcolors:
    """
    Define colors for status output.
    """
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

class ADenumerate:

    def __init__(self, args):
        self.args = args
 
    def run(self):
        """
        Run is a function that will start the initialization for enumerating the protocols that have been specified.
        """

        # Check if there is a target set
        if not self.args.target:
            print(parser.print_help())
            return

        # Check if there is at least one protocol specified
        if not self.args.ldap and not self.args.smb and not self.args.dns and not self.args.all:
            print(f"{bcolors.FAIL}[!]{bcolors.ENDC} Need at least one protocol (-L, -S, -D or -A for all")
            time.sleep(1)
            print(parser.print_help())
            return

        # Check if DontSave argument is set
        if self.args.DontSave:
            self.args.SaveOutput = False

        # Make adenumerator directory if SaveOutput is set to True
        if self.args.SaveOutput:
            if not os.path.exists("adenumerator"):
                os.mkdir("adenumerator")

        # Initialize ldap
        if self.args.ldap and not self.args.all:
            self.init_ldap()

        # Initialize SMB
        if self.args.smb and not self.args.all:
            self.init_smb()
        
        # Initialize DNS
        if self.args.dns and not self.args.all:
            self.init_dns()

        # Initialize all
        if self.args.all:
            self.init_ldap()
            self.init_smb()
            self.init_dns()

    def save_output(self, filename, content):
        """
        Is used to save the output of the enumeration to a specific file in the ./adenumerator directory.
        """
        with open(f'./adenumerator/{filename}', 'w') as outp:
            outp.write(str(content))
            outp.close()

    def try_connection(self, port, protocol):
        """
        Sets up a TCP connection to a port for testing connection.
        """
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(3)
            if sock.connect_ex((self.args.target, port)) == 0:
                print(f"{bcolors.OKGREEN}[+]{bcolors.ENDC} {protocol} port {port} is opened on {self.args.target}")
                return True
            else:
                # Return False
                return False

    def init_ldap(self):    
        """
        Initialize ldap will try to setup a connection to LDAP and enumerate it.
        """
        
        print("[i] Initializing LDAP...")

        # First setup a socket to see if LDAP is running
        # If LDAP runs, continue, else ask for custom port
        port = 3268
        conn = self.try_connection(port, 'LDAP')

        if not conn:
            set_custom_ldap = input(f"{bcolors.FAIL}[!]{bcolors.ENDC} Could not reach LDAP on port 3268, would you like to specify a custom port? [y/N] > ")

            if set_custom_ldap == 'y' or set_custom_ldap == 'Y':
                custom_ldap = int(input(f"{bcolors.OKGREEN}[+]{bcolors.ENDC} Specify LDAP port > "))
            else:
                return

            # Check if port is valid from a range of valid ports
            if int(custom_ldap) not in range(1, 65535):
                print(f"{bcolors.FAIL}[!]{bcolors.ENDC} That is not a valid port")
                return
            
            # Retry connecting to LDAP using a TCP socket
            retry_conn = self.try_connection(custom_ldap, 'LDAP')
            
            if not retry_conn:
                print(f"{bcolors.FAIL}[!]{bcolors.ENDC} Could not reach port {custom_ldap} on {self.args.target} for LDAP")
                return
            else:
                port = custom_ldap

        # Specify server using ldap3
        server = ldap3.Server(self.args.target, port=port, get_info = ldap3.ALL, use_ssl=self.args.SSL, connect_timeout=5)
        server_name = str(server)
        server_name = server_name.replace(' - cleartext', '')

        try:

            # If no password argument has been specified try to connect anonymously.
            if not self.args.password:
                print(f"{bcolors.OKGREEN}[+]{bcolors.ENDC} No credentials specified for LDAP, trying to connect anonymously")
                time.sleep(1)
                connection = ldap3.Connection(server)
                connection.bind()

                # Check if there is some output and return it.
                output = server.info
                if output == None: 
                    print(f"{bcolors.FAIL}[!]{bcolors.ENDC} Could not connect anonymously to", server_name)
                    return
                else:
                    print(f"{bcolors.OKGREEN}[+]{bcolors.ENDC} Succesfully retrieved LDAP server info from", server_name)
                    print(f"{bcolors.OKGREEN}[+]{bcolors.ENDC} Trying to authenticate anonymously to", server_name)
                    time.sleep(1)


            # Else use credentials (NTLM) to authenticate.
            else:
                if self.args.domain:
                    username = f"{self.args.domain}\{self.args.username}"
                    connection = ldap3.Connection(server, username, password=self.args.password, authentication=NTLM)
                else:
                    connection = ldap3.Connection(server, self.args.username, password=self.args.password)

                # Bind to LDAP connection
                connection.bind()

                valid = server.info
                if valid == None: 
                    print(f"{bcolors.FAIL}[!]{bcolors.ENDC} Something went wrong dumping LDAP output, maybe you specified wrong credentials or no domain?")
                    return
                else:
                    print(f"{bcolors.OKGREEN}[+]{bcolors.ENDC} Authenticated to LDAP as {connection.extend.standard.who_am_i()}")

            # Define a variable for the content of server.info
            info = str(server.info)
            base_dn = None
            
            # Use the info variable to see if "CN=Configuration" exists in the variable.
            # If it exists, we wan't to get the Base DN (root) of the domain.
            for line in info.split("\n"):
                if "CN=Configuration" in line:
                    base_dn = line.split(',')
                    base_dn = f"{base_dn[-2]},{base_dn[-1]}"
                    base_dn = base_dn.replace('\n', '')
                    break
                
            # If base_dn still equals None, we will be unable to continue enumerating LDAP.
            if base_dn == None:
                print(f"{bcolors.FAIL }[!]{bcolors.ENDC} Could not retrieve server info from LDAP. Unable to continue with LDAP")
                return

            print("[i] Getting data... ")
            time.sleep(1)

            def getldapdata(query):
                """
                Will use the connection object to search trough the ldap server.
                Needs a query argument to search.
                """

                search_filter = f"(objectClass=*)"
                connection.search(f"CN={query},"+base_dn, search_filter)

                if query == 'Users':
                    if len(connection.response) == 0:
                        return 'AuthError'
                
                print(f"{bcolors.OKGREEN}[+]{bcolors.ENDC} Found {len(connection.response)} {query} trough LDAP")

                output = f"---Begin {query}---" 
                output += '\n'
                for i in connection.response:
                    output += i['dn']
                    output += '\n'
                output += f"---End {query}---" 
                output += '\n'
            
                return output
            
            # Getting users
            users = getldapdata('Users')

            # Check if CN in users output, if not then we are most likely not allowed to authenticate.
            if users == 'AuthError':
                print(f"{bcolors.WARNING }[-]{bcolors.ENDC} Could not authenticate to", server_name)
                output = str(server.info)
            else:
                # Getting computers
                computers = getldapdata('Computers')

                # Getting Domain Users
                domain_users = getldapdata('Domain Users,CN=Users')
                
                # Getting  Administrators
                administrators = getldapdata('Administrators,CN=Builtin')

                # Getting Domain Admins
                d_administrators = getldapdata('Domain Admins,CN=Users')

                output = users + '\n' + computers + '\n'  + domain_users + '\n'  + administrators + '\n'  + d_administrators + '\n' + str(server.info)
            
            # If SaveOutput is set to True, then save the output to ldap.txt
            if self.args.SaveOutput:
                self.save_output('ldap.txt', output)
                print(f"{bcolors.OKGREEN}[+]{bcolors.ENDC} Successfully saved LDAP data to ldap.txt under the adenumerator folder")
            else:
                print(output)

        except Exception as e:
            print(e)
            print("Cannot connect to", server_name)

    
    def init_smb(self):    
        """
        Initialize smb will try to setup a connection to smb and enumerate the shares and users.
        """
        
        print("[i] Initializing SMB....")

        port = 445
        conn = self.try_connection(port, 'SMB')

        if not conn:
            set_custom_smb = input(f"{bcolors.WARNING}[-]{bcolors.ENDC} Could not reach SMB on port 445, would you like to specify a custom port? [y/N] > ")

            if set_custom_smb == 'y' or set_custom_smb == 'Y':
                custom_smb = int(input(f"{bcolors.OKGREEN}[+]{bcolors.ENDC} Specify SMB port > "))
            else:
                return

            # Check if port is valid from a range of valid ports
            if int(custom_smb) not in range(1, 65535):
                print(f"{bcolors.FAIL}[!]{bcolors.ENDC} That is not a valid port")
                return
            
            # Retry connecting to SMB using a TCP socket
            retry_conn = self.try_connection(custom_smb, 'SMB')
            
            if not retry_conn:
                print(f"{bcolors.FAIL}[!]{bcolors.ENDC} Could not reach port {custom_smb} on {self.args.target} for SMB")
                return
            else:
                port = custom_smb

        try:
            # First try to setup a anonymous session if no password argument is set.
            # We will first try to list shares using smbclient.
            if not self.args.password:
                try:
                    print(f"{bcolors.OKGREEN}[+]{bcolors.ENDC} No password set for SMB, trying to list shares anonymously")

                    smb_shares = os.popen(f'smbclient -L \\\\{self.args.target} -U " "%" " 2>/dev/null').read()

                    if "NT_STATUS_LOGON_FAILURE" in smb_shares:
                        print(f"{bcolors.WARNING }[-]{bcolors.ENDC} Could not connect to SMB anonymously")
                        return
                    
                    print(f"{bcolors.OKGREEN}[+]{bcolors.ENDC} Succesfuly connected anonymously to SMB on {self.args.target}")

                    if not self.args.SaveOutput:
                        print(smb_shares)

                except Exception:
                    print(f"{bcolors.WARNING }[-]{bcolors.ENDC} Could not connect to SMB anonymously")
                    return

            else:
                # First check if we have valid credentials

                if self.args.domain:
                    username = f"{self.args.domain}\{self.args.username}"
                else:
                    username = self.args.username
                try:
                    print(f"{bcolors.OKGREEN}[+]{bcolors.ENDC} Trying to connect to SMB as {username}")
                    sess = smbclient.register_session(self.args.target, username=username, password=self.args.password, connection_timeout=10 )

                except Exception:
                    print(f"{bcolors.FAIL}[!]{bcolors.ENDC} Invalid credentials or domain specified")
                    return

                print(f"{bcolors.OKGREEN}[+]{bcolors.ENDC} Succesfully connected to SMB as {username}")

                if not self.args.SaveOutput:
                    os.system(f'smbclient -L \\\\{self.args.target} -U {self.args.username}%{self.args.password}')

                else:
                    smb_shares = os.popen(f'smbclient -L \\\\{self.args.target} -U {self.args.username}%{self.args.password} 2>/dev/null').read()

            # Next, we will try to get a list of usernames using crackmapexec
            if self.args.password:
                if self.args.SaveOutput:
                    smb_users = os.popen(f"crackmapexec smb {self.args.target} -u '{self.args.username}' -p '{self.args.password}' --users").read()

                    print(f"{bcolors.OKGREEN}[+]{bcolors.ENDC} Successfully saved found users to smb.txt under the ./adenumerator directory")
                    
                else:
                    os.system(f"crackmapexec smb {self.args.target} -u '{self.args.username}' -p '{self.args.password}' --users")
            else:
                smb_users = "Cannot list users without credentials"
            
            # Finally save output to file if SaveOutput is not set to False
            if self.args.SaveOutput:
                output = "---begin smb---\n" + smb_shares + "\n" + smb_users + "\n" + "---end smb---"
                self.save_output('smb.txt', output)
                
        except Exception as e:
            print(e)
            print(f"{bcolors.WARNING }[-]{bcolors.ENDC} Invalid credentials for SMB")

    def init_dns(self):    
        """
        Initialize DNS will try to query and enumerate DNS of a Domain Controller if running.
        """

        # First check if the argument domain is set.
        if not self.args.domain:
            print(f"{bcolors.FAIL}[!]{bcolors.ENDC} DNS resolver needs a domain! see --help")
            return

        # First check if we can connect to DNS
        conn = self.try_connection(53, 'DNS')
        if not conn:
            set_custom_dns = input(f"{bcolors.WARNING}[-]{bcolors.ENDC} Could not reach DNS on port 53, would you like to specify a custom port? [y/N] > ")

            if set_custom_dns == 'y' or set_custom_dns == 'Y':
                custom_dns = int(input(f"{bcolors.OKGREEN}[+]{bcolors.ENDC} Specify DNS port > "))
            else:
                return

            # Check if port is valid from a range of valid ports
            if int(custom_dns) not in range(1, 65535):
                print(f"{bcolors.FAIL}[!]{bcolors.ENDC} That is not a valid port")
                return
            
            # Retry connecting to DNS using a TCP socket
            retry_conn = self.try_connection(custom_dns, 'DNS')
            
            if not retry_conn:
                print(f"{bcolors.FAIL}[!]{bcolors.ENDC} Could not reach port {custom_dns} on {self.args.target} for DNS")
                return


        # Enumerate DNS using a dns resolver
        print("[i] Initializing DNS resolver...")     

        my_resolver = dns.resolver.Resolver(configure=False)
        my_resolver.nameservers = [f'{self.args.target}']

        # Specify record types
        record_types = ['A', 'AAAA', 'NS', 'CNAME', 'MX', 'PTR', 'SOA', 'TXT']

        # Loop trough record types and query resolve them to the domain.
        dns_results = []

        for record in record_types:
            try:
                answer = my_resolver.resolve(self.args.domain, record)
                for server in answer:
                    
                    if not self.args.SaveOutput:
                        print(server.to_text())
                    else:
                        dns_results.append(server.to_text())

            # Catch DNS resolver errors
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                print(f"{bcolors.FAIL}[!]{bcolors.ENDC} Domain {self.args.domain} does not exist!")
                return
            except dns.resolver.LifetimeTimeout:
                print(f"{bcolors.FAIL}[!]{bcolors.ENDC} Domain {self.args.domain} does not exist!")
                return
        
        print(f"{bcolors.OKGREEN}[+]{bcolors.ENDC} Succesfully resolved domain")
        
        # Save DNS output to file if argument SaveOutput is set to True
        if self.args.SaveOutput:
            print(f"{bcolors.OKGREEN}[+]{bcolors.ENDC} Saving DNS resolve output to dns.txt under ./adenumerator")
            
            output = ""

            for i in dns_results:
                output += str(i)
                output += '\n'

            self.save_output('dns.txt', output)

if __name__ == '__main__':

    # Define a parser for arguments
    parser = argparse.ArgumentParser(
        description='Active Directory Enumerator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(""" Examples:
            Enumerate ldap anonymously                         ad-enumerator.py -t 10.10.10.10 -L
            Enumerate SMB anonymously                          ad-enumerator.py -t 10.10.10.10 -S
            Enumerate DNS                                      ad-enumerator.py -t 10.10.10.10 -D -d domain.local
            Enumerate everything anonymously                   ad-enumerator.py -t 10.10.10.10 -A
            Enumerate everything using credentials and domain  ad-enumerator.py -t 10.10.10.10 -A -U <username> -p <password> -d <domain>
            Using credentials                                  ad-enumerator.py -t 10.10.10.10 -<protocol> -u <username> -p <password>
            """ ))

    # Define arguments for the parser
    parser.add_argument('-D', '--dns', action='store_true', help='Do use DNS enumeration')
    parser.add_argument('-S', '--smb', action='store_true', help='Do use SMB enumeration')
    parser.add_argument('-L', '--ldap', action='store_true', help='Do use LDAP enumeration')
    parser.add_argument('-A', '--all', action='store_true', default=False, help='Do use all enumeration options')
    parser.add_argument('--SSL', action='store_true', default=False, help='Do use SSL')
    parser.add_argument('-t', '--target', help='Target IP')
    parser.add_argument('-u', '--username', help='Specify username')
    parser.add_argument('-p', '--password', help='Specify password')
    parser.add_argument('-d', '--domain', help='Specify the domain')
    parser.add_argument('-SO', '--SaveOutput', action='store_true', default=True, help='If set (default True), this script will make a directory and save the enumeration output')
    parser.add_argument('-DS', '--DontSave', action='store_true', help='If set, this script will NOT save output but instead print the output')
    args = parser.parse_args()

    # Intro
    intro = """
ad-enumerator.py by Incendium. Please use responsibly.
-------------------------------------------------------------------------
    """

    print(intro)

    # If there is less than 2 arguments, we will print out the help menu.
    if len(sys.argv[1:]) < 2:
        print("ad-enumerator.py [-h] [-u] [-p] [-D DNS] [-S SMB] [-L LDAP] [-A ALL] [-t TARGET IP]")
        print("")
        print(parser.epilog)
        sys.exit(0)

    # Parse arguments to ADenumerate class.
    enumerator = ADenumerate(args)

    # Call the run function in the ADenumerate class.
    enumerator.run()
