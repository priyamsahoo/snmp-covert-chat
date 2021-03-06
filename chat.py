import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from threading import Thread
import sys
import argparse
from tkinter import *

from snmp_manager import SNMPManager
from my_parser import MyParser
from new_gui import ChatApplication

## MAIN
if __name__ == "__main__":

    try:
        if os.getuid() != 0:
        	print("[!] The covert channel must be run as ROOT.")
        	sys.exit(1)
    except AttributeError:
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
        	print("[!] The covert channel must be run as ROOT.")
        	sys.exit(1)

    # Check needed arguments.
    # parser = argparse.ArgumentParser(description='This script has been developed as part of a practical work on Covert Communication leveraging SNMP services')
    parser = MyParser(description='__ This script has been developed as part of a practical work on Covert Communication leveraging SNMP services __')
    parser._action_groups.pop()
    
    required = parser.add_argument_group('Required arguments')
    optional = parser.add_argument_group('Optional arguments')
    
    required.add_argument('-s', action="store", dest='IP_LOCAL', help='source IP address', required=True)
    required.add_argument('-d', action="store", dest='IP_DESTINATION', help='IP address with which you are going to communicate', required=True)
    
    optional.add_argument('-c', action="store", dest='COMMUNITY', help='SNMP community value')
    
    args = parser.parse_args()

    args = vars(args) # Convert the arguments in dictionary format for easy handling.
    
    # Store parameters in variables.
    ip_destination = args['IP_DESTINATION']
    ip_local = args['IP_LOCAL']
    community = "HELLOWORLD"
    if args['COMMUNITY'] != None:
        community = args['COMMUNITY']
    print("[-] Covert Channel Chat has started.")
    
    # Set the two needed objects.
    snmpConn = SNMPManager(ip_local, ip_destination, community)
    root = Tk()
    # chatInterface = ChatGUI(root, snmpConn)
    chatInterface = ChatApplication(root, snmpConn)
    snmpConn.window = chatInterface
    
    # Start async task to receive messages 
    snmpConn.receiveMsg()
    
    # GUI loop.
    root.mainloop()