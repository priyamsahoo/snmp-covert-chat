import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from threading import Thread
import sys
import argparse
from tkinter import *
from PIL import Image
import string

from snmp_manager import SNMPManager

## GLOBALS
PORT = 162                  # Port to use for communication.
TRAPID = 14452              # ID of the SNMP trap.
SHIFT_CIPHER = 3            # Number of shifts for encryption/decryption.
ALPHABET = string.printable # Alphabet to use in the chat.

## CLASSES
# This class manage the SNMP connection.
# class SNMPManager:
#     def __init__(self, ip_local, ip_destination, community):
#         self.ip_local = ip_local
#         self.ip_destination = ip_destination
#         self.community = community
#         self.master = None
#         self.cipher = CaesarCipher(SHIFT_CIPHER)

#     # This func converts a text in a valid OID.
#     def convertMsg(self, message):
#         oid = "1.3" # All OID sent start with 1.3
#         for count in range (0, len(message)):
#             des = str (ord(message[count]))
#             oid = oid + "." + des
#             je = len(message) - 1
#             if count == je:
#                 oid = oid + ".0" # All OID sent end with .0
#         return oid

#     # This func sends our new message.
#     def sendMsg(self, text):
#         encryptedText = self.cipher.encrypt(text)
#         if (text != "q"):
#             print("* You: " + text.strip())
#         oid = self.convertMsg(encryptedText)
#         packet = IP(dst=self.ip_destination)/UDP(sport=RandShort(),dport=PORT)/SNMP(community=self.community,PDU=SNMPtrapv2(id=TRAPID,varbindlist=[SNMPvarbind(oid=ASN1_OID(oid))]))
#         send(packet, verbose=0)

#     # This func is called when a new SNMP packet arrives.
#     def snmp_values(self):
#         def sndr(pkt):
#             a = " "
#             message = ""
#             pl = pkt[SNMP].community.val
#             od = str(pl)
#             s = pkt[SNMPvarbind].oid.val
#             l = str(s)
#             long = len(l) + 1
#             for i in range (4, len(l)):
#                 if l[i] == ".":
#                     e = chr(int(a))
#                     message += e
#                     a = " "
#                 else:
#                     b = l[i]
#                     a = a + b
#             decryptedText = self.cipher.decrypt(message)
#             self.master.chatContainer.configure(state='normal')
#             if decryptedText == "q":
#                 decryptedText = "- Covert has disconnected -\n"
#                 self.master.chatContainer.insert(END, decryptedText, "bold")
#             else:
#                 self.master.chatContainer.insert(END, " > Covert: ", "bold")
#                 self.master.chatContainer.insert(END, decryptedText)
#                 decryptedText = "Covert: " + decryptedText.strip()
#             print ("* " + decryptedText)
#             self.master.chatContainer.configure(state=DISABLED)
#             self.master.chatContainer.see(END)
#         return sndr

#     # This func is called when a new packet is recieved.
#     def recieveMsg(self):
#         filterstr = "udp and ip src " + self.ip_destination +  " and port " +str(PORT)+ " and ip dst " + self.ip_local
#         sniff(prn=self.snmp_values(), filter=filterstr, store=0, count=0)
#         return

# This class manage the GUI used to chat.
class ChatGUI:
    def __init__(self, master, snmpConn):
        # Set window configurations.
        self.master = master
        master.resizable(width=False, height=False)
        self.master.protocol("WM_DELETE_WINDOW", self.closeConnection)
        self.snmpConn = snmpConn
        path = re.sub(__file__, '', os.path.realpath(__file__))
        # path = path + "/images/CovertMan.png"
        # self.picCovertMan = PhotoImage(file=path)
        # master.tk.call('wm', 'iconphoto', master._w, self.picCovertMan)
        master.title("Covert Channel - SNMP")
        # Create first Frame for rendering.
        frameOne = Frame(self.master, width=500, height=80)
        frameOne.pack(fill="both", expand=True)
        frameOne.grid_propagate(False)
        frameOne.grid_rowconfigure(0, weight=1)
        frameOne.grid_columnconfigure(0, weight=1)
        panel = Label(frameOne)
        # panel.image = self.picCovertMan
        panel.grid(row=0, padx=2, pady=2)
        # Create second Frame for rendering.
        frameTwo = Frame(self.master, width=500, height=300)
        frameTwo.pack(fill="both", expand=True)
        frameTwo.grid_propagate(False)
        frameTwo.grid_rowconfigure(0, weight=1)
        frameTwo.grid_columnconfigure(0, weight=1)
        self.chatContainer = Text(frameTwo, relief="sunken", font=("Myriad Pro", 10), spacing1=10, fg="white", borderwidth=0, highlightthickness=1, bg="black")
        self.chatContainer.tag_configure("bold", font=("Myriad Pro", 10, "bold"))
        self.chatContainer.config(wrap='word', state=DISABLED, highlightbackground="dark slate gray")
        self.chatContainer.grid(row=0, sticky="nsew", padx=5, pady=5)
        self.scrollb = Scrollbar(frameTwo, command=self.chatContainer.yview, borderwidth=0, highlightthickness=0, bg="dark slate gray")
        self.scrollb.grid(row=0, column=1, sticky='ns', padx=2, pady=5)
        self.chatContainer['yscrollcommand'] = self.scrollb.set
        frameThree = Frame(self.master, width=500, height=50)
        frameThree.pack(fill="both", expand=True)
        frameThree.grid_propagate(False)
        frameThree.grid_rowconfigure(0, weight=1)
        frameThree.grid_columnconfigure(0, weight=1)
        self.messageContainer = Text(frameThree, height=2, width=50, font=("Myriad Pro", 10),borderwidth=0, highlightthickness=1)
        self.messageContainer.config(highlightbackground="dark slate gray")
        self.messageContainer.grid(row=0, sticky="nsew", padx=5, pady=5)
        self.sendButton = Button(frameThree, text="Send", command=self.sendClicked, font=("Myriad Pro", 10), bg="black", fg="#d9d9d9", borderwidth=0, highlightthickness=1)
        self.sendButton.config(highlightbackground="dark slate gray",activebackground="dark slate gray")
        self.sendButton.grid(row=0, column=1, sticky='nsew', padx=5, pady=5)

    def validCharacters(self, text):
        if text.strip() == "q":
            return False
        for character in text:
            if character not in ALPHABET:
                return False
        return True

    # This func is called when the SEND button is clicked.
    def sendClicked(self):
        textToSend = self.messageContainer.get("1.0",END)
        if textToSend.strip() and self.validCharacters(textToSend):
            self.messageContainer.delete('1.0', END)
            self.chatContainer.configure(state='normal')
            self.chatContainer.insert(END, " > Tu: ","bold")
            self.chatContainer.insert(END, textToSend)
            self.chatContainer.configure(state=DISABLED)
            self.chatContainer.see(END)
            self.snmpConn.sendMsg(textToSend)

    # This func is called when the CLOSE button is clicked.
    def closeConnection(self):
        print("[-] Covert Channel Chat has ended.")
        self.snmpConn.sendMsg("q")
        self.master.quit()
        sys.exit(0)

    # Format the title label.
    def cycle_label_text(self, event):
        self.label_index += 1
        self.label_index %= len(self.LABEL_TEXT) # wrap around
        self.label_text.set(self.LABEL_TEXT[self.label_index])

# This class encrypts and decrypts the messages.
# class CaesarCipher:
#     def __init__(self, shift):
#         self.alphabet = ALPHABET
#         self.encrypt_alphabet = self.alphabet[shift:] + self.alphabet[:shift]
#         self.decrypt_alphabet = self.alphabet[-shift:] + self.alphabet[:-shift]

#     def encrypt(self, plaintext):
#         table = str.maketrans(self.alphabet, self.encrypt_alphabet)
#         ciphertext = str(plaintext).translate(table)
#         return ciphertext

#     def decrypt(self, ciphertext):
#         table = str.maketrans(self.alphabet, self.decrypt_alphabet)
#         plaintext = str(ciphertext).translate(table)
#         return plaintext

## MAIN
if __name__ == "__main__":
    # Check if the script is run with ROOT.
    # if os.getuid() != 0:
    #     print("[!] The covert channel must be run as ROOT.")
    #     sys.exit(1)

    try:
        if os.getuid() != 0:
        	print("[!] The covert channel must be run as ROOT.")
        	sys.exit(1)
    except AttributeError:
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
        	print("[!] The covert channel must be run as ROOT.")
        	sys.exit(1)


    # Check needed arguments.
    parser = argparse.ArgumentParser(description='This script has been developed as part of a practical work on Network Security I, Master\'s degree in Computer Security at the UBA. It is for academic purposes only.')
    parser._action_groups.pop()
    required = parser.add_argument_group('Required arguments')
    optional = parser.add_argument_group('Optional arguments')
    required.add_argument('-l', action="store", dest='IP_LOCAL', help='source IP address', required=True)
    required.add_argument('-d', action="store", dest='IP_DESTINATION', help='IP address with which you are going to communicate', required=True)
    optional.add_argument('-c', action="store",dest='COMMUNITY', help='SNMP community value')
    args = parser.parse_args()
    args = vars(args) # Convert the arguments in dictionary format for easy handling.
    # Store parameters in variables.
    ip_destination = args['IP_DESTINATION']
    ip_local = args['IP_LOCAL']
    community = "UBAMSI"
    if args['COMMUNITY'] != None:
        community = args['COMMUNITY']
    print("[-] Covert Channel Chat has started.")
    # Set the two needed objects.
    snmpConn = SNMPManager(ip_local, ip_destination, community)
    root = Tk()
    chatInterface = ChatGUI(root, snmpConn)
    snmpConn.master = chatInterface
    # Create the thread that will recieve the SNMP messages.
    thread = Thread(target = snmpConn.recieveMsg)
    thread.daemon = True
    thread.start()
    # GUI loop.
    root.mainloop()