from scapy.all import *

from caesar_cipher import CaesarCipher
from globals import PORT, TRAPID, SHIFT_CIPHER

# This class manage the SNMP connection.
class SNMPManager:
    def __init__(self, ip_local, ip_destination, community):
        self.ip_local = ip_local
        self.ip_destination = ip_destination
        self.community = community
        self.master = None
        self.cipher = CaesarCipher(SHIFT_CIPHER)

    # This func converts a text in a valid OID.
    def convertMsg(self, message):
        oid = "1.3" # All OID sent start with 1.3
        for count in range (0, len(message)):
            des = str (ord(message[count]))
            oid = oid + "." + des
            je = len(message) - 1
            if count == je:
                oid = oid + ".0" # All OID sent end with .0
        return oid

    # This func sends our new message.
    def sendMsg(self, text):
        encryptedText = self.cipher.encrypt(text)
        if (text != "q"):
            print("* You: " + text.strip())
        oid = self.convertMsg(encryptedText)
        packet = IP(dst=self.ip_destination)/UDP(sport=RandShort(),dport=PORT)/SNMP(community=self.community,PDU=SNMPtrapv2(id=TRAPID,varbindlist=[SNMPvarbind(oid=ASN1_OID(oid))]))
        send(packet, verbose=0)

    # This func is called when a new SNMP packet arrives.
    def snmp_values(self):
        def sndr(pkt):
            a = " "
            message = ""
            pl = pkt[SNMP].community.val
            od = str(pl)
            s = pkt[SNMPvarbind].oid.val
            l = str(s)
            long = len(l) + 1
            for i in range (4, len(l)):
                if l[i] == ".":
                    e = chr(int(a))
                    message += e
                    a = " "
                else:
                    b = l[i]
                    a = a + b
            decryptedText = self.cipher.decrypt(message)
            self.master.chatContainer.configure(state='normal')
            if decryptedText == "q":
                decryptedText = "- Covert has disconnected -\n"
                self.master.chatContainer.insert(END, decryptedText, "bold")
            else:
                self.master.chatContainer.insert(END, " > Covert: ", "bold")
                self.master.chatContainer.insert(END, decryptedText)
                decryptedText = "Covert: " + decryptedText.strip()
            print ("* " + decryptedText)
            self.master.chatContainer.configure(state=DISABLED)
            self.master.chatContainer.see(END)
        return sndr

    # This func is called when a new packet is recieved.
    def recieveMsg(self):
        filterstr = "udp and ip src " + self.ip_destination +  " and port " +str(PORT)+ " and ip dst " + self.ip_local
        sniff(prn=self.snmp_values(), filter=filterstr, store=0, count=0)
        return