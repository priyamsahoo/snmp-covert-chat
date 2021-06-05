from tkinter import *
from PIL import Image
import sys
from scapy.all import *

from globals import ALPHABET

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
