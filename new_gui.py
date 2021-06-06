from tkinter import *
from PIL import Image
import sys
from scapy.all import *

from globals import ALPHABET

BG_GRAY = "#ABB2B9"
BG_COLOR = "#17202A"
TEXT_COLOR = "#EAECEE"
BG_FOOTER = "#222"
BG_BUTTON = "#FFA630"

#   --secondary-color: #ffa630;
#   --side-nav-background: #eee;
#   --footer-background: #222;

FONT = "Helvetica 12"
FONT_BOLD = "Helvetica 13 bold"

class ChatApplication:

    def __init__(self, window, snmpConn):
        # self.window = Tk()

        self.window = window
        # master.resizable(width=False, height=False)
        self.window.protocol("WM_DELETE_WINDOW", self.closeConnection)
        self.snmpConn = snmpConn

        self._setup_main_window()

    def run(self):
        self.window.mainloop()

    def _setup_main_window(self):
        self.window.title("Chat")
        self.window.resizable(width=False, height=False)
        self.window.configure(width=470, height=550, bg=BG_FOOTER)

        # head label
        head_label = Label(self.window, bg=BG_FOOTER, fg=TEXT_COLOR,
                            text="Covert Channel Chat - SNMP", font=FONT_BOLD, pady=10, padx=2)
        head_label.place(relwidth=1)

        # divider
        line = Label(self.window, width=450, bg=BG_GRAY)
        line.place(rely=0.07, relx=0.025, relheight=0.0001 ,relwidth=0.95)

        # text widget
        self.text_widget = Text(self.window, width=20, height=2, bg=BG_COLOR, fg=TEXT_COLOR,
                                font=FONT, padx=5, pady=5)
        self.text_widget.place(relheight=0.745, relwidth=0.95, rely=0.08, relx=0.025)
        self.text_widget.configure(cursor="arrow", state=DISABLED)

        # scroll bar
        scrollbar = Scrollbar(self.text_widget)
        scrollbar.place(relheight=1, relx=0.974)
        scrollbar.configure(command=self.text_widget.yview)

        # # bottom label
        bottom_label = Label(self.window, bg=BG_FOOTER, height=80)
        bottom_label.place(relwidth=0.95, relx=0.025, rely=0.825)

        # message entry box
        self.msg_entry = Entry(bottom_label, bg="#2C3E50", fg=TEXT_COLOR, font=FONT)
        self.msg_entry.place(relwidth=0.74, relheight=0.04, rely=0.008)
        self.msg_entry.focus()
        self.msg_entry.bind("<Return>", self._on_enter_pressed)

        # send button
        send_button = Button(bottom_label, text="Send", font=FONT_BOLD, width=20, bg=BG_BUTTON,
                            command=lambda: self._on_enter_pressed(None))
        send_button.place(relx=0.76, rely=0.008, relheight=0.04, relwidth=0.24)

    def validCharacters(self, text):
        if text.strip() == "q":
            return False
        for character in text:
            if character not in ALPHABET:
                return False
        return True

    def _on_enter_pressed(self, event):
        msg = self.msg_entry.get()
        if msg.strip() and self.validCharacters(msg):
            self.snmpConn.sendMsg(msg)
        self._insert_message(msg, "You")

    def _insert_message(self, msg, sender):
        if not msg:
            return

        self.msg_entry.delete(0, END)
        msg1 = f"{sender}: {msg}\n\n"
        self.text_widget.configure(state=NORMAL)
        self.text_widget.insert(END, msg1)
        self.text_widget.configure(state=DISABLED)

        self.text_widget.see(END)

    # This func is called when the CLOSE button is clicked.
    def closeConnection(self):
        print("[-] Covert Channel Chat has ended.")
        self.snmpConn.sendMsg("q")
        self.window.quit()
        sys.exit(0)

    # This func is called when the SEND button is clicked.
    # def sendClicked(self):
    #     textToSend = self.messageContainer.get("1.0",END)
    #     if textToSend.strip() and self.validCharacters(textToSend):
    #         self.messageContainer.delete('1.0', END)
    #         self.chatContainer.configure(state='normal')
    #         self.chatContainer.insert(END, " > Tu: ","bold")
    #         self.chatContainer.insert(END, textToSend)
    #         self.chatContainer.configure(state=DISABLED)
    #         self.chatContainer.see(END)
    #         self.snmpConn.sendMsg(textToSend)

if __name__ == "__main__":
    app = ChatApplication()
    app.run()