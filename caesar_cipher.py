import string

ALPHABET = string.printable # Alphabet to use in the chat.

class CaesarCipher:
    def __init__(self, shift):
        self.alphabet = ALPHABET
        self.encrypt_alphabet = self.alphabet[shift:] + self.alphabet[:shift]
        self.decrypt_alphabet = self.alphabet[-shift:] + self.alphabet[:-shift]

    def encrypt(self, plaintext):
        table = str.maketrans(self.alphabet, self.encrypt_alphabet)
        ciphertext = str(plaintext).translate(table)
        return ciphertext

    def decrypt(self, ciphertext):
        table = str.maketrans(self.alphabet, self.decrypt_alphabet)
        plaintext = str(ciphertext).translate(table)
        return plaintext