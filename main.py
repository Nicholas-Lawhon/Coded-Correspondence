from abc import ABC, abstractmethod

# Cipher Key - used to encrypt and decrypt messages
ALPHABET_VALUES = {
    'A': 0, 'B': 1, 'C': 2, 'D': 3, 'E': 4, 'F': 5, 'G': 6,
    'H': 7, 'I': 8, 'J': 9, 'K': 10, 'L': 11, 'M': 12,
    'N': 13, 'O': 14, 'P': 15, 'Q': 16, 'R': 17, 'S': 18,
    'T': 19, 'U': 20, 'V': 21, 'W': 22, 'X': 23, 'Y': 24, 'Z': 25
}


# New cipher will take 2 lists of strings, one for the message and one for the keyword.
# Each character has a value from our dictionary.
# For Decrypting, we will subtract the keyword value from the message value.
# For Encrypting, we will add the keyword value to the message value.
# The remaining value will be the new character in the message.

# Don't forget to add functionality that takes the user keyword input and repeats it until it matches the message length.


# Base Class for the Ciphers
class CipherBase(ABC):
    @abstractmethod
    def encrypt(self, message, offset):
        pass

    @abstractmethod
    def decrypt(self, message, offset):
        pass

    @staticmethod
    def check_user_message_values(message):
        """
        Checks the message for a corresponding character in ALPHABET_VALUES.
        Returns the numerical value of the character if it exists.
        If the character does not exist, it returns the character as is.

        Returns: List of numerical values or characters
        """
        message_values = []
        for char in message:
            if char in ALPHABET_VALUES:
                message_values.append(int(ALPHABET_VALUES[char]))
            else:
                message_values.append(char)

        return message_values

    @staticmethod
    def check_user_keyword_values(keyword):
        """
        Checks the keyword for a corresponding character in ALPHABET_VALUES.
        Returns the numerical value of the character if it exists.
        If the character does not exist, it returns the character as is.

        Returns: List of numerical values or characters
        """
        keyword_values = []
        for char in keyword:
            if char in ALPHABET_VALUES:
                keyword_values.append(int(ALPHABET_VALUES[char]))
            else:
                keyword_values.append(char)

        return keyword_values


# Caesar Cipher Class
class CaesarCipher(CipherBase):
    def encrypt(self, message, offset):
        message_values = CipherBase.check_user_message_values(message)
        encrypted_message = []

        for value in message_values:
            if isinstance(value, int):
                value = (value - offset) % 26
                for char, num in ALPHABET_VALUES.items():
                    if num == value:
                        encrypted_message.append(char)
            else:
                encrypted_message.append(value)

        return ''.join(encrypted_message)

    def decrypt(self, message, offset):
        message_values = CipherBase.check_user_message_values(message)
        decrypted_message = []

        for value in message_values:
            if isinstance(value, int):
                value = (value + offset) % 26
                for char, num in ALPHABET_VALUES.items():
                    if num == value:
                        decrypted_message.append(char)
            else:
                decrypted_message.append(value)

        return ''.join(decrypted_message)

    def offset_unknown(self, message):
        """
        Brute forces through all possible offsets to decrypt a message
        """
        for i in range(1, 26):
            print(f"Offset: {i} - {self.decrypt(message, i)}")


# Vigenere Cipher Class
class VigenereCipher(CipherBase):
    def encrypt(self, message, keyword):
        """
        Encrypts a message using the Vigenere cipher.

        Each character in the message and keyword are assigned a numerical value
        using the ALPHABET_VALUES dictionary. The keyword value is then subtracted
        from the corresponding message value, using modulo 26 to stay within the
        alphabet range. The final value's matching character is then appended.
        Any non-alphabetic characters are appended directly without modification.

        Parameters:
        - message (str): The message to encrypt.
        - keyword (str): The keyword used for encryption.

        Returns:
        - str: The encrypted message.
        """
        message_values = CipherBase.check_user_message_values(message)
        keyword_values = CipherBase.check_user_keyword_values(keyword)
        encrypted_message = []

        for i in range(len(keyword_values)):
            if isinstance(keyword_values[i], int) and isinstance(message_values[i], int):
                adjusted_value = (message_values[i] - keyword_values[i]) % 26
                for char, num in ALPHABET_VALUES.items():
                    if num == adjusted_value:
                        encrypted_message.append(char)
                        continue
            else:
                encrypted_message.append(message_values[i])

        return ''.join(encrypted_message)


    def decrypt(self, message, keyword):
        """
        Decrypts a message using the Vigenere cipher.

        Each character in the message and keyword are assigned a numerical value
        using the ALPHABET_VALUES dictionary. The keyword value is then added
        to the corresponding message value, using modulo 26 to stay within the
        alphabet range. The final value's matching character is then appended.
        Any non-alphabetic characters are appended directly without modification.

        Parameters:
        - message (str): The message to decrypt.
        - keyword (str): The keyword used for decryption.

        Returns:
        - str: The decrypted message.
        """
        message_values = CipherBase.check_user_message_values(message)
        keyword_values = CipherBase.check_user_keyword_values(keyword)
        decrypted_message = []

        for i in range(len(message_values)):
            if isinstance(keyword_values[i], int) and isinstance(message_values[i], int):
                adjusted_value = (message_values[i] + keyword_values[i]) % 26
                for char, num in ALPHABET_VALUES.items():
                    if num == adjusted_value:
                        decrypted_message.append(char)
                        continue
            else:
                decrypted_message.append(message_values[i])

        return ''.join(decrypted_message)

    @staticmethod
    def adjust_keyword_length(user_message, user_keyword):
        adjusted_user_keyword = []
        keyword_index = 0

        for char in user_message:
            if char.isalpha():
                adjusted_user_keyword.append(user_keyword[keyword_index])
                keyword_index += 1
                if keyword_index == len(user_keyword):
                    keyword_index = 0
            else:
                adjusted_user_keyword.append(char)

        return adjusted_user_keyword


# Utility Functions
class Utility:
    @staticmethod
    def check_operation_type(user_operation_type):
        """
        Checks if the user wants to Encrypt or Decrypt a message.

        Return True: Encrypt
        Return False: Decrypt
        """
        if user_operation_type in ['E', 'ENCRYPT']:
            return True

        elif user_operation_type in ['D', 'DECRYPT']:
            return False

    @staticmethod
    def check_cipher_type(user_cipher_type):
        """
        Checks if the user wants to use the Caesar or Vigenere cipher.

        Return True: Caesar
        Return False: Vigenere
        """
        if user_cipher_type in ['C', 'CAESAR']:
            return True

        elif user_cipher_type in ['V', 'VIGENERE']:
            return False

    @staticmethod
    def contains_any_digits(message):
        """
        Checks if a message contains any digits.
        """
        return any(char.isdigit() for char in message)


    class UserInputs:
        def __init__(self):
            self.user_cipher_type = self.get_cipher_type()
            self.user_operation_type = self.get_operation_type()
            self.user_message = self.get_user_message()
            self.user_keyword = self.get_user_keyword()
            self.user_offset = None
            if self.user_cipher_type in ['C', 'CAESAR']:
                self.user_offset = self.get_user_offset()

        def get_cipher_type(self) -> object:
            while True:
                user_cipher_type = input("Choose your cipher type. Vigenere or Caesar? (v/c): ").upper()
                if user_cipher_type in ['V', 'VIGENERE', 'C', 'CAESAR']:
                    return user_cipher_type
                else:
                    print("Invalid choice. Please enter (V)igenere or (C)aesar.")

        def get_operation_type(self):
            while True:
                user_operation_type = input("Would you like to Encrypt or Decrypt your message? (e/d): ").upper()
                if user_operation_type in ['E', 'ENCRYPT', 'D', 'DECRYPT']:
                    return user_operation_type
                else:
                    print("Invalid choice. Please enter (E)ncrypt or (D)ecrypt.")

        def get_user_message(self):
            while True:
                user_message = input("Enter Message: ").upper()
                if Utility.contains_any_digits(user_message):
                    print("Invalid message. Please enter a message without any digits.")
                else:
                    return user_message

        def get_user_keyword(self):
            if self.user_cipher_type not in ['V', 'VIGENERE']:
                return None
            while True:
                user_keyword = input("Enter keyword: ").upper()
                if user_keyword.isalpha():
                    user_keyword = VigenereCipher.adjust_keyword_length(self.user_message, user_keyword)
                    return user_keyword
                else:
                    print("Invalid keyword. Please enter a valid alphabetic keyword.")

        def get_user_offset(self):
                if self.user_cipher_type not in ['C', 'CAESAR']:
                    return None
                while True:
                    try:
                        user_offset = int(input("Enter Offset: "))
                        return user_offset
                    except ValueError:
                        print("Invalid offset. Please enter a number.")


def main():
    """
    check_cipher_type() - Checks if the user selected Caesar (True) or Vigenere (False).
    check_operation_type() - Checks if the user wants to Encrypt (True) or Decrypt (False).
    """
    inputs = Utility.UserInputs()
    caesar_cipher = CaesarCipher()
    vigenere_cipher = VigenereCipher()

    if Utility.check_cipher_type(inputs.user_cipher_type):

        if Utility.check_operation_type(inputs.user_operation_type):
            encrypted_caesar_message = caesar_cipher.encrypt(inputs.user_message, inputs.user_offset)
            print(f"Your Encrypted Message: {encrypted_caesar_message}")

        elif not Utility.check_operation_type(inputs.user_operation_type):
            if inputs.user_offset == 0:
                caesar_cipher.offset_unknown(inputs.user_message)
            else:
                decrypted_caesar_message = caesar_cipher.decrypt(inputs.user_message, inputs.user_offset)
                print(f"Your Decrypted Message: {decrypted_caesar_message}")

    elif not Utility.check_cipher_type(inputs.user_cipher_type):

        if Utility.check_operation_type(inputs.user_operation_type):
            encrypted_vigenere_message = vigenere_cipher.encrypt(inputs.user_message, inputs.user_keyword)
            print(f"Your Encrypted Message: {encrypted_vigenere_message}")

        elif not Utility.check_operation_type(inputs.user_operation_type):
            decrypted_vigenere_message = vigenere_cipher.decrypt(inputs.user_message, inputs.user_keyword)
            print(f"Your Decrypted Message: {decrypted_vigenere_message}")


# Start the program
if __name__ == '__main__':
    main()
