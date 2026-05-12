from math import log as logarithm
from asn1 import ASN1Formatter
from Crypto.Cipher import AES as AES_cipher
from Crypto.Util.Padding import pad as add_padding, unpad as remove_padding
from Crypto.Hash import SHA256 as SHA256_hash
import calculate_key as ck

def load_file(path):
    try:
        with open(path, "rb") as file:
            return file.read()
    except FileNotFoundError:
        print("Error: Unable to locate file.")
        exit(0)


def save_file(path, content):
    try:
        with open(path, "wb") as file:
            file.write(content)
    except FileNotFoundError:
        print("Error: Cannot write to file.")
        exit(0)


def required_bytes(num):
    return 1 if num == 0 else int(logarithm(num, 256)) + 1


class EncryptionEngine:
    def __init__(self, prime1, prime2):
        self.public_key = 0
        self.private_key = 0
        self.aes_key = 0
        self.init_vector = 0
        self.prime1 = prime1
        self.prime2 = prime2

    def calculate_keys(self):
        self.public_key, self.private_key, self.aes_key, self.init_vector = ck.get_keys(self.prime1, self.prime2)

    def set_keys(self, pub_key, priv_key, aes_key, init_vector):
        self.public_key = pub_key
        self.private_key = priv_key
        self.aes_key = aes_key
        self.init_vector = init_vector

    def load_keys_from_files(self, path="config.json"):
        try:
            pub_key = open('public_key', 'r').read().split('\n')
            priv_key = open('private_key', 'r').read()
            aes_key = open("aes_key", 'r').read()
            iv = open('init_vector', 'r').read()
            self.public_key = [int(pub_key[0]), int(pub_key[1])]
            self.private_key = int(priv_key)
            self.aes_key = int(aes_key).to_bytes(required_bytes(int(aes_key)), "big")
            self.init_vector = int(iv).to_bytes(required_bytes(int(iv)), "big")
        except FileNotFoundError:
            exit()

    def save_asn1_format(self, data, algorithm):
        asn_formatter = ASN1Formatter()
        asn_formatter.append(asn_formatter.int_code, data)
        encoded, length = asn_formatter.finalize(asn_formatter.sequence_code)
        asn_formatter.reset()
        asn_formatter.append(asn_formatter.sequence_code, "")
        encoded, length = asn_formatter.append_at_start(encoded, length)
        asn_formatter.reset()
        asn_formatter.append(asn_formatter.int_code, self.public_key[1])
        asn_formatter.append(asn_formatter.int_code, self.public_key[0])
        asn_formatter.finalize(asn_formatter.sequence_code)
        encoded, length = asn_formatter.append_at_start(encoded, length)
        asn_formatter.reset()
        asn_formatter.append(asn_formatter.utf_string_code, "6d795f6b6579")
        asn_formatter.append(asn_formatter.utf_string_code, algorithm)
        asn_formatter.append_at_start(encoded, length)
        asn_formatter.finalize(asn_formatter.sequence_code)
        encoded, length = asn_formatter.finalize(asn_formatter.set_code)
        if algorithm == "0001":
            asn_formatter.reset()
            asn_formatter.append(asn_formatter.int_code, required_bytes(data))
            asn_formatter.append(asn_formatter.byte_string_code, "1082")
            asn_formatter.finalize(asn_formatter.sequence_code)
            asn_formatter.append_at_end(encoded, length)
        elif algorithm == "0040":
            asn_formatter.reset()
            asn_formatter.append(asn_formatter.sequence_code, "")
            asn_formatter.append_at_end(encoded, length)
        encoded, _ = asn_formatter.finalize(asn_formatter.sequence_code)
        return encoded

    def save_keys_to_files(self, path="config.json"):
        pub_key_file = open('public_key', 'w')
        priv_key_file = open('private_key', 'w')
        aes_key_file = open("aes_key", 'w')
        iv_file = open('init_vector', 'w')
        pub_key_file.write(str(self.public_key[0]) + '\n' + str(self.public_key[1]))
        priv_key_file.write(str(self.private_key))
        aes_key_file.write(str(int.from_bytes(self.aes_key, "big")))
        iv_file.write(str(int.from_bytes(self.init_vector, "big")))

    def aes_encrypt_file(self, input_path, output_path):
        file_content = load_file(input_path)
        aes_cipher = AES_cipher.new(self.aes_key, AES_cipher.MODE_CBC, self.init_vector)
        encrypted_content = aes_cipher.encrypt(add_padding(file_content, 16))
        save_file(output_path, encrypted_content)

    def aes_decrypt_file(self, input_path, output_path):
        file_content = load_file(input_path)
        aes_cipher = AES_cipher.new(self.aes_key, AES_cipher.MODE_CBC, self.init_vector)
        decrypted_content = remove_padding(aes_cipher.decrypt(file_content), 16)
        save_file(output_path, decrypted_content)

    def calculate_hash(self, file_path):
        file_content = load_file(file_path)
        hash_obj = SHA256_hash.new(file_content)
        return int(hash_obj.hexdigest(), 16)


    def process_blocks(self, number, exponent):
        number = str(number)
        output = ""
        buffer = ""
        for char in number:
            if int(buffer + char) < self.public_key[0]:
                buffer += char
            else:
                encrypted_block = pow(int(buffer), exponent, self.public_key[0])
                output += str(encrypted_block)
                buffer = char
        encrypted_block = pow(int(buffer), exponent, self.public_key[0])
        output += str(encrypted_block)
        return int(output).to_bytes(required_bytes(int(output)), "big")

    def rsa_encrypt(self, data):
        if isinstance(data, bytes):
            data = int.from_bytes(data, "big")
        encrypted_data = pow(data, self.public_key[1], self.public_key[0])
        return encrypted_data.to_bytes(required_bytes(encrypted_data), "big")

    def rsa_decrypt(self, data):
        if isinstance(data, bytes):
            data = int.from_bytes(data, "big")
        decrypted_data = pow(data, self.private_key, self.public_key[0])
        return decrypted_data.to_bytes(required_bytes(decrypted_data), "big")
