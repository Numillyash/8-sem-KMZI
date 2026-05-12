import random
from Crypto.Util.number import getPrime, inverse
import asn1


class ASN1:
    def __init__(self):
        self.encoder = None
        self.decoder = None

    def encode(self, p, g, y, a, b):
        self.encoder = asn1.Encoder()
        self.encoder.start()

        self.encoder.enter(asn1.Numbers.Sequence)
        self.encoder.write(a, asn1.Numbers.Integer)
        self.encoder.write(b, asn1.Numbers.Integer)
        self.encoder.leave()

        self.encoder.enter(asn1.Numbers.Sequence)
        self.encoder.write(y, asn1.Numbers.Integer)
        self.encoder.leave()

        self.encoder.enter(asn1.Numbers.Sequence)
        self.encoder.write(p, asn1.Numbers.Integer)
        self.encoder.write(g, asn1.Numbers.Integer)
        self.encoder.leave()

    def decode(self, data):
        self.decoder = asn1.Decoder()
        self.decoder.start(data)

        self.decoder.enter()
        a = self.decoder.read()[1]
        b = self.decoder.read()[1]
        self.decoder.leave()

        self.decoder.enter()
        y = self.decoder.read()[1]
        self.decoder.leave()

        self.decoder.enter()
        p = self.decoder.read()[1]
        g = self.decoder.read()[1]
        self.decoder.leave()

        return a, b, y, p, g


# Генерация параметров системы (p, g, y, x)
def generate_keys(bit_length=256):
    # Генерация простого числа p
    p = getPrime(bit_length)

    # Выбор первообразного корня g (обычно небольшое целое число)
    g = random.randint(2, p - 2)

    # Закрытый ключ x (случайное число от 1 до p-2)
    x = random.randint(1, p - 2)

    # Открытый ключ y = g^x mod p
    y = pow(g, x, p)

    return p, g, y, x


# Шифрование сообщения
def encrypt(message, p, g, y):
    # Преобразование строки сообщения в число
    m = int.from_bytes(message.encode('utf-8'), 'big')

    # Генерация случайного числа k
    k = random.randint(1, p - 2)

    # Вычисление a = g^k mod p
    a = pow(g, k, p)

    # Вычисление b = m * y^k mod p
    b = (m * pow(y, k, p)) % p

    return a, b


# Расшифрование сообщения
def decrypt(data, x):
    # Вычисление m = b * a^(p-1-x) mod p
    asn = ASN1()
    a, b, y, p, g = asn.decode(data)
    s = pow(a, p - 1 - x, p)
    m = (b * s) % p

    # Преобразование числа обратно в строку
    message_length = (m.bit_length() + 7) // 8
    message = m.to_bytes(message_length, 'big')

    return message


# Чтение файла и шифрование
def encrypt_file(file_path, output_path, p, g, y):
    with open(file_path, 'r') as f:
        message = f.read()

    # Шифрование содержимого файла
    a, b = encrypt(message, p, g, y)
    print(f"Сообщение:\na = {a}\nb = {b}\n")
    asn = ASN1()
    asn.encode(p, g, y, a, b)
    # Сохранение зашифрованных данных
    with open(output_path, 'wb') as f_out:
        f_out.write(asn.encoder.output())


# Чтение файла и расшифрование
def decrypt_file(file_path, output_path, x):
    with open(file_path, 'rb') as f:
        data = f.read()

    # Расшифрование
    message = decrypt(data, x)

    # Сохранение расшифрованного сообщения
    with open(output_path, 'wb') as f_out:
        f_out.write(message)


input_file = 'input.txt'
encrypted_file = 'encrypted.txt'
decrypted_file = 'decrypted.txt'
p, g, y, x = 0, 0, 0, 0
while 1:
    print("[1] Генерация ключей\n[2] Шифрование файла\n[3] Расшифрование файла\n[4] - Выход")
    choose = int(input(">> "))
    if choose == 1:
        # Генерация ключей
        p, g, y, x = generate_keys(1024)
        print(f"p = {p}\na = {g}\nb = {y}\nx = {x}")
    elif choose == 2:
        if p == 0 or g == 0 or y == 0 or x == 0:
            print("Сгенерируйте ключи!\n")
            continue
        # Шифрование файла
        encrypt_file(input_file, encrypted_file, p, g, y)
        print(f"Файл '{input_file}' зашифрован и сохранен как '{encrypted_file}'")
    elif choose == 3:
        # Расшифрование файла
        decrypt_file(encrypted_file, decrypted_file, x)
        print(f"Файл '{encrypted_file}' расшифрован и сохранен как '{decrypted_file}'")
    else:
        exit()
