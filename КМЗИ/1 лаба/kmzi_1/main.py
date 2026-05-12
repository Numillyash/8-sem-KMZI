from crypt import EncryptionEngine
import calculate_key as ck

p = 10153507496299277297056277086549348555608976562176155482060782045310205840436053640305176548238595350803712897110158940164233571262058638629824686235070793
q = 12144311936455235430918841270076549374833132287618636282013521118924336818263849703961935073965952349045406520170416045338963303471767834688310920758858909
#p, q = ck.get_params()


def main():
    crypto_obj = EncryptionEngine(p, q)

    #crypto_obj.calculate_keys()
    #crypto_obj.save_keys_to_files()
    # Получение параметров системы
    crypto_obj.load_keys_from_files()

    # Шифрование и расшифрование
    try:
        crypto_obj.aes_encrypt_file("open_text.txt", "encrypted_text.txt")
        encrypted_aes_key = crypto_obj.rsa_encrypt(crypto_obj.aes_key)
        original_aes_key = encrypted_aes_key
        crypto_obj.aes_key = crypto_obj.rsa_decrypt(encrypted_aes_key)
        crypto_obj.aes_decrypt_file("encrypted_text.txt", "decrypted_text.txt")
        print("Success encrypt-decrypt")
    except Exception as e:
        print("Error: ", e)

    # Получение и шифрование хеша файла
    try:
        original_hash = crypto_obj.calculate_hash("open_text.txt")
        encrypted_hash = crypto_obj.rsa_encrypt(original_hash)

        hash_file = open('hash_file', 'wb')
        hash_file.write(encrypted_hash)

        hash_file = open('hash_file', 'rb')
        hash = hash_file.read()

        if hash == encrypted_hash:
            print("sign is correct")
        else:
            print("Sign is incorrect")
    except Exception as e:
        print("Error:", e)



if __name__ == '__main__':
    main()
