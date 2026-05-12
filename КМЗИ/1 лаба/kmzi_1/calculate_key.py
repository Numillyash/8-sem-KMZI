import random
from Crypto.Util.number import inverse as mod_inverse, GCD as greatest_common_divisor
from Crypto.Random import get_random_bytes as random_bytes
from Crypto.Util.number import getPrime

def get_params():
    p = getPrime(512)  # 512 бит для p
    q = getPrime(512)  # 512 бит для q
    return p, q

def check_prime(n):
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for _ in range(100):
        random_test = random.randint(1, n - 1)
        if pow(random_test, n - 1, n) != 1:
            return False
    return True


def get_keys(prime1, prime2):
    try:
        if not check_prime(prime1) or not check_prime(prime2):
            raise ValueError("Provided numbers are not prime")
        modulus = prime1 * prime2
    except ValueError as ex:
        exit(str(ex))

    totient = (prime1 - 1) * (prime2 - 1)
    while True:
        e = random.randint(1, totient - 1)
        if greatest_common_divisor(totient, e) == 1:
            break
    public_key = (modulus, e)
    private_key = mod_inverse(e, totient)
    aes_key = random_bytes(32)
    init_vector = random_bytes(16)
    return public_key, private_key, aes_key, init_vector