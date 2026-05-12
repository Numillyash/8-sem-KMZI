# Генерация значений ключей RSA
# Можно к первой добавить
import random
from Cryptodome.Util.number import GCD, inverse, getPrime
from sympy import isprime, mod_inverse
RSA_KEY_LEN = 1024


def generate_RSA_key():
    e_pow = 16
    p = getPrime(RSA_KEY_LEN // 2)
    q = getPrime(RSA_KEY_LEN // 2)
    N = p * q
    Fi_n = (p - 1) * (q - 1)
    while True:
        e = random.randint(1, Fi_n)
        # e = random.randrange(2 ** e_pow, 2 ** (e_pow + 1))
        if GCD(e, Fi_n) == 1:
            break
    d = inverse(e, Fi_n)
    return p, q, e, d, N


def generate_RSA_key_N(p, q):  # генерировать ключ, зная N
    e_pow = 16
    Fi_n = (p - 1) * (q - 1)
    while True:
        e = random.randrange(2 ** e_pow, 2 ** (e_pow + 1))
        if GCD(e, Fi_n) == 1:
            break
    d = inverse(e, Fi_n)
    return e, d


def random_prime(lower, upper):
    while True:
        p = random.randint(lower, upper)
        if isprime(p):
            return p


def gen_e(p, q):
    euler = (p - 1) * (q - 1)
    e = random_prime(2 ** 128, euler - 1)
    while gcd(e, euler) != 1:
        e = random_prime(2, euler - 1)
    return e, euler


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def gen_safe_params(bitlen):
    safe = True
    while safe:
        safe = False
        # проверка делителей p-1, q-1
        p = random_prime(2 ** (bitlen // 2 + 1), 2 ** (bitlen // 2 + 2))
        if not isprime((p - 1) // 2):
            safe = True
            continue

        while True:
            q = random_prime(2 ** (bitlen // 2 + 1), 2 ** (bitlen // 2 + 2))
            if isprime((q - 1) // 2):
                break

        if p * q < 2 ** bitlen:
            safe = True
            continue

        # не допускаем малое значение e
        while True:
            e, euler = gen_e(p, q)
            if e >= 2 ** 128:
                break

        d = mod_inverse(e, euler)

        # исключаем возможность атаки Винера
        if q < p and p < 2 * q:
            n = p * q
            check = int(n ** (1 / 4)) // 3
            if d < check:
                safe = True
                continue

    print('p: ', p)
    # print('Factors of p-1: ', factorint(p - 1))
    print('q: ', q)
    # print('Factors of q-1: ', factorint(q - 1))
    print('n: ', p * q)
    print('e: ', e)
    print('d: ', d)


gen_safe_params(1024)
