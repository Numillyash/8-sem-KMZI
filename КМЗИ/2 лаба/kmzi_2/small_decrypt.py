import random
from Cryptodome.Util.number import GCD, inverse, getPrime


def generate_small_e():
    e_pow = 3
    e = random.randrange(2 ** e_pow, 2 ** (e_pow+1))
    while 1:
        p = getPrime(8)
        q = getPrime(8)
        N = p*q
        Fi_n = (p - 1) * (q - 1)
        if GCD(e, Fi_n) == 1:
            break
    d = inverse(e, Fi_n)
    return N, e, p, q, d


def Keyless_decryption_small_e(N, c, e):
    i = 1
    c_list = []
    c_list.append(c)
    while 1:
        c_list.append(pow(c_list[0], pow(e, i), N))
        if c_list[i] % N == c % N:
            m = c_list[i - 1]
            return m
        i = 1 + i

print("[Бесключевое дешифрование в случае малого порядка e]")
N, e, p, q, d = generate_small_e()
print(f"p = {p}\nq = {q}\nN = {N}\ne = {e}\nd = {d}")
m = random.randint(1, 100)
print(f"Исходное сообщение m = {m}")
c = pow(m, e, N)
new_m = Keyless_decryption_small_e(N, c, e)
print(f"Полученное сообщение m = {new_m}")