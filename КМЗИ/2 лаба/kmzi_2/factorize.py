import random
import math
from Cryptodome.Util.number import inverse

# Алгоритм 2.1. Разложение составного числа на множители по известным показателям RSA
def Factorization_n_RSA(N, e_b, d_b, e_a):
    f = 0
    s = e_b * d_b - 1
    while s % 2 == 0:
        s //= 2  # Деление на 2 с присваиванием
        f += 1
    while 1:
        a = random.randint(0, N - 1)
        b = pow(a, s, N)
        l = 0
        while 1:
            if pow(b, int(pow(2, l)), N) == 1:
                if pow(b, int(pow(2, l - 1)), N) == -1:
                    break
                else:
                    t = pow(b, int(pow(2, l - 1)), N)
                    p = math.gcd(t + 1, N)
                    q = math.gcd(t - 1, N)
                    Fi_n = (p - 1) * (q - 1)
                    if Fi_n == 0:
                        break
                    d_a = inverse(e_a, Fi_n)
                    return p, q, d_a
            else:
                l += 1
