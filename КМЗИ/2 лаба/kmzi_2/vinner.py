import random
from Cryptodome.Util.number import GCD, inverse, getPrime

RSA_KEY_LEN = 1024


# Алгоритм 2.2 Атака Винера на криптосистему RSA
def genarate_RSA_key_for_viner():
    while 1:
        p = getPrime(RSA_KEY_LEN // 2)
        q = getPrime(RSA_KEY_LEN // 2)
        if 2 * q > p > q:
            break
    N = p * q
    Fi_n = (p - 1) * (q - 1)
    while 1:
        while True:
            e = random.randint(1, Fi_n)
            # e = random.randrange(2 ** e_pow, 2 ** (e_pow + 1))
            if GCD(e, Fi_n) == 1:
                break
        d = inverse(e, Fi_n)
        if d < 1 / 3 * N ** (1 / 4):
            break
    result = e * d % Fi_n
    return p, q, e, d, N


def continued_fraction(num, den):
    terms = []
    while den != 0:
        quotient = num // den
        remainder = num % den
        terms.append(quotient)
        num, den = den, remainder
    return terms


def Viner_attack(N, e):
    fraction = continued_fraction(e, N)
    l = len(fraction)
    Q = [0] * (l + 1)
    P = [0] * (l + 1)
    P[0], P[1] = 1, 0
    Q[0], Q[1] = 0, 1
    m = random.randint(0, N - 1)
    # m = pow(m, e, N)
    for i in range(2, l + 1):
        Q[i] = fraction[i - 1] * Q[i - 1] + Q[i - 2]
        if pow(m, Q[i] * e, N) == m:
            return Q[i]
    else:
        return "Решение не найдено"


#p, q, e, d, N = genarate_RSA_key_for_viner()

# # N = 303098468963
# # e = 2421079
#
# # N = 1220275921
# # e = 1073780833
#
# N = 6727075990400738687345725133831068548505159909089226909308151105405617384093373931141833301653602476784414065504536979164089581789354173719785815972324079
# e = 4805054278857670490961232238450763248932257077920876363791536503861155274352289134505009741863918247921515546177391127175463544741368225721957798416107743
#
# d_new = Viner_attack(N, e)
# print(f"Решение: {d_new}")
#
# # m = random.randint(0, N)
# # c = pow(m, e, N)
# # m_new = pow(c, d_new, N)
# # print(f"m = {m}\nm_new = {m_new}")
