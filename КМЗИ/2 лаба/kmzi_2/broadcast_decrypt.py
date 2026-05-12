import random


def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True


def next_prime(n):
    if n < 2:
        return 2
    prime = n
    found = False
    while not found:
        prime += 1
        if is_prime(prime):
            found = True
    return prime


def extended_gcd(a, b):
    """Расширенный алгоритм Евклида для нахождения GCD и коэффициентов."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def crt(a_list, n_list):
    """Решает систему сравнений по теореме китайских остатков."""
    # Проверка на равенство длины списков
    if len(a_list) != len(n_list):
        raise ValueError("Длины списков a и n должны совпадать.")

    # Начальные значения
    total = 0
    prod = 1

    # Вычисление произведения всех модулей
    for n in n_list:
        prod *= n

    # Применение теоремы китайских остатков
    for a, n in zip(a_list, n_list):
        p = prod // n
        gcd, inv, _ = extended_gcd(p, n)
        if gcd != 1:
            raise ValueError("Модули должны быть взаимно простыми.")
        total += a * inv * p

    return total % prod

# Алгоритм 2.3 Случай специальных открытых показателей
def generate_n_c(e, count, mes):  # проверка для маленьких чисел!
    # Генерация count значений n
    n_i = []
    c_i = []
    p = next_prime(2 ** 10)  # Начальное простое число
    for _ in range(count):
        n_i.append(p)
        c_i.append(pow(mes, e, p))
        p = next_prime(p)
    return n_i, c_i


def keyless_decryption(c_i, e, n_i):
    # x=crt(c_i,n_i)
    x = crt(n_i, c_i)
    if x is not None:
        m = x[0] ** (1 / e)
        print("Result = ", m)
        return int(m)
    else:
        print("Ошибка: Китайская теорема об остатках не применима.")
        return None


m = random.randint(1, 100)  # подходит по ограничению длины сообщения
print("Begin mes = ", m)

e = 3
n_i, c_i = generate_n_c(3, e, m)
print(n_i)
print(c_i)
keyless_decryption(c_i, e, n_i)
