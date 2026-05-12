import keygen as k
import factorize as f
import vinner as v
import small_decrypt as sd
import random

# while 1:
#     p, q, e_a, d_a, N = k.generate_RSA_key()
#     e_b, d_b = k.generate_RSA_key_N(p, q)
#     if e_a != e_b and d_a != d_b:
#         fea = open("Fa.txt", "w")
#         fea.write(str(e_a))
#         fea.close()
#         feb = open("Fb.txt", "w")
#         feb.write(str(e_b))
#         feb.close()
#         fda = open("Da.txt", "w")
#         fda.write(str(d_a))
#         fda.close()
#         fdb = open("Db.txt", "w")
#         fdb.write(str(d_b))
#         fdb.close()
#         fN = open("N.txt", "w")
#         fN.write(str(N))
#         fN.close()
#         fq = open("q.txt", "w")
#         fq.write(str(q))
#         fq.close()
#         fp = open("p.txt", "w")
#         fp.write(str(p))
#         fp.close()
#         break

fea = open("Fa.txt", "r")
e_a = int(fea.read())
fea.close()
feb = open("Fb.txt", "r")
e_b = int(feb.read())
feb.close()
fda = open("Da.txt", "r")
d_a = int(fda.read())
fda.close()
fdb = open("Db.txt", "r")
d_b = int(fdb.read())
fdb.close()
fN = open("N.txt", "r")
N = int(fN.read())
fN.close()
fp = open("p.txt", "r")
p = int(fp.read())
fp.close()
fq = open("q.txt", "r")
q = int(fq.read())
fq.close()

p_new, q_new, d_a_new = f.Factorization_n_RSA(N, e_b, d_b, e_a)
print(f"[Разложение на множители]\nN = {N}\np = {p}\nq = {q}\ne_a = {e_a}\ne_b = {e_b}\nd_b = {d_b}\n\
Реальный d_a = {d_a}\nПолученный d_a = {d_a_new}\n")


# N = 303098468963
# e = 2421079

# N = 1220275921
# e = 1073780833

N = 6727075990400738687345725133831068548505159909089226909308151105405617384093373931141833301653602476784414065504536979164089581789354173719785815972324079
e = 4805054278857670490961232238450763248932257077920876363791536503861155274352289134505009741863918247921515546177391127175463544741368225721957798416107743
d_new = v.Viner_attack(N, e)
print(f"[Атака Виннера]\nN = {N}\ne = {e}\nd = {d_new}")
m = random.randint(0, N)
c = pow(m, e, N)
m_new = pow(c, d_new, N)
print(f"m = {m}\nm полученное по вычисленному d = {m_new}\n")

print("[Бесключевое дешифрование в случае малого порядка e]")
N, e, p, q, d = sd.generate_small_e()
print(f"p = {p}\nq = {q}\nN = {N}\ne = {e}\nd = {d}")
m = random.randint(1, 100)
print(f"Исходное сообщение m = {m}")
c = pow(m, e, N)
new_m = sd.Keyless_decryption_small_e(N, c, e)
print(f"Полученное сообщение m = {new_m}")