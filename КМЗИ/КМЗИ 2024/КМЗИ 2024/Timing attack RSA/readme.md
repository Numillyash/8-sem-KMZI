Временная атака на некорректную реализацию RSA.
Доп. источник: 
Brumley D., Boneh D. Remote timing attacks are practical //Computer Networks. – 2005. – Т. 48. – №. 5. – С. 701-716. URL:https://crypto.stanford.edu/~dabo/papers/ssl-timing.pdf


cryptor_v[i].exe представляет собой программу, выполняющую расшифрование данных с помощью RSA с использованием фиксированного закрытого ключа d.

Для ввода параметров и вывода результатов используется stdin/stdout.
Входные параметры: шифртекст
Выходные параметры: открытый текст, условное "время", потраченное на расшифровку шифртекста

Задача: найти делитель N и вскрыть закрытый ключ. 

Пример класса для взаимодействия с cryptor_v[i].exe:

class Cryptor:
    def __init__(self, exe_path):
        self.exe_path = exe_path

        self.process = None
        self.stdin = None
        self.stdout = None

        self.interactions = 0

    def run(self):
        self.process = subprocess.Popen(args=self.exe_path, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
        self.stdout = self.process.stdout
        self.stdin = self.process.stdin

    def interact(self, c):
        self.interactions += 1

        line = "{0:X}\r\n".format(c).encode()
        self.stdin.write(line)
        self.stdin.flush()

        time = int(self.stdout.readline())
        message = int(self.stdout.readline().strip(), 16)

        return message, time

    def close(self):
        if self.process:
            self.process.kill()


if __name__ == '__main__':
	cryptor = Cryptor("path\to\cryptor_exe")
    cryptor.run()

