from math import log as logarithm


def calculate_bytes_needed(number):
    if number == 0:
        return 1
    return int(logarithm(number, 256)) + 1


def decode_byte_length(hex_value):
    numeric_value = int(hex_value, 16)
    binary_repr = format(numeric_value, '08b')
    if binary_repr[0] == '1':
        return int(binary_repr[1:], 2)
    return 0


def convert_length_to_hex(length_value):
    if length_value < 128:
        return format(length_value, '02x')
    else:
        length_size = format(int('1' + format(calculate_bytes_needed(length_value), '07b'), 2), '02x')
        length_formatter = '0' + str(calculate_bytes_needed(length_value) * 2) + 'x'
        return length_size + format(length_value, length_formatter)

class ASN1Formatter:
    def __init__(self):
        self.int_code = "02"
        self.utf_string_code = "0c"
        self.byte_string_code = "04"
        self.sequence_code = "30"
        self.set_code = "31"
        self.rsa_code = "0001"
        self.total_length = 0
        self.encoded_data = ""

    def append_at_start(self, new_data, new_length):
        self.encoded_data += new_data
        self.total_length += new_length
        return self.encoded_data, self.total_length

    def append_at_end(self, new_data, new_length):
        self.encoded_data = new_data + self.encoded_data
        self.total_length += new_length
        return self.encoded_data, self.total_length

    def reset(self):
        self.total_length = 0
        self.encoded_data = ""

    def finalize(self, data_code):
        self.encoded_data = data_code + convert_length_to_hex(self.total_length) + self.encoded_data
        self.total_length += decode_byte_length(convert_length_to_hex(self.total_length)) + 2
        return self.encoded_data, self.total_length

    def append(self, data_code, data_value):
        encoded_value = ""
        value_size = 0

        if isinstance(data_value, int):
            self.total_length += decode_byte_length(convert_length_to_hex(self.total_length)) + 1 + calculate_bytes_needed(data_value) + 1
            formatter = '0' + str(calculate_bytes_needed(data_value) * 2) + 'x'
            encoded_value = format(data_value, formatter)
            value_size = calculate_bytes_needed(data_value)
        elif isinstance(data_value, str):
            self.total_length += len(data_value) // 2 + 1 + calculate_bytes_needed(len(data_value) // 2)
            encoded_value = data_value
            value_size = len(data_value) // 2

        self.encoded_data = data_code + convert_length_to_hex(value_size) + encoded_value + self.encoded_data
        return self.encoded_data, self.total_length
