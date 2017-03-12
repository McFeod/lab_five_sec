from constants import order, initial_message


def bit(number, idx, size=64):
    """
    Получение бита на определенной позиции слева
    :param number: число, в котором ведется поиск
    :param idx: позиция бита (нумерация с 1, слева направо)
    :param size: размер числа number в битах
    :return: значение бита
    """
    return int(bool((1 << (size-idx)) & number))


def feistel_chunk(source, table):
    """
    Подстановка S в функции Фейстеля
    :param source: исходное число (важны последние 6 бит)
    :param table: таблица подстановок
    :return: табличное значение
    """
    column = (source & 0b11110) >> 1
    row = ((source & 0b100000) >> 4) | (source & 1)
    return table[row * 16 + column]


def reorder(message, order, size):
    """
    Перестановка битов
    :param message: исходная последовательность (число)
    :param order: новый порядок (список позиций)
    :param size: размер исходной последовательности в битах
    :return: новая последовательность (число)
    """
    return sum(bit(message, position, size) << i for i, position in enumerate(reversed(order)))


def feistel(message, key_element):
    """
    Функция Фейстеля
    :param message: исходная последовательность
    :param key_element: ключевой элемент
    :return: новая последовательность, данные для отчёта
    """
    e = reorder(message, order['e'], 32)
    xor = e ^ key_element
    chunks = 0
    for i in range(8):
        chunks |= feistel_chunk(xor, order['s'][7-i]) << (i*4)
        xor >>= 6
    result = reorder(chunks, order['p'], 32)
    return result


def cipher_iteration(left, right, key):
    """
    Итерация ECB
    """
    f = feistel(right, key)
    f_left = f ^ left
    return right, f_left, locals()


def fermat(n):
    return (1 << n) - 1


def shift28(chunk, bit_count):
    """
    Циклический сдвиг 28-битового chunk числа влево на bit_count
    """
    border = 28 - bit_count
    left = (fermat(border) & chunk) << bit_count
    right = (chunk >> border) & fermat(bit_count)
    return left | right


def calc_keys(key):
    """
    Вычисление ключевых элементов на основе key
    """
    k = reorder(key, order['pc1'], 64)
    left = k >> 28
    right = k & 0xfffffff
    result = []
    for i in order['shift']:
        left = shift28(left, i)
        right = shift28(right, i)
        result.append(reorder((left << 28) | right, order['pc2'], 56))
    return result


def prepare_message(string):
    """
    Разбиение шифруемого сообщения на блоки по 64 бита в кодировке cp1251
    :return: последовательность блоков данных, данные для отчёта
    """

    def chunker(seq, size):
        return (seq[pos:pos + size] for pos in range(0, len(seq), size))

    def get_byte(chunk, idx):
        return chunk[idx] if idx < len(chunk) else 0

    bytes_ = string.encode('cp1251')
    blocks = []

    for chunk in chunker(bytes_, 8):
        block = 0
        for i in range(8):
            block = (block << 8) | get_byte(chunk, i)
        blocks.append(block)
    return blocks, locals()


def prepare_keys(string):
    """
    Выделение ключа из заданной строки
    :return: последовательность ключевых элементов, данные для отчёта
    """
    def parity_bit(byte):
        parity = False
        while byte:
            parity = not parity
            byte ^= byte & (~byte + 1)
        return int(parity)

    def insert_bits(number):
        result = 0
        for i in range(8):
            chunk = number & 0x7f
            result |= ((chunk << 1) | parity_bit(chunk)) << (8 * i)
            number >>= 7
        return result

    bytes_ = string.encode('cp1251')
    assert len(bytes_) >= 7
    number = int.from_bytes(bytes_[:7], 'big')
    with_parity = insert_bits(number)
    keys = calc_keys(with_parity)
    return keys, locals()


def ecb(message, keys):
    """
    Шифрование блока message при помощи ключевых элементов keys
    """
    shuffled = reorder(message, order['ip'], 64)
    right = shuffled & 0xffffffff
    left = shuffled >> 32
    history = []
    for key_element in keys:
        left, right, steps = cipher_iteration(left, right, key_element)
        history.append(steps)
    result = reorder((left << 32) | right, order['ip-1'], 64)
    return result, locals()


def cbc(message, key_phrase):
    """
    Шифрование исходного сообщения message при помощи строки key_phrase
    """
    initial = initial_message
    blocks, message_preparation = prepare_message(message)
    key_elements, keys_preparation = prepare_keys(key_phrase)
    result = initial
    steps = []
    for block in blocks:
        result ^= block
        steps.append(result)
        result, step = ecb(result, key_elements)
        steps.append(step)
    return locals()
