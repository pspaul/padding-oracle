import string


def alphabet_from_string(string, complete=True):
    alpha = []

    # add chars from string
    for c in string:
        val = ord(c)
        if val not in alpha:
            alpha.append(val)

    # add missing byte values
    if complete:
        for i in range(255, 0, -1):
            if i not in alpha:
                alpha.append(i)

    return alpha


def default_alphabet():
    """
    All the plain old byte values.
    """
    return list(range(255, 0, -1))


def printable_ascii_alphabet():
    """
    This is faster for printable ASCII data.
    """
    return alphabet_from_string(string.printable)


def padding_alphabet(block_size):
    """
    This is faster for the padding.
    """
    return list(range(0, block_size))[::-1] + list(range(block_size, 256)) + [0]


def json_alphabet():
    """
    This is faster for JSON data.
    """
    alpha = ''
    
    # JSON special characters
    alpha += '{}[]": ,\\'

    # alphanumeric
    alpha += string.ascii_lowercase + string.digits + string.ascii_uppercase
    
    # remaining printable ascii
    alpha += string.printable

    return alphabet_from_string(alpha)
