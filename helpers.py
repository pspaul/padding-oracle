from binascii import unhexlify


def int_array_to_hex(iv_array):
    """
    Converts an integer array to a hex string.
    """
    iv_hex = ''
    for b in iv_array:
        iv_hex += '{:02x}'.format(b)

    return iv_hex


def hex_to_int_array(hex_string):
    """
    Converts a hex string to an integer array.
    """
    return list(unhexlify(hex_string))


def split_into_chunks(string, chunk_size):
    """
    Splits a string into chunks of the specified size.
    NOTE: expects len(str) to be multiple of chunk_size.
    """
    chunks = []
    for i in range(0, len(string), chunk_size):
        chunks.append(string[i:i + chunk_size])    
    return chunks
