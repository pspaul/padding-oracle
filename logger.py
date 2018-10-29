from helpers import int_array_to_hex

LOG_DEBUG = 1
LOG_INFO = 2

class Logger:
    def __init__(self, log_level=LOG_INFO):
        if log_level not in (LOG_INFO, LOG_DEBUG):
            raise Exception('Invalid log level: {}'.format(log_level))
        self.log_level = log_level

    def info(self, msg, **kwargs):
        if self.log_level >= LOG_INFO:
            print(msg, **kwargs)

    def debug(self, msg, **kwargs):
        if self.log_level >= LOG_DEBUG:
            print(msg, **kwargs)

    def log_byte_status(self, iv_byte, byte_value, byte_index, alphabet_length, byte_position, block_size, cipher_string):
        if self.log_level == LOG_DEBUG:
            self.debug('  Trying {:02x} ({})... (Try {:3d}/{:3d} for Byte {:2d}/{:2d}) => {}'.format(iv_byte, repr(chr(byte_value)), byte_index + 1, alphabet_length, byte_position + 1, block_size, cipher_string))
        else:
            self.info('.', end='', flush=True)

    def log_oracle_error(self, e):
        if self.log_level == LOG_DEBUG:
            self.debug(e)
            self.debug('')
            self.debug('Retrying...')
        else:
            self.info('E', end='', flush=True)

    def log_found_byte(self, index, x, m):
        if self.log_level == LOG_DEBUG:
            self.debug(' Found it! x{:02d}={:02x} m{:02d}={:02x}'.format(index + 1, x, index + 1, m))
        else:
            self.info(' 0x{:02x}'.format(m))

    def log_block_decryption(self, block_index, block_count, plain_block, intermediate_block):
        plain_block_hex = int_array_to_hex(plain_block)
        plain_block_raw = bytes(plain_block)
        if self.log_level == LOG_DEBUG:
            self.debug('')
            self.debug('block {}/{}'.format(block_index, block_count))
            self.debug('plaintext    = {}'.format(plain_block))
            self.debug('               {}'.format(plain_block_hex))
            self.debug('               {}'.format(repr(plain_block_raw)))
            self.debug('intermediate = {}'.format(intermediate_block))
            self.debug('')
        else:
            self.info('block {}/{}: {}'.format(block_index+1, block_count-1, plain_block_hex))
