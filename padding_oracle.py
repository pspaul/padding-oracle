from time import sleep
from binascii import unhexlify

from helpers import hex_to_int_array, int_array_to_hex, split_into_chunks
from optimized_alphabets import padding_alphabet, printable_ascii_alphabet
from logger import Logger, LOG_INFO


DEFAULT_MAX_RETRIES = 10
DEFAULT_RETRY_WAIT_SECONDS = 3


class PaddingOracleException(Exception):
    pass


class PaddingOracle:
    def __init__(self, oracle, block_size=16, max_retries=DEFAULT_MAX_RETRIES, retry_wait_seconds=DEFAULT_RETRY_WAIT_SECONDS, log_level=LOG_INFO):
        self.oracle = oracle
        self.block_size = block_size
        self.max_retries = max_retries
        self.retry_wait_seconds = retry_wait_seconds
        self.logger = Logger(log_level)

    def _call_oracle(self, cipher_hex):
        """
        Calls the oracle function, catches exceptions and retries.
        """
        retries = 0
        last_exception = None
        while retries < self.max_retries or self.max_retries == -1:
            try:
                return self.oracle(cipher_hex)
            except Exception as e:
                self.logger.log_oracle_error(e)
                last_exception = e
                retries += 1
                sleep(self.retry_wait_seconds)
        raise PaddingOracleException('Oracle finally failed after {} retries!'.format(self.max_retries)) from last_exception

    def decrypt_block(self, iv_block, cipher_block, pre_known=[], detect_padding=False, optimized_alphabet=printable_ascii_alphabet()):
        """
        Decrypts a single cipher block.
        """
        if len(iv_block) != self.block_size:
            raise PaddingOracleException('IV size is not block size: {} != {}'.format(len(iv_block), self.block_size))
        if len(cipher_block)//2 != self.block_size:
            raise PaddingOracleException('Cipher size is not block size: {} != {}'.format(len(cipher_block)//2, self.block_size))

        # build the plaintext placeholder
        plain = [0]*(16-len(pre_known)) + pre_known

        # start with the padding alphabet
        current_alphabet = padding_alphabet(self.block_size)
        
        padding_length = 1 if detect_padding else 0
        current_iv = iv_block[:]
        index_start = len(pre_known)
        for i in range(index_start, self.block_size):
            index = self.block_size - i - 1

            self.logger.info('Byte {:02d}:'.format(index + 1))

            # prepare the previously decoded bytes to have the value of the current padding
            for j in range(i):
                j = self.block_size - j - 1
                current_iv[j] = iv_block[j] ^ plain[j] ^ (i + 1)

            # we decrypted the whole padding, so we now use a better alphabet
            if i >= padding_length:
                current_alphabet = optimized_alphabet

            # try all bytes
            for byte_index, byte_value in enumerate(current_alphabet):
                current_iv[index] = iv_block[index] ^ byte_value ^ (i + 1)
                cipher_hex = int_array_to_hex(current_iv) + cipher_block

                self.logger.log_byte_status(current_iv[index], byte_value, byte_index, len(current_alphabet), i, len(plain), cipher_hex)
                
                decryption_success = self._call_oracle(cipher_hex)
                if decryption_success:
                    intermediate = (i + 1) ^ current_iv[index]
                    plain[index] = intermediate ^ iv_block[index]
                    
                    self.logger.log_found_byte(index, intermediate, plain[index])

                    # assume this byte's value is the padding length (PKCS#7)
                    if detect_padding and i == 0:
                        padding_length = plain[index]

                    break

        # the values that come out of the block cipher, before XORing with the iv
        intermediates = [(m ^ _iv) for m, _iv in zip(plain, iv_block)]

        return plain, intermediates, padding_length

    def decrypt(self, cipher, optimized_alphabet=printable_ascii_alphabet()):
        """
        Decrypts all cipher blocks.
        """
        cipher_blocks = split_into_chunks(cipher, self.block_size*2)

        plain = []
        padding = 0

        # iterate over block pairs
        for i in range(0, len(cipher_blocks) - 1):
            iv = hex_to_int_array(cipher_blocks[i])
            cipher_block = cipher_blocks[i + 1]

            # detect the padding if its the last block
            detect_padding = (i == len(cipher_blocks) - 2)

            # decrypt the current block
            plain_block, intermediate, padding = self.decrypt_block(iv, cipher_block, detect_padding=detect_padding, optimized_alphabet=optimized_alphabet)

            # append to the whole plaintext
            plain += plain_block

            # log this block's plaintext
            self.logger.log_block_decryption(i, len(cipher_blocks), plain_block, intermediate)

        plain_raw = bytes(plain[:-padding])
        return plain_raw, padding

    def craft(self, cipher, plain_old, plain_new):
        """
        Crafts a new valid cipher for a modified plaintext.
        """
        if len(plain_old) != len(plain_new):
            raise PaddingOracleException('The plaintexts differ in size! old={} new={}'.format(len(plain_old), len(plain_new)))

        # pad the plaintexts
        missing = len(plain_old) % self.block_size
        pad = chr(missing).encode('ascii') * missing
        plain_old = plain_old + pad
        plain_new = plain_new + pad

        # split the stuff into blocks
        plain_old_blocks = split_into_chunks(plain_old, self.block_size)
        plain_new_blocks = split_into_chunks(plain_new, self.block_size)
        cipher_blocks = split_into_chunks(cipher, self.block_size*2)

        # the last cipher block never gets changed, so add it
        cipher_new_blocks = [cipher_blocks[-1]]

        nothing_changed_yet = True
        for i in range(len(cipher_blocks) - 1, 0, -1):
            cipher_block = cipher_blocks[i]

            plain_old_block = plain_old_blocks[i-1]
            plain_new_block = plain_new_blocks[i-1]
            iv = cipher_blocks[i-1]

            # nothing changed, use the old "iv"
            if nothing_changed_yet and plain_old_block == plain_new_block:
                print('block{} didnt change.'.format(i))
                cipher_new_blocks.insert(0, iv)
                continue

            if nothing_changed_yet:
                print('block{} changed!'.format(i))
                cipher_new_block = int_array_to_hex([(a ^ b ^ c) for a, b, c in zip(plain_old_block, plain_new_block, hex_to_int_array(iv))])
                cipher_new_blocks.insert(0, cipher_new_block)
                
                nothing_changed_yet = False
            else:
                print('crafting new block{}...'.format(i))
                _, intermediate, _ = self.decrypt_block(hex_to_int_array(iv), cipher_new_blocks[0])
                cipher_new_block = int_array_to_hex([(m ^ x) for m, x in zip(plain_new_block, intermediate)])
                cipher_new_blocks.insert(0, cipher_new_block)

        cipher_new = ''.join(cipher_new_blocks)
        return cipher_new
