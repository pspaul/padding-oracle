#!/usr/bin/env python

from padding_oracle import PaddingOracle
from optimized_alphabets import json_alphabet

import requests


def oracle(cipher_hex):
    headers = {'Cookie': 'vals={}'.format(cipher_hex)}
    r = requests.get('http://converter.uni.hctf.fun/convert', headers=headers)
    response = r.content

    if b'Invalid padding bytes.' not in response:
        return True
    else:
        return False


o = PaddingOracle(oracle, max_retries=-1)

# Decrypt the plain text
cipher = 'b5290bd594ba08fa58b1d5c7a19f876c338191a51eeeac94c2b434bdb8adbfb8596f996d6eddca93c059e3dc35f7bef36b57a5611250ec4528c11e1573799d2178c54c034b9ea8fda8ae9a4a41c67763'
plain, padding = o.decrypt(cipher, optimized_alphabet=json_alphabet())
print('Plaintext: {}'.format(plain))

# Craft a modified but valid cipher text
plain_new = plain[:24] + b'XXXX' + plain[28:]
cipher_new = o.craft(cipher, plain, plain_new)
print('Modified: {}'.format(cipher_new))
