# Padding Oracle Helper
Helps you pulling off a padding oracle attack. I built this to solve the *Converter* challenge of P.W.N. CTF 2018.

With this tool you can:
- Decrypt cipher texts
- Craft modified cipher texts

## Usage
Example:
```py
from padding_oracle import PaddingOracle
from optimized_alphabets import json_alphabet

import requests

# This function has to be implemented and will be passed to the PaddingOracle constructor.
# It gets a hex encoded cipher text and has to return True if it can be decrypted successfully,
# False otherwise.
# 
# Here is an example implementation that I used for P.W.N. CTF 2018.
def oracle(cipher_hex):
    headers = {'Cookie': 'vals={}'.format(cipher_hex)}
    r = requests.get('http://converter.uni.hctf.fun/convert', headers=headers)
    response = r.content

    if b'Invalid padding bytes.' not in response:
        return True
    else:
        return False


# Instantiate the helper with the oracle implementation
o = PaddingOracle(oracle, max_retries=-1)

# Decrypt the plain text.
# To make the guesswork faster, use an alphabet optimized for JSON data.
cipher = 'b5290bd594ba08fa58b1d5c7a19f876c338191a51eeeac94c2b434bdb8adbfb8596f996d6eddca93c059e3dc35f7bef36b57a5611250ec4528c11e1573799d2178c54c034b9ea8fda8ae9a4a41c67763'
plain, padding = o.decrypt(cipher, optimized_alphabet=json_alphabet())
print('Plaintext: {}'.format(plain))

# Craft a modified but valid cipher text
plain_new = plain[:24] + b'XXXX' + plain[28:]
cipher_new = o.craft(cipher, plain, plain_new)
print('Modified: {}'.format(cipher_new))
```
