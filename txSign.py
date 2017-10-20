from base58 import b58encode, b58decode
from pyblake2 import blake2b
import hashlib
import pywaves
import pywaves.crypto as crypto
import time
import os
import axolotl_curve25519 as curve
import requests
import json

def SecureHash(seed):

    #set BLAKE hashing parameters and hash
    h = blake2b(digest_size=32)
    h.update(seed)
    seed = h.digest()

    #Keccak256 from PyWaves (crypto)
    h = crypto.KeccakHash()
    seed = h.digest(seed).encode('latin-1')
    return seed

seed = b'prosper primary borrow coil tissue yard mix train velvet regret avoid inherit argue stumble cruel'
seed_str = crypto.bytes2str(seed)
seed = b'\x00\x00\x00\x00' + seed
seed_hashed = SecureHash(seed)

#sha256
h = hashlib.sha256()
h.update(seed_hashed)
seed = h.digest()

#compute Keys
k_pr = curve.generatePrivateKey(seed)
k_pub = curve.generatePublicKey(k_pr)

#compute Address
ver = bytes([1])
scheme = b'\x54' # \x57 for mainnet, \x54 for testnet
k_pub_hash = SecureHash(k_pub)[:20]
checksum = SecureHash(ver + scheme + k_pub_hash)[0:4]
address = ver + scheme + k_pub_hash + checksum

time = int(time.time() * 1000)

#constructing Tx
components = {    't_type' : b'\4',
            'k_pub' : k_pub,
            'amount_flag' : b'\0',
            'fee_flag' : b'\0',
            'timestamp' : time.to_bytes(8, byteorder='big'),
            'amount' : (100000000).to_bytes(8, byteorder='big'),
            'fee' : (100000).to_bytes(8, byteorder='big'),
            'recip_address' : b58decode('3NBVqYXrapgJP9atQccdBPAgJPwHDKkh6A8'),
            'att' : (4).to_bytes(2, byteorder='big'),
            'att_bytes' : b58decode('2VfUX')
        }
tx = b''
for key, value in components.items():
    tx += value

#sign tx
randm64 = os.urandom(64)
sign = curve.calculateSignature(randm64, k_pr, tx)

#prepare data for broadcast
data = json.dumps({
                "senderPublicKey": b58encode(k_pub),
                "recipient": '3NBVqYXrapgJP9atQccdBPAgJPwHDKkh6A8',
                "amount": 100000000,
                "fee": 100000,
                "timestamp": time,
                "attachment": '2VfUX',
                "signature": b58encode(sign)
            })

#set the node and execute transaction
pywaves.setNode(node = 'http://52.30.47.67:6869', chain = 'testnet')
print(pywaves.wrapper('/addresses/balance/%s%s' % (b58encode(address), ''))['balance'])
req = requests.get('https://testnode2.wavesnodes.com/assets/balance/%s' % (b58encode(address))).json()

#req = requests.post('https://testnode2.wavesnodes.com/assets/broadcast/transfer', data=data, headers={'content-type': 'application/json'}).json()
print(req)
