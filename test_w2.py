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


pywaves.CHAIN = 'testnet'
pywaves.CHAIN_ID = 'T'

def SecureHash(seed):

    #set BLAKE hashing parameters and hash
    h = blake2b(digest_size=32)
    h.update(seed)
    seed = h.digest()
    # CHECK: print('Computed blake2b hash:\n{}'.format(b58encode(seed)))

    #Keccak256 from PyWaves (crypto)
    h = crypto.KeccakHash()
    seed = h.digest(seed).encode('latin-1')
    # CHECK: print('Computed keccak hash:\n{}'.format(b58encode(seed)))
    return seed

#seed string
#seed = b'manage manual recall harvest series desert melt police rose hollow moral pledge kitten position add'
#seed_str = 'manage manual recall harvest series desert melt police rose hollow moral pledge kitten position add'
seed = b'prosper primary borrow coil tissue yard mix train velvet regret avoid inherit argue stumble cruel'
seed_str = 'prosper primary borrow coil tissue yard mix train velvet regret avoid inherit argue stumble cruel'

#encoded and amended seed
seed = b'\x00\x00\x00\x00' + seed

seed_hashed = SecureHash(seed)

#sha256 from hashlib library
h = hashlib.sha256()
h.update(seed_hashed)
seed = h.digest()
#print('Computed sha256 hash:\n{}'.format(b58encode(seed)))
#print('Expected result:\n49mgaSSVQw6tDoZrHSr9rFySgHHXwgQbCRwFssboVLWX\n')

#compute Private Key
k_pr = curve.generatePrivateKey(seed)
#print('Computed Private Key:\n{}'.format(b58encode(k_pr)))
# CHECK:print('Expected result:\n3kMEhU5z3v8bmer1ERFUUhW58Dtuhyo9hE5vrhjqAWYT')

#compute Public Key
k_pub = curve.generatePublicKey(k_pr)
#print('Computed Public Key:\n{}'.format(b58encode(k_pub)))
# CHECK:print('Expected result:\nHBqhfdFASRQ5eBBpu2y6c6KKi1az6bMx8v1JxX4iW1Q8')

#compute Address
ver = bytes([1])
scheme = b'\x54' # \x57 for mainnet, \x54 for testnet
k_pub_hash = SecureHash(k_pub)[:20]
checksum = SecureHash(ver + scheme + k_pub_hash)[0:4]
address = ver + scheme + k_pub_hash + checksum
#print('Computed Address:\n{}\n'.format(b58encode(address)))

unhashedAddress = chr(1) + str('T') + crypto.hashChain(k_pub)[0:20]
addressHash = crypto.hashChain(crypto.str2bytes(unhashedAddress))[0:4]
address2 = crypto.str2bytes(unhashedAddress + addressHash)

pywaves.setNode(node = 'http://52.30.47.67:6869', chain = 'testnet')

myAddress = pywaves.Address(seed=seed_str)

#print(myAddress.balance())
#myAddress.sendWaves(recipient = pywaves.Address('3NBVqYXrapgJP9atQccdBPAgJPwHDKkh6A8'), amount = 300000000)

#list of components in bytes to be assembled in transaction or block etc.
comp = {}

#constructing Tx
comp = {    't_type' : b'\x04',
            'k_pub' : b58decode('EENPV1mRhUD9gSKbcWt84cqnfSGQP5LkCu5gMBfAanYH'),
            'amount_flag' : bytes([1]), # 0 - waves
            'as_ID' : b58decode('BG39cCNUFWPQYeyLnu7tjKHaiUGRxYwJjvntt9gdDPxG'), # Amount's asset ID (if used)
            'fee_flag' : bytes([1]), # Fee's asset flag (0-Waves, 1-Asset)
            'fee_ID' : b58decode('BG39cCNUFWPQYeyLnu7tjKHaiUGRxYwJjvntt9gdDPxG'), # Fee's asset ID (if used)
            'timestamp' : (1479287120875).to_bytes(8, byteorder='big'), #timestamp = int(time.time() * 1000)
            'amount' : (1).to_bytes(8, byteorder='big'), # 1 stands for amount
            'fee' : (1).to_bytes(8, byteorder='big'), # 1 stands for fee
            'recip_address' : b58decode('3NBVqYXrapgJP9atQccdBPAgJPwHDKkh6A8'),
            'att' : (4).to_bytes(2, byteorder='big'),
            'att_bytes' : b58decode('2VfUX')
        }

comp = {    't_type' : b'\x04',
            'k_pub' : k_pub,
            'amount_flag' : bytes([0]), # 0 - waves
            #'as_ID' : b58decode('BG39cCNUFWPQYeyLnu7tjKHaiUGRxYwJjvntt9gdDPxG'), # Amount's asset ID (if used)
            'fee_flag' : bytes([0]), # Fee's asset flag (0-Waves, 1-Asset)
            #'fee_ID' : b58decode('BG39cCNUFWPQYeyLnu7tjKHaiUGRxYwJjvntt9gdDPxG'), # Fee's asset ID (if used)
            'timestamp' : int(time.time() * 1000).to_bytes(8, byteorder='big'), #'timestamp' : (1479287120875).to_bytes(8, byteorder='big')
            'amount' : (1).to_bytes(8, byteorder='big'), # amount = 1
            'fee' : (1).to_bytes(8, byteorder='big'), # fee = 1
            'recip_address' : b58decode('3NBVqYXrapgJP9atQccdBPAgJPwHDKkh6A8'),
            'att' : (4).to_bytes(2, byteorder='big'),
            'att_bytes' : b58decode('2VfUX')
        }

tx = b''
for key, value in comp.items():
    #print("{0}: {1}".format(key, b58encode(value)))
    tx += value

randm64 = os.urandom(64)
sign = curve.calculateSignature(randm64, k_pr, tx)
#print(b58encode(sign))
#sign = crypto.sign(b58encode(k_pr), tx)
#print(sign)

#print('result')
#print(b58encode(tx + sign))

data = json.dumps({
                "senderPublicKey": b58encode(k_pub),
                "recipient": '3NBVqYXrapgJP9atQccdBPAgJPwHDKkh6A8',
                "amount": 300000000,
                "fee": 100000,
                "timestamp": int(time.time() * 1000),
                "attachment": '2VfUX',
                "signature": b58encode(sign)
            })
#print(data)
#pywaves.wrapper('/assets/broadcast/transfer', postData=data, host='https://testnode4.wavesnodes.com')
#myAddress.sendWaves(recipient = pywaves.Address('3NBVqYXrapgJP9atQccdBPAgJPwHDKkh6A8'), amount = 500000000)

print(pywaves.wrapper('/addresses/balance/%s%s' % (b58encode(address), ''))['balance'])
print(pywaves.wrapper('/assets/broadcast/transfer', postData=data, host='https://testnode4.wavesnodes.com'))