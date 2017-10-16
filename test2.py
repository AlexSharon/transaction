import base58
import binascii
import hashlib
import sys
import axolotl_curve25519 as curve
import os

randm32 = os.urandom(32)
randm64 = os.urandom(64)

private_key = base58.b58decode('3kMEhU5z3v8bmer1ERFUUhW58Dtuhyo9hE5vrhjqAWYT')
message = b'test'

signature = curve.calculateSignature(randm64, private_key, message)
print(signature)