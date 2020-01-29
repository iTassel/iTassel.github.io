#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, random
import string, binascii, base64


from secret import flag
assert flag.startswith(b'hgame{') and flag.endswith(b'}')

flag_len = len(flag)

def xor(s1, s2):
    #assert len(s1)==len(s2)
    return bytes( map( (lambda x: x[0]^x[1]), zip(s1, s2) ) )
str = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
random.seed( os.urandom(8) )
keystream = ''.join( [ random.choice(str) for _ in range(flag_len) ] )
keystream = keystream.encode()
print( base64.b64encode(xor(flag, keystream)).decode() )

# string = 'JisqDl0eAGQZIH8BIk4CREhlCiQNHmFrChoAN0YWQVcYIUohGn46UDI3FQ=='
