#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, random
import string, binascii, base64

string = 'JisqDl0eAGQZIH8BIk4CREhlCiQNHmFrChoAN0YWQVcYIUohGn46UDI3FQ=='

str =base64.b64decode('JisqDl0eAGQZIH8BIk4CREhl')
def xor(s1, s2):
    return bytes( map( (lambda x: x[0]^x[1]), zip(s1, s2) ) )

def re(var):
	flag = base64.b64decode(string)
	random.seed( var)
	keystream = ''.join( [ random.choice(code) for _ in range(45) ] )
	keystream = keystream.encode()
	end = xor(flag, keystream)
	print (end)

code = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
while True:
	var = os.urandom(8)
	random.seed( var)
	keystream = ''.join( [ random.choice(code) for _ in range(6) ] )
	keystream = keystream.encode()
	end = xor(str, keystream)
	if end.startswith(b'hgame{'):
		print (var)
		re(var)

