_dl_fixup (struct link_map *l, ElfW(Word) reloc_arg)
{
  //获取符号表地址
  const ElfW(Sym) *const symtab = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
  //获取字符串表地址
  const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);
  //获取重定位结构地址
  const PLTREL *const reloc = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
  //通过r_info获取函数的符号表结构体
  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
  const ElfW(Sym) *refsym = sym;
  //得到函数对应的got地址，即真实函数地址要填回的地址
  void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
  lookup_t result;
  DL_FIXUP_VALUE_TYPE value;

  /* Sanity check that we're really looking at a PLT relocation.  */
  assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT); //判断是否为延迟绑定

   /* Look up the target symbol.  If the normal lookup rules are not
      used don't look in the global scope.  */
  if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0)
    {
      const struct r_found_version *version = NULL;

      if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)
      {
		  const ElfW(Half) *vernum = (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
		  ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
		  version = &l->l_versions[ndx];
		  if (version->hash == 0)
			version = NULL;
	  }

      /* We need to keep the scope around so do some locking.  This is
	 not necessary for objects which cannot be unloaded or when
	 we are not using any threads (yet).  */
      int flags = DL_LOOKUP_ADD_DEPENDENCY;
      if (!RTLD_SINGLE_THREAD_P)
	  {
		  THREAD_GSCOPE_SET_FLAG ();
		  flags |= DL_LOOKUP_GSCOPE_LOCK;
      }

#ifdef RTLD_ENABLE_FOREIGN_CALL
      RTLD_ENABLE_FOREIGN_CALL;
#endif
	  //获取函数对应的字符串
      result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,version, ELF_RTYPE_CLASS_PLT, flags, NULL);

      /* We are done with the global scope.  */
      if (!RTLD_SINGLE_THREAD_P)
      		THREAD_GSCOPE_RESET_FLAG ();

#ifdef RTLD_FINALIZE_FOREIGN_CALL
      RTLD_FINALIZE_FOREIGN_CALL;
#endif

      /* Currently result contains the base load address (or link map)
	 of the object that defines sym.  Now add in the symbol
	 offset.  */
	  //获取函数在libc中的实际地址
      value = DL_FIXUP_MAKE_VALUE (result,sym ? (LOOKUP_VALUE_ADDRESS (result)+ sym->st_value) : 0);
    }
  else
    {
      /* We already found the symbol.  The module (and therefore its load
	 address) is also known.  */
      value = DL_FIXUP_MAKE_VALUE (l, l->l_addr + sym->st_value);
      result = l;
    }

  /* And now perhaps the relocation addend.  */
  value = elf_machine_plt_value (l, reloc, value);

  if (sym != NULL && __builtin_expect (ELFW(ST_TYPE) (sym->st_info) == STT_GNU_IFUNC, 0))
		value = elf_ifunc_invoke (DL_FIXUP_VALUE_ADDR (value));

  /* Finally, fix up the plt itself.  */
  if (__glibc_unlikely (GLRO(dl_bind_not)))
    return value;
  //最后把value写入相应的GOT表条目rel_addr中
  return elf_machine_fixup_plt (l, result, refsym, sym, reloc, rel_addr, value);
}
