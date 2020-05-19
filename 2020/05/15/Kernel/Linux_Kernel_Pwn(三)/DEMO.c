#include<stdio.h>
#include<stdlib.h>
#include<pthread.h>
struct member
{
	int num;
	size_t *name;
};
void *pthread(void *arg)
{
	struct member *tmp;
	puts("Start");
	sleep(2);
	tmp = (struct member*)arg;
	printf("Num:\t%d\n",tmp->num);
	printf("Name:\t%s\n",tmp->name);
	return NULL;
}
int main(int argc,char *argv[])
{
	pthread_t thread; //线程标识符
	struct member *mbr;
	mbr = (struct member *)malloc(sizeof(struct member));
	mbr->num = 1;
	mbr->name ="FMYY";
	if ((pthread_create(&thread, NULL, pthread, (void*)mbr)) == -1)
	{
		puts("Create Error");
		return 1;
	}
	sleep(1); //令线程函数先运行
	puts("Main Continue"); //由于线程函数休眠2s,故main函数先执行
	if(pthread_join(thread,NULL))
	{
		puts("Thread Ended");
		return 0;
	}
	return 0;
}
