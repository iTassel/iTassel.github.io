	#include<stdio.h>
	int main()
	{
			//ÐéÄâ»úOPcode 
			FILE *fp;
			int n = 0,R0,R1,R2;
			int *N = &n;
			fp = fopen("bin","w");
			unsigned char S[] =
			{
			0x8,0x1,0x0,0x8,0x3,0x46,0xe,0x15,0xa,0x1,
			0x9,0x2,0xb,0xa,0x1,0xa,0x2,0x9,0x1,0x11,
			0x1,0xd,0x1,0x3,0xf,0x8,0x8,0x1,0x0,0x8,
			0x3,0x47,0xe,0x46,0xa,0x1,0x1a,0x2,0x6,0x1d,
			0x1,0x4,0x14,0x2,0x1,0x19,0x1,0x2,0x1b,0x1,
			0x1,0x1d,0x1,0x6e,0x13,0x1,0x63,0x15,0x1,0x74,
			0x13,0x1,0x66,0x1c,0x2,0x1,0x9,0x1,0x11,0x1,
			0xd,0x1,0x3,0xf,0x22,0x64
			};
			int i = 0;//I±íÊ¾EIP Location 
			while(i<75)
			{
				if(S[i]== 8)
				{
					fprintf(fp,"%d\tmov R%d %d\n",i,S[i+1]-1,S[i+2]);
					i+=3;
				}
				if(S[i] ==9)
				{
					fprintf(fp,"%d\tpop R%d\n",i,S[i+1]-1);
					i+=2;
				}
				if(S[i] == 10)
				{
					fprintf(fp,"%d\tpush R%d\n",i,S[i+1]-1);
					i+=2;
				}
				if(S[i] == 11)
				{
					fprintf(fp,"%d\tR0 = getchar()\n",i);
					i++;
				}
				if(S[i]==12)
				{
					fprintf(fp,"%d\tRO = putchar()\n",i);
					i++;
				}
				if(S[i] == 13)
				{
					fprintf(fp,"%d\tif R%d==R%d\n\t\tmov Rx 0x80\n",i,S[i+1]-1,S[i+2]-1);
					fprintf(fp,"\tif R%d <R%d\n\t\tmov Rx 0x40\n",S[i+1]-1,S[i+2]-1);
					fprintf(fp,"\tif R%d >R%d\n\t\tmov Rx 0x20\n",S[i+1]-1,S[i+2]-1);
					i+=3;
				}
				if(S[i] ==14)
				{
					fprintf(fp,"%d\tjmp %d\n",i,S[i+1]);
					i+=2;
				}
				if(S[i] == 15)
				{
					fprintf(fp,"%d\tand Rx 80h\n",i);
					fprintf(fp,"\ttest Rx Rx\n");
					fprintf(fp,"\tjnz %d\n",S[i+1]);
					i+=2;
				}
				if(S[i] == 16)
				{
					fprintf(fp,"%d\tand Rx 80h\n",i);
					fprintf(fp,"\ttest Rx Rx\n");
					fprintf(fp,"\tjz %d \n",S[i+1]);
					i+=2;
				}
				if(S[i] == 17)
				{
					fprintf(fp,"%d\tinc R%d\n",i,S[i+1]-1);
					i+=2;
				}
				if(S[i] == 18)
				{
					fprintf(fp,"%d\tdec R%d\n",i,S[i+1]-1);
					i+=2;
				}
				if(S[i] == 19)
				{
					fprintf(fp,"%d\tadd R%d %d\n",i,S[i+1]-1,S[i+2]);
					i+=3;
				}
				if(S[i] == 20)
				{
					fprintf(fp,"%d\tsub R%d R%d\n",i,S[i+1]-1,S[i+2]-1);
					i+=3;

				}
				if(S[i] == 21)
				{
					fprintf(fp,"%d\txor R%d %d\n",i,S[i+1]-1,S[i+2]);
					i+=3;
				}
				if(S[i] ==22)
				{
					fprintf(fp,"%d\tand R%d R%d\n",i,S[i+1]-1,S[i+2]-1);
					i+=3;

				}
				if(S[i] == 23)
				{
					fprintf(fp,"%d\tor R%d R%d\n",i,S[i+1]-1,S[i+2]-1);
					i+=3;
				}
				if(S[i] == 25)
				{
					fprintf(fp,"%d\tmov R%d R%d\n",i,S[i+1]-1,S[i+2]-1);
					i+=3;
				}
				if(S[i] == 26)
				{
					fprintf(fp,"%d\tlea R%d [R%d]\n",i,S[i+1]-1,S[i+2]-1);
					i+=3;
				}
				if(S[i] == 27)
				{
					fprintf(fp,"%d\tmov R%d [R%d]\n",i,S[i+1]-1,S[i+2]-1);
					i+=3;
				}
				if(S[i] == 28)
				{
					fprintf(fp,"%d\tmov [R%d] R%d\n",i,S[i+1]-1,S[i+2]-1);
					i+=3;
				}
				if(S[i] == 29)
				{
					fprintf(fp,"%d\tmul R%d %d\n",i,S[i+1]-1,S[i+2]);
					i+=3;
				}
				if(S[i]==100)
				{
					fprintf(fp,"%d\tRet\n",i);
					printf("-------Ret--------\n");
					fclose(fp); 
				}
			}
	}
