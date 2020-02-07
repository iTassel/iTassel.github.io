#include<stdio.h>
void func(char P[])
{
	unsigned char I[8];
	unsigned char II[8];
	for(int i =0;i<8;i++)
	{
		for(int p =0;p<16;p++)
			{
				for(int q =0;q<16;q++)
					{
						if(P[i] == (16*p + q))
						{
							I[i] = p;
							II[i]= q;
						}
					}
			}
	}
	for(int n =0;n<8;n++)
	{
		printf("%d",I[n]);
		printf("%d",II[n]);
	}
	putchar(10);

	for(int i =0;i<8;i++)
	{
		if(I[i]>=0 && I[i]<=9)
			I[i] +=48;
		else if(I[i] >=10 && I[i]<=15)
			I[i] +=87;
		else
			puts("Wrong");
		if(II[i] >=0 && II[i] <=9)
			II[i] +=48;
		else if(II[i] >=10 && II[i]<=15)
			II[i] +=87;
		else
			puts("Wrong");
	}

	for(int n =0;n<8;n++)
	{
		printf("%c",I[n]);
		printf("%c",II[n]);
	}
	putchar(10);
}
int main()
{
	char str1[] = "e4sy_Re_";
	char str2[] = "Easylif3";
	char list[] = {76,60,-42,54,80,-120,32,-52};
	char I[8];
	char II[8];
	char III[8];
	char IV[8];
	for(int i = 0;i<8;i++)
		I[i] = (list[i]^str1[i]);
	for(int i = 0;i<8;i++)
		II[i] = ((list[i]^str1[i])^str2[i]);
	for(int i =0;i<8;i++)
	{
		for(int n =0;n<256;n++)
		{
			if(I[i] == (n&0x55 ^ ((II[7-i]&0xAA)>>1) | n&0xAA)%256)
				III[i] = n;
		}
		for(int n =0;n<256;n++)
		{
			if(II[7-i] == (2*(III[i]&0x55)^n&0xAA | n&0x55)%256)
				IV[7-i] = n;
		}
		for(int n =0;n<256;n++)
		{
			if(III[i] == (n&0x55 ^ ((IV[7-i]&0xAA)>>1) | n&0xAA)%256)
				III[i] = n;
		}
		for(int n = 0;n<256;n++)
		{
			if(III[i] == (((n&0xE0)>>5) | 8*n)%256)
				III[i] = n;
		}

	}
	func(III);
	func(IV);
}
