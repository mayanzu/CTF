#include<stdio.h>
#include<unistd.h>
void init()
{
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
	setvbuf(stderr, 0, 2, 0);
}
int get_size()
{
	int size;
	scanf("%d", &size);
	size = abs(size);
	return (size % 0x30) & 0xff;
}
int main()
{
	init();
	char buf[0x30];
	int size;
	printf("please input you input size\n");
	size = get_size();
	read(0, buf, size);
	puts(buf);
}
