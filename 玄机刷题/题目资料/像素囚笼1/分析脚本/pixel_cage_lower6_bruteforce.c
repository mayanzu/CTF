#include <stdint.h>
#include <stdio.h>
static uint32_t table[256];
static const unsigned char enc[12]={0x0d,0xc8,0xb1,0x0e,0xc2,0x20,0x10,0x00,0xd0,0x9d,0xaf,0x38};
static uint32_t cb(uint32_t c,unsigned char v){return table[(c^v)&0xff]^(c>>8);}
static void up(uint32_t *a,uint32_t *b,uint32_t *c,unsigned char p){*a=cb(*a,p);*b=(*b+(*a&255))*134775813u+1u;*c=cb(*c,(unsigned char)(*b>>24));}
static int match(const unsigned char *pw,int n){uint32_t a=0x12345678u,b=0x23456789u,c=0x34567890u;for(int i=0;i<n;i++)up(&a,&b,&c,pw[i]);unsigned char q=0;for(int i=0;i<12;i++){uint32_t t=c|2u;q=enc[i]^(unsigned char)((t*(t^1u))>>8);up(&a,&b,&c,q);}return q==0x9d;}
static unsigned char pw[7];static FILE *out;static unsigned long long tested;
static void walk(int pos,int len){if(pos==len){tested++;if(match(pw,len)){for(int i=0;i<len;i++)fputc(pw[i],out);fputc('\n',out);}return;}for(int c='a';c<='z';c++){pw[pos]=(unsigned char)c;walk(pos+1,len);}}
int main(void){for(uint32_t i=0;i<256;i++){uint32_t c=i;for(int j=0;j<8;j++)c=(c&1)?(c>>1)^0xedb88320u:c>>1;table[i]=c;}out=fopen("pixel_cage_lower6_header_matches.txt","wb");if(!out)return 2;for(int n=1;n<=6;n++){walk(0,n);fprintf(stderr,"checked length %d; total %llu\n",n,tested);}fclose(out);printf("tested %llu printable candidates\n",tested);}



