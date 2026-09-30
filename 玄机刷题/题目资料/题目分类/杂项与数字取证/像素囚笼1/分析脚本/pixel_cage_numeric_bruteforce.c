#include <stdint.h>
#include <stdio.h>
#include <string.h>
static uint32_t table[256];
static const unsigned char enc[12] = {0x0d,0xc8,0xb1,0x0e,0xc2,0x20,0x10,0x00,0xd0,0x9d,0xaf,0x38};
static uint32_t crc_byte(uint32_t c, unsigned char v) { return table[(c ^ v) & 0xff] ^ (c >> 8); }
static void update(uint32_t *k0, uint32_t *k1, uint32_t *k2, unsigned char p) {
    *k0 = crc_byte(*k0, p);
    *k1 = (*k1 + (*k0 & 0xff)) * 134775813u + 1u;
    *k2 = crc_byte(*k2, (unsigned char)(*k1 >> 24));
}
static int matches(const char *pw, int len) {
    uint32_t k0=0x12345678u,k1=0x23456789u,k2=0x34567890u;
    for (int i=0;i<len;i++) update(&k0,&k1,&k2,(unsigned char)pw[i]);
    unsigned char last=0;
    for (int i=0;i<12;i++) {
        uint32_t t=k2|2u;
        unsigned char plain=enc[i] ^ (unsigned char)((t*(t^1u)) >> 8);
        update(&k0,&k1,&k2,plain);
        last=plain;
    }
    return last==0x9d;
}
static unsigned long long tested=0;
static char pw[9];
static FILE *out;
static void walk(int pos,int target) {
    if(pos==target) { tested++; if(matches(pw,target)) { pw[target]=0; fprintf(out,"%s\n",pw); } return; }
    for(int d=0;d<=9;d++) { pw[pos]=(char)('0'+d); walk(pos+1,target); }
}
int main(void) {
    for(uint32_t i=0;i<256;i++){uint32_t c=i;for(int j=0;j<8;j++)c=(c&1)?(c>>1)^0xedb88320u:c>>1;table[i]=c;}
    out=fopen("pixel_cage_numeric_header_matches.txt","w"); if(!out)return 2;
    for(int n=1;n<=8;n++){walk(0,n);fprintf(stderr,"checked length %d; total %llu\n",n,tested);}
    fclose(out); printf("tested %llu candidates\n",tested); return 0;
}
