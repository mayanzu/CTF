#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
int main(void){
  const unsigned char target[16]={0x72,0x0b,0x44,0x55,0xc9,0x1b,0x6a,0x02,0x41,0x35,0x34,0x33,0x86,0xb6,0x67,0x9d};
  uint32_t start=1735689600u, end=1761955200u;
  for(uint32_t s=start;s<end;s++){
    srand(s); for(int i=0;i<16;i++) rand();
    int j=0; for(;j<4;j++) if(((unsigned char)rand())!=target[j]) break;
    if(j<4) continue;
    unsigned char got[16]; for(int i=0;i<4;i++) got[i]=target[i];
    for(int i=4;i<16;i++) got[i]=(unsigned char)rand();
    int ok=1; for(int i=0;i<16;i++) if(got[i]!=target[i]) ok=0;
    if(ok){ printf("MATCH seed=%u\n",s); return 0; }
  }
  puts("no match in 2025-01-01 through 2025-10-31 UTC"); return 1;
}
