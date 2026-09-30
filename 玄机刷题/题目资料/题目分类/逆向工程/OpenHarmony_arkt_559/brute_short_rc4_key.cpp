#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static const uint8_t cipher[36] = {0x13,0x8c,0x5f,0xf4,0x28,0x0f,0x93,0x0c,0x0f,0x3c,0x15,0xe8,0xbb,0x72,0xbc,0xb6,0xf8,0xe1,0x1c,0x70,0xec,0xaf,0x0f,0x72,0x4f,0xe4,0x8a,0x4e,0x08,0x23,0x59,0xd4,0x29,0x4e,0xea,0xe4};
static const std::string prefixes[] = {"OHCTF2025{","OHCTF2026{","OpenHarmony{","OpenHarmonyCTF{","flag{","FLAG{","ohctf{","OHCTF{","OHOS{","DASCTF{","HCTF{","NCTF{"};
static const char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
static uint64_t tried=0;
static uint64_t prefix_hits=0;
static uint64_t format_hits=0;

static void test_key(const std::string &key) {
  ++tried;
  std::array<uint8_t,256> s{};
  for (int i=0;i<256;i++) s[i]=(uint8_t)i;
  int j=0;
  for (int i=0;i<256;i++) {
    j=(j+s[i]+(uint8_t)key[(size_t)i%key.size()])&255;
    uint8_t t=s[i]; s[i]=s[j]; s[j]=t;
  }
  int i=0; j=0;
  uint8_t plain[36];
  for (int k=0;k<36;k++) {
    i=(i+1)&255; j=(j+s[i])&255;
    uint8_t t=s[i]; s[i]=s[j]; s[j]=t;
    uint8_t ks=s[(s[i]+s[j])&255];
    plain[k]=cipher[k]^ks;
  }
  bool matched=false;
  for (const auto &prefix:prefixes) {
    if (prefix.size()<=36 && std::memcmp(plain,prefix.data(),prefix.size())==0) {
      matched=true; ++prefix_hits;
      bool printable=true;
      for (uint8_t b:plain) if (b<0x20 || b>0x7e) printable=false;
      bool closed=plain[35]=='}';
      std::printf("PREFIX_MATCH key=%s prefix=%s printable=%d closing_brace=%d plaintext=",key.c_str(),prefix.c_str(),printable,closed);
      for (uint8_t b:plain) std::putchar((b>=0x20&&b<=0x7e)?b:'.');
      std::puts("");
      if(printable&&closed){++format_hits;std::printf("FORMAT_HIT key=%s\n",key.c_str());}
    }
  }
}
static void gen(std::string &key,int maxlen) {
  if ((int)key.size()>=maxlen) return;
  for (char c:alphabet) {
    key.push_back(c);
    test_key(key);
    gen(key,maxlen);
    key.pop_back();
  }
}
int main(){
  std::string key;
  for(int maxlen=1;maxlen<=4;maxlen++) gen(key,maxlen);
  std::printf("SEARCHED_ALNUM_KEY_COUNT=%llu\nPREFIX_MATCH_COUNT=%llu\nVALID_FORMAT_COUNT=%llu\n",(unsigned long long)tried,(unsigned long long)prefix_hits,(unsigned long long)format_hits);
  return 0;
}
