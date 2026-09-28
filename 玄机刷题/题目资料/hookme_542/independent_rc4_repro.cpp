#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <random>
#include <string>
#include <vector>
static std::vector<uint8_t> crypt(const std::vector<uint8_t>& in, const std::string& key) {
  uint32_t seed = (uint32_t)(int8_t)key[0] << 8 | (uint32_t)(int8_t)key[1];
  std::mt19937 rng(seed);
  std::array<uint8_t,256> s{};
  for (auto& x : s) x = static_cast<uint8_t>(rng());
  unsigned j=0;
  for (unsigned i=0;i<256;i++) {
    j=(j+s[i]+static_cast<int8_t>(key[i%key.size()]))&255;
    std::swap(s[i],s[j]);
  }
  unsigned i=0; j=0; std::vector<uint8_t> out; out.reserve(in.size());
  for(auto c:in) { i=(i+1)&255; j=(j+s[i])&255; std::swap(s[i],s[j]); out.push_back(c ^ s[(s[i]+s[j])&255]); }
  return out;
}
static std::vector<uint8_t> unhex(const std::string& s) { std::vector<uint8_t> v; for(size_t n=0;n<s.size();n+=2) v.push_back((uint8_t)std::stoul(s.substr(n,2),nullptr,16)); return v; }
static std::string hex(const std::vector<uint8_t>& v) { std::ostringstream o; o<<std::hex<<std::setfill('0'); for(auto x:v)o<<std::setw(2)<<(unsigned)x; return o.str(); }
int main() {
 const std::string key="com.example.hookme";
 const auto cipher=unhex("f235b888b3f4e08bff17e7e29bc3bf67d0f9a1b7b6581bb4a1eb299684e99923a8d193caf91d");
 auto plain=crypt(cipher,key);
 std::cout<<"SEED=0x"<<std::hex<<(((unsigned)(uint8_t)key[0]<<8)|(uint8_t)key[1])<<"\n";
 std::cout<<"PLAINTEXT_HEX="<<hex(plain)<<"\n";
 std::cout<<"PLAINTEXT="<<std::string(plain.begin(),plain.end())<<"\n";
 std::cout<<"REENC_MATCH="<<(crypt(plain,key)==cipher)<<"\n";
}
