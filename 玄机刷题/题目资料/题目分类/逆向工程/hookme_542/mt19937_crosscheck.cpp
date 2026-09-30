#include <cstdint>
#include <iomanip>
#include <iostream>
#include <random>
int main() {
    const std::uint32_t seed = 0x636f;
    std::mt19937 mt(seed);
    std::cout << "SEED=" << seed << " (0x" << std::hex << seed << std::dec << ")\n";
    for (int i=0; i<8; ++i) {
        const auto x=mt();
        std::cout << "MT[" << i << "]=0x" << std::hex << x << " low8=0x" << (x & 0xff) << std::dec << '\n';
    }
}
