#include <botan/hash.h>
#include <iostream>
#include <memory>
int main() {
    auto h = Botan::HashFunction::create("SHA-256");
    if(!h) return 1;
    h->update(reinterpret_cast<const uint8_t*>("abc"), 3);
    auto out = h->final_stdvec();
    std::cout << "SMOKE_RESULT target=botan ok=1 outlen=" << out.size() << "\n";
    return out.empty() ? 1 : 0;
}
