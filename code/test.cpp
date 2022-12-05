#include <iostream>
#include <iomanip>
#include <stdint.h>

uint16_t
cksum(const void* _data, int len)
{
  const uint8_t* data = reinterpret_cast<const uint8_t*>(_data);
  uint32_t sum;

  for (sum = 0;len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  return sum ? sum : 0xffff;
}

uint16_t compute_cksum(uint16_t* data, size_t len, int cksum_index) {
    data[cksum_index] = 0;
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += data[i];
    }
    uint32_t carry;
    while (sum > 0xffff) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    data[cksum_index] = sum;
    return sum;
}

int main() {

    uint16_t data[10] = {0x4500, 0x0073, 0x0000, 0x4000, 0x4011, 0xb861, 0xc0a8, 0x0001, 0xc0a8, 0x00c7};
    uint16_t sum = ~cksum(data, 20);
    std::cout << std::hex << sum;

}