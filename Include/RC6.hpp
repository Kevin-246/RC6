#pragma once

#include <vector>
#include <cstdint>

#define RC6_MAX_KEY_SIZE 64 // Maximum allowed by standard is 255
#define RC6_ROUNDS 20

#define P32 0xB7E15163
#define Q32 0x9E3779B9

#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define ROL32(a, n) (((a) << (n)) | ((a) >> (32 - (n))))
#define ROR32(a, n) (((a) >> (n)) | ((a) << (32 - (n))))

class RC6{
private:
    uint32_t l[RC6_MAX_KEY_SIZE / 4];
    uint32_t s[2 * RC6_ROUNDS + 4];
public:
    RC6(std::vector<uint8_t>& key);

    void Encrypt(uint8_t input[16]);
    void Decrypt(uint8_t input[16]);
};
