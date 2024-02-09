#include <RC6.hpp>

RC6::RC6(std::vector<uint8_t>& key){
    uint32_t c;
    uint32_t i;
    uint32_t j;
    uint32_t s;
    uint32_t v;
    uint32_t a;
    uint32_t b;
    
    uint32_t keyLength = static_cast<uint32_t>(key.size());
    
    if(keyLength > RC6_MAX_KEY_SIZE) keyLength = RC6_MAX_KEY_SIZE;
    
    std::memset(this -> l, 0, RC6_MAX_KEY_SIZE);
    std::memcpy(this -> l, key.data(), keyLength);
    
    c = (keyLength > 0) ? (keyLength + 3) / 4 : 1;
    
    this -> s[0] = P32;
    
    for(i = 1; i < (2 * RC6_ROUNDS + 4); i++){
        this -> s[i] = this -> s[i - 1] + Q32;
    }
    
    i = 0;
    j = 0;
    a = 0;
    b = 0;
    
    v = 3 * MAX(c, 2 * RC6_ROUNDS + 4);
    
    for(s = 0; s < v; s++){
        this -> s[i] += a + b;
        this -> s[i] = ROL32(this -> s[i], 3);
        a = this -> s[i];
        
        this -> l[j] += a + b;
        this -> l[j] = ROL32(this -> l[j], (a + b) % 32);
        b = this -> l[j];
        
        if(++i >= (2 * RC6_ROUNDS + 4)) i = 0;
        if(++j >= c) j = 0;
    }
}

void RC6::Encrypt(uint8_t input[16]){
    uint32_t t;
    uint32_t u;
    
    uint32_t a = (input[0] << 24) | (input[1] << 16) | (input[2] << 8) | (input[3]);
    uint32_t b = (input[4] << 24) | (input[5] << 16) | (input[6] << 8) | (input[7]);
    uint32_t c = (input[8] << 24) | (input[9] << 16) | (input[10] << 8) | (input[11]);
    uint32_t d = (input[12] << 24) | (input[13] << 16) | (input[14] << 8) | (input[15]);
    
    b += this -> s[0];
    d += this -> s[1];
    
    for(int i = 1; i <= RC6_ROUNDS; i++){
        t = (b * (2 * b + 1));
        t = ROL32(t, 5);
        
        u = (d * (2 * d + 1));
        u = ROL32(u, 5);
        
        a ^= t;
        a = ROL32(a, u % 32) + this -> s[2 * i];
        
        c ^= u;
        c = ROL32(c, t % 32) + this -> s[2 * i + 1];
        
        t = a;
        a = b;
        b = c;
        c = d;
        d = t;
    }
    a += this -> s[2 * RC6_ROUNDS + 2];
    c += this -> s[2 * RC6_ROUNDS + 3];
    
    input[0] = (a >> 24) & 0xFF;
    input[1] = (a >> 16) & 0xFF;
    input[2] = (a >> 8) & 0xFF;
    input[3] = (a) & 0xFF;
    
    input[4] = (b >> 24) & 0xFF;
    input[5] = (b >> 16) & 0xFF;
    input[6] = (b >> 8) & 0xFF;
    input[7] = (b) & 0xFF;
    
    input[8] = (c >> 24) & 0xFF;
    input[9] = (c >> 16) & 0xFF;
    input[10] = (c >> 8) & 0xFF;
    input[11] = (c) & 0xFF;
    
    input[12] = (d >> 24) & 0xFF;
    input[13] = (d >> 16) & 0xFF;
    input[14] = (d >> 8) & 0xFF;
    input[15] = (d) & 0xFF;
}

void RC6::Decrypt(uint8_t input[16]){
    uint32_t t;
    uint32_t u;
    
    uint32_t a = (input[0] << 24) | (input[1] << 16) | (input[2] << 8) | (input[3]);
    uint32_t b = (input[4] << 24) | (input[5] << 16) | (input[6] << 8) | (input[7]);
    uint32_t c = (input[8] << 24) | (input[9] << 16) | (input[10] << 8) | (input[11]);
    uint32_t d = (input[12] << 24) | (input[13] << 16) | (input[14] << 8) | (input[15]);
    
    c -= this -> s[2 * RC6_ROUNDS + 3];
    a -= this -> s[2 * RC6_ROUNDS + 2];
    
    for(int i = RC6_ROUNDS; i > 0; i--){
        t = d;
        d = c;
        c = b;
        b = a;
        a = t;
        
        u = (d * (2 * d + 1));
        u = ROL32(u, 5);
        
        t = (b * (2 * b + 1));
        t = ROL32(t, 5);
        
        c -= this -> s[2 * i + 1];
        c = ROR32(c, t % 32) ^ u;
        
        a -= this -> s[2 * i];
        a = ROR32(a, u % 32) ^ t;
    }
    
    d -= this -> s[1];
    b -= this -> s[0];
    
    input[0] = (a >> 24) & 0xFF;
    input[1] = (a >> 16) & 0xFF;
    input[2] = (a >> 8) & 0xFF;
    input[3] = (a) & 0xFF;
    
    input[4] = (b >> 24) & 0xFF;
    input[5] = (b >> 16) & 0xFF;
    input[6] = (b >> 8) & 0xFF;
    input[7] = (b) & 0xFF;
    
    input[8] = (c >> 24) & 0xFF;
    input[9] = (c >> 16) & 0xFF;
    input[10] = (c >> 8) & 0xFF;
    input[11] = (c) & 0xFF;
    
    input[12] = (d >> 24) & 0xFF;
    input[13] = (d >> 16) & 0xFF;
    input[14] = (d >> 8) & 0xFF;
    input[15] = (d) & 0xFF;
}
