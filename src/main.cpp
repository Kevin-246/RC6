#include <iostream>
#include <RC6.hpp>
#include <vector>

int main(int argc, char* argv[]){
    std::vector<uint8_t> a(16, 0);
    std::vector<uint8_t> key = {1, 2, 3, 4, 5, 6, 7, 8};
    std::cout << "Orginal message: " << std::endl;
    for(int i = 0; i < 16; i++){
        std::cout << static_cast<int>(a[i]) << " ";
    }
    std::cout << std::endl;
    RC6 rc6(key);
    rc6.Encrypt(a.data());
    std::cout << "Encrypted message: " << std::endl;
    for(int i = 0; i < 16; i++){
        std::cout << static_cast<int>(a[i]) << " ";
    }
    std::cout << std::endl;
    rc6.Decrypt(a.data());
    std::cout << "Decrypted message: " << std::endl;
    for(int i = 0; i < 16; i++){
        std::cout << static_cast<int>(a[i]) << " ";
    }
    std::cout << std::endl;
    return 0;
}
