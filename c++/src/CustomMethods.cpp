#include "CustomMethods.hpp"
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <string>

using namespace std;

int mod_pow(int base, int exp, int mod) {
    int result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return result;
}

int mod_nor(int dividend, int divisor) {
    int result = dividend % divisor;
    if (result < 0 && divisor > 0) {
        result += divisor;
    } else if (result >= 0 && divisor < 0) {
        result -= divisor;
    }
    return result;
}

uint64_t hash_function(const string& items) {
    string s = items;
    CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
    CryptoPP::SHA256 hash;
    hash.CalculateDigest(digest, (const CryptoPP::byte*)s.data(), s.length());

    uint64_t result = 0;
    for (int i = 0; i < CryptoPP::SHA256::DIGESTSIZE; i++) {
        result += digest[i];
    }
    return result;
}