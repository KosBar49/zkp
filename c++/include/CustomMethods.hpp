#ifndef CUSTOM_METHODS_HPP
#define CUSTOM_METHODS_HPP
#include <string>

using namespace std;

int mod_pow(int base, int exp, int mod);
int mod_nor(int dividend, int divisor);
uint64_t hash_function(const string& items);

#endif // CUSTOM_METHODS_HPP