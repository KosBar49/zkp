#include "DiscreteLogInteractive.hpp"
#include <cmath>
#include <cassert>

int modPow(int base, int exp, int mod) {
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

DiscreteLogInteractive::DiscreteLogInteractive(int g, int y, int p, int x) 
    : _g(g), _y(y), _p(p), _x(x), gen(rd()), dis(1, p - 1) {}

int DiscreteLogInteractive::commitment() {
    _r = dis(gen);
    return modPow(_g, _r, _p); 
}

int DiscreteLogInteractive::challenge() {
    _challenge = dis(gen);
    return _challenge;
}

int DiscreteLogInteractive::response(int challenge) {
    int response = modPow(_x * challenge + _r, 1, _p - 1);
    return response; 
}

bool DiscreteLogInteractive::verify(int response, int commitment) {
    int lhs = modPow(_g, response,  _p);
    int rhs = (modPow(_y, _challenge, _p) * commitment) % _p;
    return lhs == rhs;
}