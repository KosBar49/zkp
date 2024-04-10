#include "DiscreteLogInteractive.hpp"
#include "CustomMethods.hpp"
#include <cmath>
#include <cassert>

DiscreteLogInteractive::DiscreteLogInteractive(int g, int y, int p, int x) 
    : _g(g), _y(y), _p(p), _x(x), gen(rd()), dis(1, p - 1) {}

int DiscreteLogInteractive::commitment() {
    _r = dis(gen);
    return mod_pow(_g, _r, _p);
}

int DiscreteLogInteractive::challenge() {
    _challenge = dis(gen);
    return _challenge;
}

int DiscreteLogInteractive::response(int challenge) {
    int response = mod_pow(_x * challenge + _r, 1, _p - 1);
    return response; 
}

bool DiscreteLogInteractive::verify(int response, int commitment) {
    int lhs = mod_pow(_g, response,  _p);
    int rhs = (mod_pow(_y, _challenge, _p) * commitment) % _p;
    return lhs == rhs;
}