#include "DiscreteLog.hpp"
#include "CustomMethods.hpp"
#include <iostream>
#include <string>
#include <utility>

using namespace std; 

DiscreteLog::DiscreteLog(int g, int y, int p, int x)
    : _g(g), _y(y), _p(p), _x(x), _gen(_rd()), _dis(1, p - 1) {}

pair<int, int> DiscreteLog::response() {
    int v = _dis(_gen); 
    int t = mod_pow(_g, v, _p) % _p;
    string hash_data = to_string(_g) + to_string(_y) + to_string(t);
    int c = hash_function(hash_data);
    return { t, mod_nor(( v - c * _x), (_p - 1)) };
}

bool DiscreteLog::verify(int s, int t) {

    string hash_data = to_string(_g) + to_string(_y) + to_string(t);
    int c = hash_function(hash_data);
    int check = mod_nor(mod_pow(_g, s, _p) * mod_pow(_y, c, _p), _p);
    return t = check;
    
}