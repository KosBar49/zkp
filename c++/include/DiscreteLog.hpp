#ifndef DISCRETE_LOG_HPP
#define DISCRETE_LOG_HPP

#include "ZeroKnowledgeProtocol.hpp"
#include <random>
#include <utility>

using namespace std;

class DiscreteLog : public ZeroKnowledgeProtocol {
private:
    int _g, _y, _p, _x;
    random_device _rd;
    mt19937 _gen;
    uniform_int_distribution<> _dis;

public:
    DiscreteLog(int g, int y, int p, int x = 0);
    pair<int, int> response();
    bool verify(int s, int t);
};

#endif // DISCRETE_LOG_HPP