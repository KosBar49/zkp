// DiscreteLogInteractive.hpp
#ifndef DISCRETE_LOG_INTERACTIVE_HPP
#define DISCRETE_LOG_INTERACTIVE_HPP

#include "ZeroKnowledgeProtocolInteractive.hpp"
#include <random>

using namespace std;

class DiscreteLogInteractive : public ZeroKnowledgeProtocolInteractive {
private:
    int _g, _y, _p, _x, _r, _challenge;
    random_device rd;
    mt19937 gen;
    uniform_int_distribution<> dis;

public:
    DiscreteLogInteractive(int g, int y, int p, int x = 0 );
    int commitment();
    int challenge() override;
    int response(int challenge) override;
    bool verify(int response, int commitment) override;
};

#endif // DISCRETE_LOG_INTERACTIVE_HPP