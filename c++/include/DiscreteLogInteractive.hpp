// DiscreteLogInteractive.hpp
#ifndef DISCRETE_LOG_INTERACTIVE_HPP
#define DISCRETE_LOG_INTERACTIVE_HPP

#include "ZeroKnowledgeProtocol.hpp"
#include <random>
#include <iostream>

class DiscreteLogInteractive : public ZeroKnowledgeProtocol {
private:
    int _g, _y, _p, _x, _r, _challenge;
    std::random_device rd;
    std::mt19937 gen;
    std::uniform_int_distribution<> dis;

public:
    DiscreteLogInteractive(int g, int y, int p, int x = 0 );
    int commitment();
    int challenge() override;
    int response(int challenge) override;
    bool verify(int response, int commitment) override;
};

#endif // DISCRETE_LOG_INTERACTIVE_HPP