// ZeroKnowledgeProtocol.hpp
#ifndef ZERO_KNOWLEDGE_PROTOCOL_HPP
#define ZERO_KNOWLEDGE_PROTOCOL_HPP
#include <utility>

using namespace std;

class ZeroKnowledgeProtocol {
public:
    virtual pair<int, int> response() = 0;
    virtual bool verify(int statement, int proof) = 0;
    virtual ~ZeroKnowledgeProtocol() {}
};

#endif // ZERO_KNOWLEDGE_PROTOCOL_HPP