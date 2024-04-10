// ZeroKnowledgeProtocol.hpp
#ifndef ZERO_KNOWLEDGE_PROTOCOL_INTERACTIVE_HPP
#define ZERO_KNOWLEDGE_PROTOCOL_INTERACTIVE_HPP

class ZeroKnowledgeProtocolInteractive {
public:
    virtual int response(int statement) = 0;
    virtual int challenge() = 0;
    virtual bool verify(int statement, int proof) = 0;
    virtual ~ZeroKnowledgeProtocolInteractive() {}
};

#endif // ZERO_KNOWLEDGE_PROTOCOL_INTERACTIVE_HPP