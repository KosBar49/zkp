#include <string>
#include <unordered_map>
#include <stdexcept>

class EllipticCurve {
public:
    std::string name;
    unsigned long long a, b;
    std::pair<unsigned long long, unsigned long long> g;
    unsigned long long n, p;

    EllipticCurve(
        std::string name, 
        unsigned long long a, 
        unsigned long long b, 
        std::pair<unsigned long long, unsigned long long> g, 
        unsigned long long n, 
        unsigned long long p
    ) : name(name), a(a), b(b), g(g), n(n), p(p) {}
};

class CurveFactory {
private:
    std::unordered_map<std::string, EllipticCurve> curves;

public:
    CurveFactory() {
        curves["secp256k1"] = EllipticCurve(
            "secp256k1",
            0,
            7,
            {55066263022277343669578718895168534326250603453777594175500187360389116729240ULL,
             32670510020758816978083085130507043184471273380659243275938904335757337482424ULL},
            115792089237316195423570985008687907853269984665640564039457584007908834671663ULL,
            115792089237316195423570985008687907852837564279074904382605163141518161494337ULL
        );

        // Add other curves similarly...
    }

    EllipticCurve getCurve(const std::string& type) {
        if (curves.find(type) != curves.end()) {
            return curves[type];
        } else {
            throw std::invalid_argument(type + " not supported");
        }
    }
};

int main() {
    CurveFactory factory;
    try {
        EllipticCurve curve = factory.getCurve("secp256k1");
        // Use curve here...
    } catch (const std::exception& e) {
        // Handle exception...
    }
    
    return 0;
}
