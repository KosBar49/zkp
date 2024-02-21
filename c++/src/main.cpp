#include "DiscreteLogInteractive.hpp"

using namespace std; 

int main() {
    int g = 2; 
    int x = 5; 
    int p = 13;
    int P = pow(g, x); 
    DiscreteLogInteractive client_a(g, P, p, x);
    DiscreteLogInteractive client_b(g, P, p);
    int t = client_a.commitment();
    int c = client_b.challenge(); 
    int s = client_a.response(c); 
    cout << client_b.verify(s, t) << endl;
    return 0;
}