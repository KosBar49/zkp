#include <iostream>
#include "DiscreteLog.hpp"
#include "DiscreteLogInteractive.hpp"

using namespace std; 

int main() {
    int g = 2; 
    int x = 5; 
    int p = 13;
    int P = pow(g, x); 

    DiscreteLog* client_a = new DiscreteLog(g, P, p, x);
    DiscreteLog* client_b = new DiscreteLog(g, P, p);
    pair<int, int> result = client_a -> response(); 
    bool verify =  client_b -> verify(result.first, result.second);
    if (verify) {
        cout << "#1 Verification successful!" << endl;
    } else {
        cout << "#1 Verification failed" << endl;
    }

    delete client_a; 
    delete client_b;

    DiscreteLogInteractive* client_c = new DiscreteLogInteractive(g, P, p, x);
    DiscreteLogInteractive* client_d = new DiscreteLogInteractive(g, P, p);

    int t = client_c -> commitment();
    int c = client_d -> challenge();
    int s = client_c -> response(c);
    verify = client_d -> verify(s, t);
    if (verify) {
        cout << "#2 Verification successful!" << endl;
    } else {
        cout << "#2 Verification failed" << endl;
    }
    
    delete client_c; 
    delete client_d; 

    return 0;
}