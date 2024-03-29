import time
import matplotlib.pyplot as plt
import random
from sympy import primerange
from zkps.zkp_log_disjunction import DiscreteLogDisjunctionEcc
from statistics import median
from zkps.elliptic_curve import get_curve

curve = get_curve('secp256r1')
g1, h1, g2, h2 = curve.get_generators(4)

def test_performance(max_bits=20, step=2, simulations=5, zkp_class=DiscreteLogDisjunctionEcc):
    x_ = []
    y_r = []
    y_v = []
    
    # Loop through each bit length
    for bits in range(3, max_bits + 1, step):
        times_r = []
        times_v = []

        # Run the protocol N=simulations times
        for i in range(simulations):
            print(f"Running simulation {i+1}/{simulations} for {bits} bits")
            primes = list(primerange(2**(bits - 1), 2**bits))
            if not primes:
                continue
            p = random.choice(primes)

            x = random.randint(1, p - 2)  # Private key
            y = random.randint(1, p - 2)  # Private key
            
            P = curve.scalar_mult(x, g1)
            Q = curve.scalar_mult(y, h1)
            
            client_a = zkp_class(x)
            client_b = zkp_class()
            
            s_r = time.time()
            t1c1s1, t2c2s2 = client_a.response(g1, h1, P, Q)
            e_r = time.time()
            
            s_v = time.time()
            client_b.verify(g1, h1, P, Q, t1c1s1, t2c2s2)
            e_v = time.time()

            times_r.append(e_r - s_r)
            times_v.append(e_v - s_v)

    
        y_v.append(median(times_v))     
  
        y_r.append(median(times_r))
        
        x_.append(bits)
        
    plt.plot(x_, y_v, marker='o', label = 'verify')
    plt.plot(x_, y_r, marker='o', label = 'response')
    plt.title(f'Medium Perf. of {zkp_class.__name__} with Inc. Parameter Sizes')
    plt.xlabel('Bit length of p')
    plt.ylabel('Medium execution time (seconds)')
    plt.grid(True)
    plt.legend()
    plt.savefig(f'images/{zkp_class.__name__}_{str(bits)}bits.png')


if __name__ == "__main__":
    test_performance(max_bits=20, step=1, simulations=150)