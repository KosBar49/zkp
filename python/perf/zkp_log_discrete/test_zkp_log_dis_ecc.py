import time
import matplotlib.pyplot as plt
import random
from sympy import primerange
from zkps.zkp_log_discrete import DiscreteLogEcc
from statistics import median

def test_performance(max_bits=20, step=2, simulations=5, zkp_class=DiscreteLogEcc):
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
            g = 2  # Simple generator for demonstration; in real scenarios, check its properties.
            x = random.randint(1, p - 2)  # Private key
            
            client_a = zkp_class(x)
            client_b = zkp_class()
            
            s_r = time.time()
            t, s = client_a.response()
            e_r = time.time()
            
            s_v = time.time()
            client_b.verify(s, t)
            e_v = time.time()

            times_r.append(e_r - s_r)
            times_v.append(e_v - s_v)

        #avg_time_v = sum(times_v) / len(times_v)
        y_v.append(median(times_v))
        
        #avg_time_r = sum(times_r) / len(times_r)
        y_r.append(median(times_r))
        
        x_.append(bits)
        
    plt.plot(x_, y_v, marker='o', label = 'verify')
    plt.plot(x_, y_r, marker='o', label = 'response')
    plt.title(f'Median of the time execution for {zkp_class.__name__}')
    plt.xlabel('Bit length of p')
    plt.ylabel('Medium execution time (seconds)')
    plt.grid(True)
    plt.legend()
    plt.savefig(f'images/{zkp_class.__name__}_{str(bits)}bits.png')


if __name__ == "__main__":
    test_performance(max_bits=20, step=1, simulations=150)