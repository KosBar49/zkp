import time
import matplotlib.pyplot as plt
import random
from sympy import primerange
from zkps.zkp_pederesen_commitments_messages import PedersenCommitmentsEqualMessagesInteractive as zkp_class
from statistics import median

def test_performance(max_bits=20, step=2, simulations=5, zkp_class=zkp_class):
    x_ = []
    y_r = []
    y_v = []
    
    # Loop through each bit length
    for bits in range(3, max_bits + 1, step):
        times_v = []
        times_r = []
        
        # Run the protocol N=simulations times
        for i in range(simulations):
            print(f"Running simulation {i+1}/{simulations} for {bits} bits")
            primes = list(primerange(2**(bits - 1), 2**bits))
            if not primes:
                continue
            
            p = random.SystemRandom().choice(primes)
            g = 3
            h = 7
            
            x = random.randint(1, p - 2 ) # Private key
            y = random.randint(1, p - 2)
            z = random.randint(1, p - 2)  # Private key
            
            P = ( pow(g, x, p) * pow(h, y, p) ) % p
            Q = ( pow(g, x, p) * pow(h, z, p) ) % p
            
            client_a = zkp_class(p, g, h, x, y, z)
            
            client_b = zkp_class(p, g, h)
            
            c = client_b.challenge()
            
            s_r = time.time()
            t1s1, t2s2, s3 = client_a.response(c)
            e_r = time.time()
            
            s_v = time.time()
            client_b.verify(P, Q, t1s1, t2s2, s3)
            e_v = time.time()

            times_r.append(e_r - s_r)
            times_v.append(e_v - s_v)
            
        # Compute the average execution time for this bit length
        #avg_time_v = sum(times_v) / len(times_v)
        y_v.append(median(times_v))
        
        #avg_time_r = sum(times_r) / len(times_r)
        y_r.append(median(times_r))
        
        x_.append(bits)

    plt.plot(x_, y_r, marker='o', label = 'response')
    plt.plot(x_, y_v, marker='o', label = 'verify')
    plt.title(f'Median of the time execution for {zkp_class.__name__}')
    plt.xlabel('Bit length of p')
    plt.ylabel('Median execution time (seconds)')
    plt.grid(True)
    plt.legend()
    plt.savefig(f'images/{zkp_class.__name__}_{str(bits)}bits.png')
    


if __name__ == "__main__":
    test_performance(max_bits=20, step=1, simulations=15)