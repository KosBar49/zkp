from machine import Pin
import time 

p = Pin(2, Pin.OUT)

while True: 
    
    p.value(1)
    time.sleep(1)
    p.value(0)
    time.sleep(10)
        
