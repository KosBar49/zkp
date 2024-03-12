from hashlib import sha256

class Base():
    supported_hash = sha256
    def __init__(self):
        pass
    
    def _hash(self, itmes):
        s_ = ''
        h = self.supported_hash()
        for item in itmes:      
            s_ += str(item)
        h.update(s_.encode())
        return int(h.hexdigest(), 16)