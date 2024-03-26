import hashlib

class Base():
    supported_hash_name = "sha256"
    hashes = {
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha224": hashlib.sha224,
        "sha384": hashlib.sha384,
    }
    def __init__(self):
        pass
    
    def _hash(self, itmes):
        s_ = ''
        h = self.hashes[self.supported_hash_name]()
        for item in itmes:      
            s_ += str(item)
        h.update(s_.encode())
        return int(h.hexdigest(), 16)