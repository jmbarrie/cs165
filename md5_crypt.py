import hashlib

class MD5_Crypt:
    def __init__(self, password, salt, max_password_length):
        self.password = password.encode('utf-8')
        self.password_length = max_password_length
        self.salt = salt.encode('utf-8')
        self.magic = '$1$'.encode('utf-8')
        self.base64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

    def get_hash(self):
        """
        Uses helper methods to calculate the expected hash using md5-crypt.

        returns the calculated hash as a string.
        """
        intermediate = self._calculate_intermediate()
        intermediate = self._loop(intermediate.digest())
        base64_output = self._calculate_base64_hash(intermediate)

        hash_solution = self.magic.decode() + self.salt.decode() + '$' + base64_output

        return hash_solution

    def _calculate_alternate_sum(self):
        """
        Calculates the alternate sum.

        returns hashlib md5 object.
        """
        return hashlib.md5(self.password + self.salt + self.password)
    
    def _calculate_intermediate(self):
        """
        Calculates the intermediate.

        returns hashlib md5 object.
        """
        intermediate = self.password + self.magic + self.salt
        alternate_sum = self._calculate_alternate_sum()
        length_bits = pass_length = self.password_length

        while pass_length > 0:
            temp_digest  = alternate_sum.digest()
            intermediate += temp_digest[0:min(16, pass_length)]
            pass_length -= 16

        while length_bits:
            if length_bits & 1:
                intermediate += chr(0).encode('utf-8')
            else:
                intermediate += self.password[0:1]

            length_bits >>= 1

        return hashlib.md5(intermediate)

    def _loop(self, intermediate):
        """
        Loop 1000 times calculating a new md5 hash based on an alternating
        concatenation of password, salt, and intermediate values.

        returns intermediate bytes.
        """
        for i in range(0, 1000):
            temp = b''
            if i % 2 == 0:
                temp += intermediate
            else:
                temp += self.password
            if i % 3:
                temp += self.salt
            if i % 7:
                temp += self.password
            if i % 2 == 0 :
                temp += self.password
            else:
                temp += intermediate
            
            intermediate = hashlib.md5(temp).digest()

        return intermediate

    def _calculate_base64_hash(self, intermediate):
        """ 
        We will be picking out 16 bytes as described in the Vidar blog post.

        returns the base64 hash string
        """        
        idx = [0, 6, 12, 1, 7, 13, 2, 8, 14, 3, 9, 15, 4, 10, 5, 11]
        size = 4
        h = intermediate

        ret = ''
        for i in range(0, 16, 3):
            if idx[i] == 11:
                ret += self._to64(h[idx[i]], int(size / 2))
            else:
                ret += self._to64((h[idx[i]] << 16) | (h[idx[i + 1]] << 8) | (h[idx[i + 2]]), size)
        
        return ret

    def _to64(self, intermediate_bits, size):
        """
        Converts intermediate bits to base64.
        """
        ret = ''
        for i in range(1, size + 1):
            ret += self.base64[intermediate_bits & 0x3f]
            intermediate_bits >>= 6
        
        return ret
