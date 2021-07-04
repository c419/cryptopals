#!/bin/env python
import base64

class Set1:
    @staticmethod
    def challenge1(hex_str):
        """Converts string containing hex to base64 bytes
        >>> input = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
        >>> Set1.challenge1(input)
        b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
        """
        b = bytes.fromhex(hex_str)
        return base64.b64encode(b)

    @staticmethod
    def challenge2(buf1, buf2):
        """Returning XOR of two equal-length bufers
        >>> buf1 = '1c0111001f010100061a024b53535009181c'
        >>> buf2 = '686974207468652062756c6c277320657965'
        >>> Set1.challenge2(buf1, buf2)
        '746865206b696420646f6e277420706c6179'
        """
        n1, n2 = (int(buf1, 16), int(buf2, 16))
        return f'{n1 ^ n2:x}'

    
    common_char_pairs = []
    with open("char_pairs.txt") as f:
        for line in f:
            common_char_pairs.append(line.strip())

    @staticmethod
    def challenge3(encrypted_str, common_char_pairs=common_char_pairs):
        """Decrypts with XOR, arguments are hex strings
        """
        import string
        def decrypt(encrypted_hexstr,cypher_str):
            from itertools import cycle
            encrypted_bytes = bytes.fromhex(encrypted_hexstr) 
            cypher_bytes = cypher_str.encode("ascii")
            try:
                return bytes( a ^ b for a, b in zip(encrypted_bytes, cycle(cypher_bytes))).decode('ascii')
            except:
                return ''
    
        def score(text):
            score = 0
            for common_char in common_char_pairs:
                score += text.count(common_char)
            return score

        peak_decrypt, peak_cypher = ('', '')
        max_score = 0
        printset = set(string.printable)
        for c in string.printable:
            decrypt_str = decrypt(encrypted_str,c)
            sc = score(decrypt_str)
            if not set(decrypt_str).issubset(printset):
                continue
            #if decrypt_str:
            #    print(f"{sc} > {decrypt_str}")
            if sc > max_score:
                max_score = sc
                peak_decrypt, peak_cypher = (decrypt_str, c)

        if peak_decrypt:
            print(f"Highest >>{peak_cypher}>> {peak_decrypt}")
        return max_score, peak_decrypt

    @staticmethod
    def challenge4():
        max_score = 0
        max_string = str()
        max_orig = str()
        with open("4.txt") as f:
            for line in f:
                line_score, line_decrypt = Set1.challenge3(line.strip())
                if line_score > max_score:
                    max_score = line_score
                    max_string = line_decrypt
                    max_orig = line

        print(f"{max_orig}\n{max_string}")

            
    @staticmethod
    def encrypt(data_bytes, cypher_bytes):
        from itertools import cycle
        return bytes( a ^ b for a, b in zip(data_bytes, cycle(cypher_bytes)))

    @staticmethod
    def challenge5(s, c):
        r"""
        >>> s = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        >>> c = "ICE"
        >>> Set1.challenge5(s, c)
        b'0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'

        """
        return Set1.encrypt(s.encode('ascii'), c.encode('ascii')).hex().encode('ascii')


    



if __name__ == '__main__':
    import doctest
    doctest.testmod()
