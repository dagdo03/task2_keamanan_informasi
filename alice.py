import socket
from static import *
from des import *

def alice():
    key_des = "AABB09182736CCDD"
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostname()
    port = 12345
    server_socket.bind((host, port))
    server_socket.listen()
    print(f"Server berjalan di {host}:{port}")
    client_socket, addr = server_socket.accept()
    print(f"Menerima koneksi dari {addr}")
    print("Let's Talks with bob")
    while(True):
        plain_text = input("Masukkan Plaintext: ")
        if(plain_text != "exit"):
            print("Plaintext: " + plain_text)
            print("Key: " + key_des)
            key_des = hex2bin(key_des)
            key_des = permute(key_des, keyp, 56)
            # Splitting
            left = key_des[0:28]    # rkb for RoundKeys in binary
            right = key_des[28:56]  # rk for RoundKeys in hexadecimal
            rkb = []
            rk = []
            
            for i in range(0, 16):
                # Shifting the bits by nth shifts by checking from shift table
                left = shift_left(left, shift_table[i])
                right = shift_left(right, shift_table[i])
                # Combination of left and right string
                combine_str = left + right
                # Compression of key_des from 56 to 48 bits
                round_key = permute(combine_str, key_comp, 48)
                rkb.append(round_key)
                rk.append(bin2hex(round_key))
            
            print("Encryption")
            ct, added_char = ecb_encrypt(plain_text, rkb, rk)
            original_ct = bin2hex(ct) + added_char
            print("Cipher Text : ", original_ct)
            client_socket.send(original_ct.encode())
        else:
            return

if __name__ == '__main__':
    alice()
        
