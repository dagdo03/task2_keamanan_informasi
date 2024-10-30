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
        plain_text = input("Masukkan Plaintext (atau ketik 'exit' untuk keluar): ")
        if plain_text != "exit":
            print("Plaintext: " + plain_text)
            print("Key: " + key_des)
            key_des = hex2bin(key_des)
            key_des = permute(key_des, keyp, 56)
            left = key_des[0:28]
            right = key_des[28:56]
            rkb = []
            rk = []
            
            for i in range(0, 16):
                left = shift_left(left, shift_table[i])
                right = shift_left(right, shift_table[i])
                combine_str = left + right
                round_key = permute(combine_str, key_comp, 48)
                rkb.append(round_key)
                rk.append(bin2hex(round_key))
            
            print("Encryption")
            ct, added_char = ecb_encrypt(plain_text, rkb, rk)
            original_ct = bin2hex(ct) + added_char
            print("Cipher Text : ", original_ct)
            client_socket.send(original_ct.encode())
        else:
            client_socket.send("exit".encode())
            break
        
        response = client_socket.recv(1024).decode()
        if response == "exit":
            print("Bob has left the chat.")
            break

        if len(response) % 16 != 0:
            chiper_text = response[:-1]
        else:
            chiper_text = response
        print("Cipher Text from Bob: " + chiper_text)
        
        rk_reverse = rk[::-1]
        rkb_reverse = rkb[::-1]
        decrypted_response = bin2hex(ecb_decrypt(chiper_text, rkb_reverse, rk_reverse))
        if len(response) % 16 != 0:
            padding_len = bin2dec(int(hex2bin(response[-1])))
            decrypted_response = decrypted_response[:-padding_len]
        print(f"Decrypted plain text from Bob: {decrypted_response}")
    client_socket.close()
    server_socket.close()

if __name__ == '__main__':
    alice()