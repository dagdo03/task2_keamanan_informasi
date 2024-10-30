import socket
from static import *
from des import *

def bob():
    key_des = "AABB09182736CCDD"
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostname()
    port = 12345
    client_socket.connect((host, port))
    print(f"Terhubung ke server di {host}:{port}")
    
    while(True):
        text = client_socket.recv(1024).decode()
        if text == "exit":
            print("Alice has left the chat.")
            break
        if len(text) % 16 != 0:
            chiper_text = text[:-1]
        else:
            chiper_text = text
        print("Cipher Text from Alice: " + chiper_text)
        print("Key : " + key_des)

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
        rk_reverse = rk[::-1]
        rkb_reverse = rkb[::-1]
        plain_text = bin2hex(ecb_decrypt(chiper_text, rkb_reverse, rk_reverse))
        if len(text) % 16 != 0:
            padding_len = bin2dec(int(hex2bin(text[-1])))
            plain_text = plain_text[:-padding_len]
        print(f"Decrypted plain text from Alice: {plain_text}")

        response_text = input("Masukkan Plaintext untuk Alice (atau ketik 'exit' untuk keluar): ")
        if response_text == "exit":
            client_socket.send("exit".encode())
            break

        ct, added_char = ecb_encrypt(response_text, rkb, rk)
        original_ct = bin2hex(ct) + added_char
        print("Cipher Text for Alice : ", original_ct)
        client_socket.send(original_ct.encode())
    client_socket.close()

if __name__ == "__main__":
    bob()