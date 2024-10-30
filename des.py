from static import *
import random
# Fungsi untuk mengkonversi dari hexadecimal ke binary
def hex2bin(s):
	mp = {'0': "0000",
		'1': "0001",
		'2': "0010",
		'3': "0011",
		'4': "0100",
		'5': "0101",
		'6': "0110",
		'7': "0111",
		'8': "1000",
		'9': "1001",
		'A': "1010",
		'B': "1011",
		'C': "1100",
		'D': "1101",
		'E': "1110",
		'F': "1111"}
	bin = ""
	for i in range(len(s)):
		bin = bin + mp[s[i]]
	return bin


# Fungsi untuk mengkonversi dari binary ke hexadecimal

def bin2hex(s):
	mp = {"0000": '0',
		"0001": '1',
		"0010": '2',
		"0011": '3',
		"0100": '4',
		"0101": '5',
		"0110": '6',
		"0111": '7',
		"1000": '8',
		"1001": '9',
		"1010": 'A',
		"1011": 'B',
		"1100": 'C',
		"1101": 'D',
		"1110": 'E',
		"1111": 'F'}
	hex = ""
	for i in range(0, len(s), 4):
		ch = ""
		ch = ch + s[i]
		ch = ch + s[i + 1]
		ch = ch + s[i + 2]
		ch = ch + s[i + 3]
		hex = hex + mp[ch]

	return hex


# Fungsi untuk mengkonversi dari binary ke decimal

def bin2dec(binary):

	decimal, i = 0, 0
	while(binary != 0):
		dec = binary % 10
		decimal = decimal + dec * pow(2, i)
		binary = binary//10
		i += 1
	return decimal


# Fungsi untuk mengkonversi dari decimal ke binary

def dec2bin(num):
	res = bin(num).replace("0b", "")
	if(len(res) % 4 != 0):
		div = len(res) / 4
		div = int(div)
		counter = (4 * (div + 1)) - len(res)
		for i in range(0, counter):
			res = '0' + res
	return res


# fungsi untuk melakukan permutation

def permute(k, arr, n): 	#contoh pt = permute(pt, initial_perm, 64)
	permutation = ""
	for i in range(0, n):
		permutation = permutation + k[arr[i] - 1]
	return permutation


# fungsi untuk melakukan shift left

def shift_left(k, nth_shifts): 	# contoh : left = shift_left(left, shift_table[i])
	s = ""
	for i in range(nth_shifts):
		for j in range(1, len(k)):
			s = s + k[j]
		s = s + k[0]
		k = s
		s = ""
	return k


# fungsi untuk melakukan operasi xor antara dua nilai biner dari string a dan b

def xor(a, b):
	ans = ""
	for i in range(len(a)):
		if a[i] == b[i]:
			ans = ans + "0"
		else:
			ans = ans + "1"
	return ans


def key_generator():
    key = ''
    characters = '123456789ABCDEF'
    
    for _ in range(16):  # Assuming you want a 16-character key
        key += random.choice(characters)
    
    return key

def encrypt(pt, rkb, rk):
	pt = hex2bin(pt)

	# Initial Permutation
	pt = permute(pt, initial_perm, 64)
	print("After initial permutation", bin2hex(pt))
	print("| Round     |  left      |  Right     |  round key ")

	# Splitting
	left = pt[0:32]
	right = pt[32:64]
	for i in range(1, 17):
		# Expansion D-box: Expanding the 32 bits data into 48 bits
		right_expanded = permute(right, exp_d, 48)

		# XOR RoundKey[i] and right_expanded
		xor_x = xor(right_expanded, rkb[i-1])
		#100101
		# S-boxex: substituting the value from s-box table by calculating row and column
		sbox_str = ""
		for j in range(0, 8): # 100101
			row = bin2dec(int(xor_x[j * 6] + xor_x[j * 6 + 5])) #mengambil index row di tabel sbox lewat angka ke "[0]"+"[5]"
			col = bin2dec(
				int(xor_x[j * 6 + 1] + xor_x[j * 6 + 2] + xor_x[j * 6 + 3] + xor_x[j * 6 + 4]))
			val = sbox[j][row][col]
			sbox_str = sbox_str + dec2bin(val)

		# Straight D-box: After substituting rearranging the bits
		# Transposition P-Box
		sbox_str = permute(sbox_str, per, 32) 

		# XOR left and sbox_str
		result = xor(left, sbox_str)
		left = result

		# Swapper
		if(i != 16):
			left, right = right, left
		print("| Round ", i, " | ", bin2hex(left),
			" | ", bin2hex(right), " | ", rk[i-1])

	# Combination
	combine = left + right

	# Final permutation: final rearranging of bits to get cipher text
	ct = permute(combine, final_perm, 64)
	return ct

# Padding Function
def add_padding(plaintext):
    padding_length = 16 - (len(plaintext) % 16)
    padding_char = "0" * padding_length
    padding_info = bin2hex(dec2bin(padding_length))
    return plaintext + padding_char, padding_info

# ECB Encryption Mode
def ecb_encrypt(plaintext, round_keys_bin, round_keys_hex):
    padding_info = ""
    if len(plaintext) % 16 != 0:
        plaintext, padding_info = add_padding(plaintext)
    
    ciphertext = ""
    total_blocks = len(plaintext) // 16
    
    for block_index in range(total_blocks):
        current_block = plaintext[block_index * 16 : (block_index + 1) * 16]
        encrypted_block = encrypt(current_block, round_keys_bin, round_keys_hex)
        ciphertext += encrypted_block
    
    return ciphertext, padding_info



