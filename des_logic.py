from des_tables import IP, FP, E, S_BOX, P, PC1, PC2, ROTATIONS

def hex_to_bin(hex_str):
    """Mengubah string heksadesimal menjadi string biner."""
    return bin(int(hex_str, 16))[2:].zfill(len(hex_str) * 4)

def bin_to_hex(bin_str):
    """Mengubah string biner menjadi string heksadesimal."""
    return hex(int(bin_str, 2))[2:].upper().zfill(len(bin_str) // 4)

def text_to_bin(text):
    """Mengubah string teks ASCII menjadi string biner."""
    return ''.join(format(ord(char), '08b') for char in text)

def bin_to_text(bin_str):
    """Mengubah string biner menjadi string teks ASCII dan menghapus padding."""
    text = ""
    for i in range(0, len(bin_str), 8):
        byte = bin_str[i:i+8]
        char_code = int(byte, 2)
        if char_code > 0:
            text += chr(char_code)
            
    if text:
        pad_char_val = ord(text[-1])
        if pad_char_val <= 8 and text.endswith(chr(pad_char_val) * pad_char_val):
            return text[:-pad_char_val]
    return text

def pad(bin_str):
    block_size = 64
    padding_len = block_size - (len(bin_str) % block_size)
    if padding_len == 0:
        padding_len = block_size
        
    pad_char_val = padding_len // 8
    pad_char_bin = format(pad_char_val, '08b')
    return bin_str + pad_char_bin * pad_char_val

def permute(block, table):
    return "".join(block[i - 1] for i in table)

def xor(a, b):
    return "".join('1' if x != y else '0' for x, y in zip(a, b))

def s_box_substitute(block_48bit):
    output_32bit = ""
    for i in range(8):
        chunk = block_48bit[i*6 : (i+1)*6]
        row = int(chunk[0] + chunk[5], 2)
        col = int(chunk[1:5], 2)
        val = S_BOX[i][row][col]
        output_32bit += format(val, '04b')
    return output_32bit

def generate_subkeys(key_64bit):
    key_56bit = permute(key_64bit, PC1)
    C, D = key_56bit[:28], key_56bit[28:]
    subkeys = []
    for shift in ROTATIONS:
        C = C[shift:] + C[:shift]
        D = D[shift:] + D[:shift]
        subkey = permute(C + D, PC2)
        subkeys.append(subkey)
    return subkeys

def process_block(block_64bit, subkeys):
    block_64bit = permute(block_64bit, IP)
    L, R = block_64bit[:32], block_64bit[32:]

    for i in range(16):
        R_expanded = permute(R, E)
        xored = xor(R_expanded, subkeys[i])
        s_substituted = s_box_substitute(xored)
        p_permuted = permute(s_substituted, P)
        
        new_R = xor(L, p_permuted)
        L = R
        R = new_R

    final_block = R + L
    return permute(final_block, FP)

def run_des(input_data, key_str, mode='encrypt'):
    if len(key_str) != 8:
        raise ValueError("Kunci harus tepat 8 karakter (64 bit).")
        
    bin_key = text_to_bin(key_str)
    subkeys = generate_subkeys(bin_key)
    
    if mode == 'encrypt':
        bin_data = text_to_bin(input_data)
        padded_data = pad(bin_data)
        process_func = lambda block: process_block(block, subkeys)
        output_converter = bin_to_hex
        input_blocks = [padded_data[i:i+64] for i in range(0, len(padded_data), 64)]

    elif mode == 'decrypt':
        bin_data = hex_to_bin(input_data)
        if len(bin_data) % 64 != 0:
            raise ValueError("Ciphertext (HEX) tidak valid, panjang tidak kelipatan 64 bit.")
        
        reversed_subkeys = list(reversed(subkeys))
        process_func = lambda block: process_block(block, reversed_subkeys)
        output_converter = bin_to_text
        input_blocks = [bin_data[i:i+64] for i in range(0, len(bin_data), 64)]
    
    else:
        raise ValueError("Mode tidak valid. Pilih 'encrypt' atau 'decrypt'.")

    processed_bin = "".join(process_func(block) for block in input_blocks)
    return output_converter(processed_bin)

def main():
    while True:
        choice = input("\nPilih mode (1: Enkripsi, 2: Dekripsi, q: Keluar): ").strip().lower()
        
        if choice == 'q':
            break
        
        if choice not in ['1', '2']:
            print("Pilihan tidak valid. Silakan masukkan '1', '2', atau 'q'.")
            continue
            
        try:
            key = input("Masukkan kunci (harus 8 karakter): ").strip()
            if len(key) != 8:
                print("Error: Kunci harus tepat 8 karakter.")
                continue

            if choice == '1':
                plaintext = input("Masukkan plaintext untuk dienkripsi: ")
                ciphertext = run_des(plaintext, key, 'encrypt')
                print("\n--- HASIL ENKRIPSI ---")
                print(f"Ciphertext (HEX): {ciphertext}")
                
            elif choice == '2':
                ciphertext_hex = input("Masukkan ciphertext (HEX) untuk didekripsi: ")
                decrypted_text = run_des(ciphertext_hex, key, 'decrypt')
                print("\n--- HASIL DEKRIPSI ---")
                print(f"Plaintext: {decrypted_text}")
                
        except ValueError as e:
            print(f"Error: {e}")
        except Exception as e:
            print(f"Terjadi kesalahan yang tidak terduga: {e}")

if __name__ == "__main__":
    main()