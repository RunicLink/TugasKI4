import socket
import sys
import random
from des_logic import run_des
from rsa_logic import generate_keypair, sign_message, verify_signature

def derive_des_key(shared_secret_int):
    """
    Membuat kunci DES 8 karakter dari shared secret TANPA hashlib.
    Menggunakan random generator yang di-seed dengan shared secret.
    """
    # Simpan state random saat ini agar tidak mengganggu fungsi lain
    state = random.getstate()
    
    # Seed random dengan shared secret (S) agar deterministik
    random.seed(shared_secret_int)
    
    # Generate 8 karakter ascii yang bisa dicetak (33-126)
    key_chars = [chr(random.randint(33, 126)) for _ in range(8)]
    key_str = "".join(key_chars)
    
    # Kembalikan state random ke semula
    random.setstate(state)
    
    return key_str

HOST = '127.0.0.1' 
PORT = 65432

def start_server():
    """Device 1 (Server)"""
    print("--- Device 1 (Server) ---")
    
    # 1. Server Generate RSA Keypair
    print("Generating Server RSA keypair...")
    server_pub, server_priv = generate_keypair()
    print(f"Server Public Key: {server_pub}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Menunggu koneksi dari Device 2...")
        conn, addr = s.accept()
        with conn:
            print(f"Terhubung dengan {addr}")
            print("Memulai pertukaran kunci RSA & Handshake...")
            
            try:
                # A. Kirim Public Key Server ke Client
                conn.sendall(f"{server_pub[0]},{server_pub[1]}".encode('utf-8'))
                
                # B. Terima Public Key Client (Supaya bisa verifikasi signature client)
                client_pub_str = conn.recv(2048).decode('utf-8')
                e_c, n_c = map(int, client_pub_str.split(','))
                client_pub = (e_c, n_c)
                print(f"Menerima Public Key Client: {client_pub}")

                # C. Terima Secret (C) untuk Kunci DES
                C_str = conn.recv(2048).decode('utf-8')
                C = int(C_str)
                
                # Dekripsi S menggunakan Private Key Server
                d, n = server_priv
                S = pow(C, d, n)
                
                KEY = derive_des_key(S)
                print(f"*** Shared Secret (S) = {S} ***")
                print(f"*** Kunci DES: {repr(KEY)} ***\n")
                
            except Exception as e_key:
                print(f"Error saat handshake: {e_key}")
                return

            print("Siap chat. Ketik 'q' untuk keluar.\n")

            while True:
                # --- TERIMA PESAN (Server) ---
                raw_data = conn.recv(1024).decode('utf-8')
                if not raw_data:
                    print("Device 2 menutup koneksi.")
                    break
                
                try:
                    parts = raw_data.split("::")
                    if len(parts) == 2:
                        ciphertext, sig_str = parts[0], parts[1]
                        signature = int(sig_str)

                        # 1. Dekripsi Pesan (DES)
                        decrypted_msg = run_des(ciphertext, KEY, 'decrypt')
                        
                        # 2. Verifikasi Signature (RSA) pakai Public Key Client
                        is_valid = verify_signature(decrypted_msg, signature, client_pub)
                        status = "[VALID]" if is_valid else "[INVALID/PALSU!]"
                        
                        print(f"[Device 2] {status}: {decrypted_msg}")
                        # Print detail yang DITERIMA
                        print(f"   -> Ciphertext diterima: {ciphertext}")
                        print(f"   -> Signature diterima : {signature}")

                        if decrypted_msg.lower() == 'q': break
                    else:
                        print(f"Format pesan salah: {raw_data}")

                except Exception as e_dec:
                    print(f"Error: {e_dec}")
                    continue 

                # --- KIRIM BALASAN (Server) ---
                msg_to_send = input("[Device 1] Balas: ")
                
                # 1. Enkripsi Pesan (DES)
                encrypted_msg = run_des(msg_to_send, KEY, 'encrypt')
                
                # 2. Buat Signature (RSA) pakai Private Key Server
                sig = sign_message(msg_to_send, server_priv)
                
                # Print detail yang DIKIRIM
                print(f"   -> Ciphertext dikirim: {encrypted_msg}")
                print(f"   -> Signature dikirim : {sig}")
                
                # Kirim format gabungan
                payload = f"{encrypted_msg}::{sig}"
                conn.sendall(payload.encode('utf-8'))
                
                if msg_to_send.lower() == 'q': break

def start_client():
    """Device 2 (Client)"""
    print(f"--- Device 2 (Client) ---")
    
    # 1. Client Generate RSA Keypair (Untuk Signature)
    print("Generating Client RSA keypair...")
    client_pub, client_priv = generate_keypair()
    print(f"Client Public Key: {client_pub}")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT))
        except ConnectionRefusedError:
            print("Gagal terhubung. Pastikan Server sudah jalan.")
            return
            
        print(f"Terhubung ke Server.")
        
        try:
            # A. Terima Public Key Server
            server_pub_str = s.recv(2048).decode('utf-8')
            e_s, n_s = map(int, server_pub_str.split(','))
            server_pub = (e_s, n_s)
            print(f"Menerima Public Key Server: {server_pub}")

            # B. Kirim Public Key Client ke Server
            s.sendall(f"{client_pub[0]},{client_pub[1]}".encode('utf-8'))

            # C. Generate dan Kirim Shared Secret (S)
            S = random.randint(1, n_s - 1)
            C = pow(S, e_s, n_s) # Enkripsi S dengan pub key Server
            s.sendall(str(C).encode('utf-8'))
            
            KEY = derive_des_key(S)
            print(f"*** Shared Secret (S) = {S} ***")
            print(f"*** Kunci DES: {repr(KEY)} ***\n")
            
        except Exception as e_key:
            print(f"Error handshake: {e_key}")
            return
        
        print("Siap chat. Ketik 'q' untuk keluar.\n")

        while True:
            # --- KIRIM PESAN (Client) ---
            msg_to_send = input("[Device 2] Kirim: ")
            
            # 1. Enkripsi (DES)
            encrypted_msg = run_des(msg_to_send, KEY, 'encrypt')
            
            # 2. Signature (RSA) pakai Private Key Client
            sig = sign_message(msg_to_send, client_priv)

            # Print detail yang DIKIRIM
            print(f"   -> Ciphertext dikirim: {encrypted_msg}")
            print(f"   -> Signature dikirim : {sig}")
            
            payload = f"{encrypted_msg}::{sig}"
            s.sendall(payload.encode('utf-8'))
            
            if msg_to_send.lower() == 'q': break

            # --- TERIMA BALASAN (Client) ---
            raw_data = s.recv(1024).decode('utf-8')
            if not raw_data:
                print("Server menutup koneksi.")
                break

            try:
                parts = raw_data.split("::")
                if len(parts) == 2:
                    ciphertext, sig_str = parts[0], parts[1]
                    signature = int(sig_str)

                    # 1. Dekripsi
                    decrypted_msg = run_des(ciphertext, KEY, 'decrypt')
                    
                    # 2. Verifikasi Signature pakai Public Key Server
                    is_valid = verify_signature(decrypted_msg, signature, server_pub)
                    status = "[VALID]" if is_valid else "[INVALID/PALSU!]"
                    
                    print(f"[Device 1] {status}: {decrypted_msg}")
                    # Print detail yang DITERIMA
                    print(f"   -> Ciphertext diterima: {ciphertext}")
                    print(f"   -> Signature diterima : {signature}")
                    
                    if decrypted_msg.lower() == 'q': break
                else:
                    print(f"Format pesan salah.")
                    
            except Exception as e_dec:
                print(f"Error: {e_dec}")
                continue 

if __name__ == "__main__":
    choice = input("Pilih peran (1=Server, 2=Client): ").strip()
    if choice == '1':
        start_server()
    elif choice == '2':
        start_client()
    else:
        print("Pilihan tidak valid.")