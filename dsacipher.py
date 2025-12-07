"""
dsacipher.py
Digital Signature implementacia:
- RSA key generation (Miller-Rabin)
- SHA3-512 hashing
- Sign/verify functions
- Key export/import (.priv, .pub)
"""

import random
import math
import hashlib
import base64
import os
from datetime import datetime
from typing import Tuple, List, Optional, Callable

# ---------------------------
# RSA - Pomocne funkcie pre teorie cisel
# ---------------------------


def _egcd(a: int, b: int) -> Tuple[int, int, int]:
    """Rozsireny Euklidov algoritmus: vracia (g, x, y) kde ax + by = g = gcd(a,b)."""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = _egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def modinv(a: int, m: int) -> int:
    """Modularny inverz a^{-1} mod m. Vyvola ValueError ak inverz neexistuje."""
    g, x, _ = _egcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m


def _is_probable_prime(n: int, k: int = 8) -> bool:
    """Miller-Rabin pravdepodobnostny test prvocisla."""
    if n < 2:
        return False
    
    # Trial division pre male prvocisla
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    
    # Rozlozenie n-1 = 2^s * d
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    
    # Miller-Rabin test s k pokusmi
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(
    bits: int, progress_callback: Optional[Callable[[str], None]] = None
) -> int:
    """Generuje pravdepodobne prvocislo so zadanou bitovou dlzkou."""
    attempts = 0
    while True:
        attempts += 1
        # Nastavi horny a dolny bit pre spravnu dlzku
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        
        if progress_callback and (attempts % 16) == 0:
            progress_callback(f"Trying prime candidate #{attempts} (bits={bits})")
        
        if _is_probable_prime(candidate):
            if progress_callback:
                progress_callback(
                    f"Found prime (bits={bits}) after {attempts} attempts"
                )
            return candidate


# ---------------------------
# RSA - Generovanie klucov
# ---------------------------


def generate_keys(
    bits: int = 512, progress_callback: Optional[Callable[[str], None]] = None
) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """
    Generuje RSA par klucov.
    - bits: bitova dlzka pre kazde prvocislo p a q (n bude ~2*bits)
    - progress_callback: volitelny callback(msg) pre aktualizaciu GUI
    Vracia: (public_key(n,e), private_key(n,d))
    """
    if progress_callback:
        progress_callback(f"Start key generation (prime bits = {bits})")

    # Generuj prvocislo p
    p = generate_prime(bits, progress_callback=progress_callback)
    if progress_callback:
        progress_callback(f"P = {p}")

    # Generuj prvocislo q (rozne od p)
    q = generate_prime(bits, progress_callback=progress_callback)
    while q == p:
        if progress_callback:
            progress_callback("Q == P, regenerating Q")
        q = generate_prime(bits, progress_callback=progress_callback)
    if progress_callback:
        progress_callback(f"Q = {q}")

    # Vypocitaj n a phi
    n = p * q
    if progress_callback:
        progress_callback(f"N = P * Q = {n}")
    phi = (p - 1) * (q - 1)
    if progress_callback:
        progress_callback(f"φ(N) = (P-1)(Q-1) = {phi}")

    # Zvol e (standardne 65537)
    e = 65537
    if math.gcd(e, phi) != 1:
        if progress_callback:
            progress_callback(
                "65537 not coprime with φ(N), searching for alternative e"
            )
        # Najdi ine e
        while True:
            e = random.randrange(3, phi - 1, 2)
            if math.gcd(e, phi) == 1:
                break
    if progress_callback:
        progress_callback(f"1 < E < φ(N) -> E = {e}")

    # Vypocitaj d ako inverzne modulo
    d = modinv(e, phi)
    if progress_callback:
        progress_callback(f"D = {d}")
        progress_callback("Key generation finished")

    public_key = (n, e)
    private_key = (n, d)
    return public_key, private_key


# ---------------------------
# SHA3-512 Hashovanie
# ---------------------------


def hash_file(file_path: str) -> bytes:
    """
    Hashuje subor pomocou SHA3-512 (Keccak).
    Vracia 64-bajtovy hash.
    """
    sha3 = hashlib.sha3_512()
    
    # Citaj subor po blokoch (pre velke subory)
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            sha3.update(chunk)
    
    return sha3.digest()  # 64 bajtov


# ---------------------------
# Podpisovanie a overovanie
# ---------------------------


def sign_file(file_path: str, private_key: Tuple[int, int]) -> str:
    """
    Podpise subor pomocou RSA + SHA3-512.
    
    Proces:
    1. Zahashuj subor pomocou SHA3-512 -> 64 bajtov
    2. Konvertuj hash na integer
    3. Sifruj hash pomocou privatneho kluca (= podpis)
    4. Vrat podpis ako Base64 string
    
    Vracia: "RSA_SHA3-512 BASE64_SIGNATURE"
    """
    # Krok 1: Zahashuj subor
    file_hash = hash_file(file_path)
    
    # Krok 2: Konvertuj hash na integer
    hash_int = int.from_bytes(file_hash, byteorder='big')
    
    # Krok 3: Sifruj hash privatnym klucom (= podpis)
    n, d = private_key
    signature_int = pow(hash_int, d, n)
    
    # Krok 4: Konvertuj signature na bajty a Base64
    # Vypocitaj potrebny pocet bajtov pre n
    byte_length = (n.bit_length() + 7) // 8
    signature_bytes = signature_int.to_bytes(byte_length, byteorder='big')
    signature_b64 = base64.b64encode(signature_bytes).decode('ascii')
    
    return f"RSA_SHA3-512 {signature_b64}"


def verify_signature(
    file_path: str, 
    signature_str: str, 
    public_key: Tuple[int, int]
) -> bool:
    """
    Overuje podpis suboru pomocou verejneho kluca.
    
    Proces:
    1. Zahashuj subor pomocou SHA3-512
    2. Extrahuj podpis z Base64 stringu
    3. Desifruj podpis pomocou verejneho kluca
    4. Porovnaj desifrovany hash s aktualnym hashom
    
    Vracia: True ak podpis sedi, False inak
    """
    # Krok 1: Zahashuj subor
    file_hash = hash_file(file_path)
    hash_int = int.from_bytes(file_hash, byteorder='big')
    
    # Krok 2: Parsuj signature string
    if not signature_str.startswith("RSA_SHA3-512 "):
        return False
    
    signature_b64 = signature_str[13:].strip()  # Odstran prefix
    
    try:
        signature_bytes = base64.b64decode(signature_b64)
        signature_int = int.from_bytes(signature_bytes, byteorder='big')
    except Exception:
        return False
    
    # Krok 3: Desifruj podpis pomocou verejneho kluca
    n, e = public_key
    decrypted_hash_int = pow(signature_int, e, n)
    
    # Krok 4: Porovnaj
    return decrypted_hash_int == hash_int


# ---------------------------
# Praca s klucmi (export/import)
# ---------------------------


def export_private_key(private_key: Tuple[int, int], file_path: str):
    """
    Exportuje privatny kluc do .priv suboru.
    Format: RSA N_BASE64 D_BASE64
    """
    n, d = private_key
    
    # Konvertuj n a d na Base64
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
    d_bytes = d.to_bytes((d.bit_length() + 7) // 8, byteorder='big')
    
    n_b64 = base64.b64encode(n_bytes).decode('ascii')
    d_b64 = base64.b64encode(d_bytes).decode('ascii')
    
    content = f"RSA {n_b64} {d_b64}"
    
    with open(file_path, 'w') as f:
        f.write(content)


def export_public_key(public_key: Tuple[int, int], file_path: str):
    """
    Exportuje verejny kluc do .pub suboru.
    Format: RSA N_BASE64 E_BASE64
    """
    n, e = public_key
    
    # Konvertuj n a e na Base64
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
    e_bytes = e.to_bytes((e.bit_length() + 7) // 8, byteorder='big')
    
    n_b64 = base64.b64encode(n_bytes).decode('ascii')
    e_b64 = base64.b64encode(e_bytes).decode('ascii')
    
    content = f"RSA {n_b64} {e_b64}"
    
    with open(file_path, 'w') as f:
        f.write(content)


def import_private_key(file_path: str) -> Tuple[int, int]:
    """
    Importuje privatny kluc z .priv suboru.
    Vracia: (n, d)
    """
    with open(file_path, 'r') as f:
        content = f.read().strip()
    
    if not content.startswith("RSA "):
        raise ValueError("Invalid private key format")
    
    parts = content.split()
    if len(parts) != 3:
        raise ValueError("Invalid private key format")
    
    n_b64 = parts[1]
    d_b64 = parts[2]
    
    n_bytes = base64.b64decode(n_b64)
    d_bytes = base64.b64decode(d_b64)
    
    n = int.from_bytes(n_bytes, byteorder='big')
    d = int.from_bytes(d_bytes, byteorder='big')
    
    return (n, d)


def import_public_key(file_path: str) -> Tuple[int, int]:
    """
    Importuje verejny kluc z .pub suboru.
    Vracia: (n, e)
    """
    with open(file_path, 'r') as f:
        content = f.read().strip()
    
    if not content.startswith("RSA "):
        raise ValueError("Invalid public key format")
    
    parts = content.split()
    if len(parts) != 3:
        raise ValueError("Invalid public key format")
    
    n_b64 = parts[1]
    e_b64 = parts[2]
    
    n_bytes = base64.b64decode(n_b64)
    e_bytes = base64.b64decode(e_b64)
    
    n = int.from_bytes(n_bytes, byteorder='big')
    e = int.from_bytes(e_bytes, byteorder='big')
    
    return (n, e)


# ---------------------------
# Informacie o subore
# ---------------------------


def get_file_info(file_path: str) -> dict:
    """
    Vrati informacie o subore.
    Vracia dict s: name, path, extension, size, modified_date
    """
    stat = os.stat(file_path)
    
    return {
        "name": os.path.basename(file_path),
        "path": os.path.abspath(file_path),
        "extension": os.path.splitext(file_path)[1],
        "size": stat.st_size,  # v bajtoch
        "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
    }


# ---------------------------
# Praca so .sign suborom
# ---------------------------


def save_signature(signature_str: str, output_path: str):
    """Ulozi podpis do .sign suboru."""
    with open(output_path, 'w') as f:
        f.write(signature_str)


def load_signature(sign_path: str) -> str:
    """Nacita podpis z .sign suboru."""
    with open(sign_path, 'r') as f:
        return f.read().strip()


# ---------------------------
# Demo pri priamom spusteni
# ---------------------------
if __name__ == "__main__":
    print("=== DSA Demo ===")
    
    # Generuj kluce
    print("Generating keys...")
    pub, priv = generate_keys(bits=512)
    print(f"Public key: {pub}")
    print(f"Private key: {priv}")
    
    # Vytvor testovaci subor
    test_file = "test_document.txt"
    with open(test_file, 'w') as f:
        f.write("This is a test document for digital signature.")
    
    # Podpis
    print("\nSigning file...")
    signature = sign_file(test_file, priv)
    print(f"Signature: {signature[:50]}...")
    
    # Overenie
    print("\nVerifying signature...")
    is_valid = verify_signature(test_file, signature, pub)
    print(f"Signature valid: {is_valid}")
    
    # Test s upravenym suborom
    with open(test_file, 'a') as f:
        f.write(" MODIFIED")
    
    print("\nVerifying modified file...")
    is_valid_modified = verify_signature(test_file, signature, pub)
    print(f"Signature valid after modification: {is_valid_modified}")
    
    # Cleanup
    os.remove(test_file)