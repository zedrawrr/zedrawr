import bcrypt
import hashlib
import time
from passlib.hash import md5_crypt

RED = '\033[91m'
GREEN = '\033[92m'
RESET = '\033[0m'

def verify_bcrypt(stored_hash: str, password: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))

def verify_md5_hash(stored_hash: str, password: str) -> bool:
    return hashlib.md5(password.encode('utf-8')).hexdigest() == stored_hash

def verify_sha1(stored_hash: str, password: str) -> bool:
    return hashlib.sha1(password.encode('utf-8')).hexdigest() == stored_hash

def verify_sha256(stored_hash: str, password: str) -> bool:
    return hashlib.sha256(password.encode('utf-8')).hexdigest() == stored_hash

def verify_sha512(stored_hash: str, password: str) -> bool:
    return hashlib.sha512(password.encode('utf-8')).hexdigest() == stored_hash

def verify_md4(stored_hash: str, password: str) -> bool:
    m = hashlib.new('md4')
    m.update(password.encode('utf-8'))
    return m.hexdigest() == stored_hash

def print_ascii_banner():
    banner = """                                                         
 
███╗░░██╗██╗░░░██╗██╗░░░░░██╗░░░░░░██████╗███████╗░█████╗░  ██████╗░██╗░░██╗
████╗░██║██║░░░██║██║░░░░░██║░░░░░██╔════╝██╔════╝██╔══██╗  ██╔══██╗██║░░██║
██╔██╗██║██║░░░██║██║░░░░░██║░░░░░╚█████╗░█████╗░░██║░░╚═╝  ██████╔╝███████║
██║╚████║██║░░░██║██║░░░░░██║░░░░░░╚═══██╗██╔══╝░░██║░░██╗  ██╔═══╝░██╔══██║
██║░╚███║╚██████╔╝███████╗███████╗██████╔╝███████╗╚█████╔╝  ██║░░░░░██║░░██║
╚═╝░░╚══╝░╚═════╝░╚══════╝╚══════╝╚═════╝░╚══════╝░╚════╝░  ╚═╝░░░░░╚═╝░░╚═╝
                        |____|/                   
                        
                Hash Cracker
    """
    print(banner)

def check_password(stored_hash: str, password: str, hash_type: str) -> bool:
    if hash_type == '1':
        return verify_bcrypt(stored_hash, password)
    elif hash_type == '2':
        return verify_md5_hash(stored_hash, password)
    elif hash_type == '3':
        return verify_sha1(stored_hash, password)
    elif hash_type == '4':
        return verify_sha256(stored_hash, password)
    elif hash_type == '5':
        return verify_sha512(stored_hash, password)
    elif hash_type == '6':
        return verify_md4(stored_hash, password)
    return False

def is_hash_valid(hash_type: str, stored_hash: str) -> bool:
    if hash_type == '1':  
        return stored_hash.startswith('$2a$') or stored_hash.startswith('$2b$') or stored_hash.startswith('$2y$')
    elif hash_type == '2':  
        return len(stored_hash) == 32 and all(c in '0123456789abcdef' for c in stored_hash)
    elif hash_type == '3':  
        return len(stored_hash) == 40 and all(c in '0123456789abcdef' for c in stored_hash)
    elif hash_type == '4':  
        return len(stored_hash) == 64 and all(c in '0123456789abcdef' for c in stored_hash)
    elif hash_type == '5':  
        return len(stored_hash) == 128 and all(c in '0123456789abcdef' for c in stored_hash)
    elif hash_type == '6':  
        return len(stored_hash) == 32 and all(c in '0123456789abcdef' for c in stored_hash)
    return False

def analyze_hash(stored_hash: str) -> str:
    if stored_hash.startswith('$2a$') or stored_hash.startswith('$2b$') or stored_hash.startswith('$2y$'):
        return "BCRYPT"
    elif len(stored_hash) == 32 and all(c in '0123456789abcdef' for c in stored_hash):
        return "MD5"
    elif len(stored_hash) == 40 and all(c in '0123456789abcdef' for c in stored_hash):
        return "SHA-1"
    elif len(stored_hash) == 64 and all(c in '0123456789abcdef' for c in stored_hash):
        return "SHA-256"
    elif len(stored_hash) == 128 and all(c in '0123456789abcdef' for c in stored_hash):
        return "SHA-512"
    elif len(stored_hash) == 32 and all(c in '0123456789abcdef' for c in stored_hash):
        return "MD4"
    else:
        return "Unknown hash type"

def main():
    while True:  
        print_ascii_banner()  
        print("Choose an option:")
        print("1: Crack BCRYPT")
        print("2: Crack MD5")
        print("3: Crack SHA-1")
        print("4: Analyze Hash")

        choice = input("Enter your choice (1-4): ")

        if choice == '':
            print(f"{RED}Please choose the choices to scan.{RESET}")
            time.sleep(3)
            continue

        if choice == '4':
            stored_hash = input("Put the hash to analyze: ").strip()
            hash_type = analyze_hash(stored_hash)
            print(f"The hash type is likely: {hash_type}")
            continue
        
        stored_hash = input("Put the exact hash to scan: ").strip()
        
        if not is_hash_valid(choice, stored_hash) and choice in ['1', '2', '3']:
            print(f"{RED}Please put the exact hash{RESET}")
            time.sleep(5)
            continue  

        password_file = input("Put the password list file (e.g. wordlist.txt): ").strip()

        try:
            with open(password_file, 'r') as file:
                for line in file:
                    password_to_check = line.strip()
                    if check_password(stored_hash, password_to_check, choice):
                        print(f"{GREEN}[FOUND!] {password_to_check}{RESET}")
                        return
                    print(f"{RED}[NOT FOUND!] {password_to_check}{RESET}")
                    time.sleep(0.5)
        except FileNotFoundError:
            print(f"{RED}File '{password_file}' not found. Please try again.{RESET}")
            time.sleep(3)
            continue

        print(f"{RED}No matching password found.{RESET}")

if __name__ == "__main__":
    main()
