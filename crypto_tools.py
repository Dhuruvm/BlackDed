
#!/usr/bin/env python3
"""
BlackDeD Cryptography & Password Tools Module
Encryption, decryption, hashing, and password utilities
"""

import hashlib
import base64
import secrets
import string
import itertools
import time
from colorama import Fore, Back, Style
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
from Crypto.Cipher import AES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import bcrypt

console = Console(style="on black")

class CryptoTools:
    def __init__(self):
        self.common_passwords = [
            'password', '123456', 'password123', 'admin', 'root', 'user',
            'test', 'guest', 'qwerty', 'abc123', '111111', '123123',
            'password1', 'admin123', 'letmein', 'welcome', 'monkey',
            'dragon', 'master', 'login', 'princess', '1234567890'
        ]
    
    def hash_analyzer(self):
        """Analyze and identify hash types"""
        console.print(f"\n{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}🔍 Hash Analyzer & Identifier")
        console.print(f"{Back.BLACK}{Fore.GREEN}" + "=" * 60)
        
        hash_input = input(f"{Back.BLACK}{Fore.GREEN}root@blackded:~# Enter hash to analyze: ").strip()
        
        if not hash_input:
            console.print(f"{Back.BLACK}{Fore.RED}[-] No hash provided!")
            return
        
        # Hash type identification based on length and format
        hash_types = []
        hash_length = len(hash_input)
        
        if hash_length == 32 and all(c in '0123456789abcdefABCDEF' for c in hash_input):
            hash_types.append("MD5")
        
        if hash_length == 40 and all(c in '0123456789abcdefABCDEF' for c in hash_input):
            hash_types.append("SHA-1")
        
        if hash_length == 64 and all(c in '0123456789abcdefABCDEF' for c in hash_input):
            hash_types.append("SHA-256")
        
        if hash_length == 96 and all(c in '0123456789abcdefABCDEF' for c in hash_input):
            hash_types.append("SHA-384")
        
        if hash_length == 128 and all(c in '0123456789abcdefABCDEF' for c in hash_input):
            hash_types.append("SHA-512")
        
        if hash_input.startswith('$2b$') or hash_input.startswith('$2a$') or hash_input.startswith('$2y$'):
            hash_types.append("bcrypt")
        
        if hash_input.startswith('$1$'):
            hash_types.append("MD5 Crypt")
        
        if hash_input.startswith('$6$'):
            hash_types.append("SHA-512 Crypt")
        
        # Display analysis results
        analysis_table = Table(show_header=False, border_style="green on black", style="on black")
        analysis_table.add_column("Property", style="green on black", justify="right")
        analysis_table.add_column("Value", style="bright_green on black")
        
        analysis_table.add_row("Hash", hash_input)
        analysis_table.add_row("Length", str(hash_length))
        analysis_table.add_row("Possible Types", ", ".join(hash_types) if hash_types else "Unknown")
        
        panel = Panel(analysis_table, title="[green on black]Hash Analysis Results[/green on black]", border_style="green on black", style="on black")
        console.print(panel)
        
        # Attempt dictionary attack if hash type is identified
        if hash_types and 'bcrypt' not in hash_types:
            attempt_crack = input(f"\n{Back.BLACK}{Fore.GREEN}Attempt dictionary attack? (y/n): ").lower().strip()
            if attempt_crack == 'y':
                self.dictionary_attack(hash_input, hash_types[0])
    
    def dictionary_attack(self, target_hash, hash_type):
        """Perform dictionary attack on hash"""
        console.print(f"\n{Back.BLACK}{Fore.GREEN}[+] Starting dictionary attack...")
        console.print(f"{Back.BLACK}{Fore.GREEN}[*] Hash Type: {hash_type}")
        
        # Extended wordlist
        wordlist = self.common_passwords + [
            'password', '123456789', 'qwerty123', 'abc123456',
            'password1234', 'admin1234', 'root123', 'test123',
            '12345678', '87654321', 'qwertyuiop', 'asdfghjkl',
            'zxcvbnm', 'football', 'baseball', 'basketball'
        ]
        
        found = False
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Cracking hash...", total=len(wordlist))
            
            for word in wordlist:
                # Generate hash based on type
                if hash_type.upper() == "MD5":
                    test_hash = hashlib.md5(word.encode()).hexdigest()
                elif hash_type.upper() == "SHA-1":
                    test_hash = hashlib.sha1(word.encode()).hexdigest()
                elif hash_type.upper() == "SHA-256":
                    test_hash = hashlib.sha256(word.encode()).hexdigest()
                elif hash_type.upper() == "SHA-384":
                    test_hash = hashlib.sha384(word.encode()).hexdigest()
                elif hash_type.upper() == "SHA-512":
                    test_hash = hashlib.sha512(word.encode()).hexdigest()
                else:
                    test_hash = ""
                
                if test_hash.lower() == target_hash.lower():
                    console.print(f"\n{Back.BLACK}{Fore.GREEN}[+] HASH CRACKED!")
                    console.print(f"{Back.BLACK}{Fore.GREEN}[+] Plaintext: {word}")
                    found = True
                    break
                
                progress.advance(task)
        
        if not found:
            console.print(f"\n{Back.BLACK}{Fore.YELLOW}[!] Hash not found in dictionary")
            console.print(f"{Back.BLACK}{Fore.YELLOW}[*] Try a larger wordlist or brute force attack")
    
    def password_generator(self):
        """Generate secure passwords"""
        console.print(f"\n{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}🔐 Secure Password Generator")
        console.print(f"{Back.BLACK}{Fore.GREEN}" + "=" * 60)
        
        try:
            length = int(input(f"{Back.BLACK}{Fore.GREEN}Password length (8-128): "))
            if length < 8 or length > 128:
                console.print(f"{Back.BLACK}{Fore.RED}[-] Invalid length! Using default (16)")
                length = 16
        except ValueError:
            length = 16
        
        # Character sets
        print(f"\n{Back.BLACK}{Fore.GREEN}Character sets:")
        print(f"{Back.BLACK}{Fore.GREEN}1. Lowercase letters")
        print(f"{Back.BLACK}{Fore.GREEN}2. Uppercase letters") 
        print(f"{Back.BLACK}{Fore.GREEN}3. Numbers")
        print(f"{Back.BLACK}{Fore.GREEN}4. Special characters")
        print(f"{Back.BLACK}{Fore.GREEN}5. All (recommended)")
        
        choice = input(f"\n{Back.BLACK}{Fore.GREEN}Select character set (1-5): ").strip()
        
        if choice == "1":
            charset = string.ascii_lowercase
        elif choice == "2":
            charset = string.ascii_uppercase
        elif choice == "3":
            charset = string.digits
        elif choice == "4":
            charset = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        else:
            charset = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Generate multiple passwords
        passwords = []
        for _ in range(5):
            password = ''.join(secrets.choice(charset) for _ in range(length))
            strength = self.calculate_password_strength(password)
            passwords.append((password, strength))
        
        # Display generated passwords
        password_table = Table(show_header=True, header_style="bold green on black", style="on black")
        password_table.add_column("Password", style="bright_green on black")
        password_table.add_column("Strength", style="green on black")
        password_table.add_column("Score", style="white on black")
        
        for password, strength in passwords:
            strength_color = "green" if strength['score'] >= 80 else "yellow" if strength['score'] >= 60 else "red"
            password_table.add_row(
                password,
                f"[{strength_color}]{strength['level']}[/{strength_color}]",
                f"{strength['score']}/100"
            )
        
        panel = Panel(password_table, title="[green on black]Generated Passwords[/green on black]", border_style="green on black", style="on black")
        console.print(panel)
    
    def calculate_password_strength(self, password):
        """Calculate password strength score"""
        score = 0
        length = len(password)
        
        # Length bonus
        if length >= 8:
            score += 20
        if length >= 12:
            score += 20
        if length >= 16:
            score += 10
        
        # Character variety
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        char_types = sum([has_lower, has_upper, has_digit, has_special])
        score += char_types * 10
        
        # Complexity bonus
        if char_types >= 3:
            score += 20
        
        # Determine strength level
        if score >= 80:
            level = "Very Strong"
        elif score >= 60:
            level = "Strong"
        elif score >= 40:
            level = "Medium"
        else:
            level = "Weak"
        
        return {'score': min(score, 100), 'level': level}
    
    def text_encoder_decoder(self):
        """Encode and decode text in various formats"""
        console.print(f"\n{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}🔄 Text Encoder/Decoder")
        console.print(f"{Back.BLACK}{Fore.GREEN}" + "=" * 60)
        
        print(f"\n{Back.BLACK}{Fore.GREEN}Operations:")
        print(f"{Back.BLACK}{Fore.GREEN}1. Base64 Encode")
        print(f"{Back.BLACK}{Fore.GREEN}2. Base64 Decode")
        print(f"{Back.BLACK}{Fore.GREEN}3. URL Encode")
        print(f"{Back.BLACK}{Fore.GREEN}4. URL Decode")
        print(f"{Back.BLACK}{Fore.GREEN}5. Hex Encode")
        print(f"{Back.BLACK}{Fore.GREEN}6. Hex Decode")
        
        choice = input(f"\n{Back.BLACK}{Fore.GREEN}Select operation (1-6): ").strip()
        text_input = input(f"{Back.BLACK}{Fore.GREEN}Enter text: ").strip()
        
        if not text_input:
            console.print(f"{Back.BLACK}{Fore.RED}[-] No text provided!")
            return
        
        try:
            if choice == "1":
                result = base64.b64encode(text_input.encode()).decode()
                operation = "Base64 Encoded"
            elif choice == "2":
                result = base64.b64decode(text_input).decode()
                operation = "Base64 Decoded"
            elif choice == "3":
                import urllib.parse
                result = urllib.parse.quote(text_input)
                operation = "URL Encoded"
            elif choice == "4":
                import urllib.parse
                result = urllib.parse.unquote(text_input)
                operation = "URL Decoded"
            elif choice == "5":
                result = text_input.encode().hex()
                operation = "Hex Encoded"
            elif choice == "6":
                result = bytes.fromhex(text_input).decode()
                operation = "Hex Decoded"
            else:
                console.print(f"{Back.BLACK}{Fore.RED}[-] Invalid operation!")
                return
            
            # Display results
            result_table = Table(show_header=False, border_style="green on black", style="on black")
            result_table.add_column("Field", style="green on black", justify="right")
            result_table.add_column("Value", style="bright_green on black")
            
            result_table.add_row("Operation", operation)
            result_table.add_row("Input", text_input)
            result_table.add_row("Output", result)
            
            panel = Panel(result_table, title="[green on black]Encoding/Decoding Results[/green on black]", border_style="green on black", style="on black")
            console.print(panel)
            
        except Exception as e:
            console.print(f"{Back.BLACK}{Fore.RED}[-] Operation failed: {e}")
    
    def aes_encryption(self):
        """AES encryption and decryption"""
        console.print(f"\n{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}🔐 AES Encryption Tool")
        console.print(f"{Back.BLACK}{Fore.GREEN}" + "=" * 60)
        
        print(f"\n{Back.BLACK}{Fore.GREEN}Operations:")
        print(f"{Back.BLACK}{Fore.GREEN}1. Encrypt Text")
        print(f"{Back.BLACK}{Fore.GREEN}2. Decrypt Text")
        
        choice = input(f"\n{Back.BLACK}{Fore.GREEN}Select operation (1-2): ").strip()
        
        if choice == "1":
            plaintext = input(f"{Back.BLACK}{Fore.GREEN}Enter text to encrypt: ").strip()
            password = input(f"{Back.BLACK}{Fore.GREEN}Enter password: ").strip()
            
            if not plaintext or not password:
                console.print(f"{Back.BLACK}{Fore.RED}[-] Text and password required!")
                return
            
            try:
                # Generate key from password
                key = hashlib.sha256(password.encode()).digest()
                
                # Generate random IV
                iv = get_random_bytes(16)
                
                # Encrypt
                cipher = AES.new(key, AES.MODE_CBC, iv)
                padded_data = pad(plaintext.encode(), AES.block_size)
                ciphertext = cipher.encrypt(padded_data)
                
                # Combine IV and ciphertext
                encrypted_data = iv + ciphertext
                encoded_data = base64.b64encode(encrypted_data).decode()
                
                console.print(f"\n{Back.BLACK}{Fore.GREEN}[+] Encryption successful!")
                console.print(f"{Back.BLACK}{Fore.GREEN}Encrypted data: {encoded_data}")
                
            except Exception as e:
                console.print(f"{Back.BLACK}{Fore.RED}[-] Encryption failed: {e}")
        
        elif choice == "2":
            encrypted_input = input(f"{Back.BLACK}{Fore.GREEN}Enter encrypted data: ").strip()
            password = input(f"{Back.BLACK}{Fore.GREEN}Enter password: ").strip()
            
            if not encrypted_input or not password:
                console.print(f"{Back.BLACK}{Fore.RED}[-] Encrypted data and password required!")
                return
            
            try:
                # Generate key from password
                key = hashlib.sha256(password.encode()).digest()
                
                # Decode base64
                encrypted_data = base64.b64decode(encrypted_input)
                
                # Extract IV and ciphertext
                iv = encrypted_data[:16]
                ciphertext = encrypted_data[16:]
                
                # Decrypt
                cipher = AES.new(key, AES.MODE_CBC, iv)
                padded_data = cipher.decrypt(ciphertext)
                plaintext = unpad(padded_data, AES.block_size).decode()
                
                console.print(f"\n{Back.BLACK}{Fore.GREEN}[+] Decryption successful!")
                console.print(f"{Back.BLACK}{Fore.GREEN}Decrypted text: {plaintext}")
                
            except Exception as e:
                console.print(f"{Back.BLACK}{Fore.RED}[-] Decryption failed: {e}")
        
        else:
            console.print(f"{Back.BLACK}{Fore.RED}[-] Invalid operation!")
    
    def show_menu(self):
        """Display crypto tools menu"""
        while True:
            console.print(f"\n{Back.BLACK}{Fore.GREEN}{Style.BRIGHT}🔒 CRYPTOGRAPHY & PASSWORD TOOLS")
            console.print(f"{Back.BLACK}{Fore.GREEN}" + "=" * 50)
            
            options = [
                ("1", "🔍 Hash Analyzer", "Identify and analyze hash types"),
                ("2", "🔐 Password Generator", "Generate secure passwords"),
                ("3", "🔄 Text Encoder/Decoder", "Base64, URL, Hex encoding/decoding"),
                ("4", "🔐 AES Encryption", "Encrypt/decrypt text with AES"),
                ("5", "💀 Hash Cracker", "Dictionary attack on hashes"),
                ("0", "🔙 Back to Main Menu", "Return to BlackDeD main menu")
            ]
            
            menu_table = Table(show_header=True, header_style="bold green on black", style="on black")
            menu_table.add_column("Option", style="green on black", justify="center", width=8)
            menu_table.add_column("Tool", style="bright_green on black", width=25)
            menu_table.add_column("Description", style="white on black", width=40)
            
            for option, tool, description in options:
                menu_table.add_row(option, tool, description)
            
            panel = Panel(menu_table, title="[green on black]Cryptography Tools[/green on black]", border_style="green on black", style="on black")
            console.print(panel)
            
            try:
                choice = input(f"\n{Back.BLACK}{Fore.GREEN}root@blackded:~# Select option: ").strip()
                
                if choice == "1":
                    self.hash_analyzer()
                elif choice == "2":
                    self.password_generator()
                elif choice == "3":
                    self.text_encoder_decoder()
                elif choice == "4":
                    self.aes_encryption()
                elif choice == "5":
                    self.hash_analyzer()  # Same function, different entry point
                elif choice == "0":
                    break
                else:
                    console.print(f"{Back.BLACK}{Fore.RED}[-] Invalid option!")
                
                if choice != "0":
                    input(f"\n{Back.BLACK}{Fore.GREEN}[*] Press Enter to continue...")
                    
            except KeyboardInterrupt:
                console.print(f"\n{Back.BLACK}{Fore.YELLOW}[!] Returning to main menu...")
                break

def main():
    crypto = CryptoTools()
    crypto.show_menu()

if __name__ == "__main__":
    main()
