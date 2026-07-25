#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TCHADIN-CRYP - Suite Cryptographie & Stéganographie Avancée
Créé par GONI (Tchad) - Communauté Hidden World
Version: 1.0
"""

import os
import sys
import base64
import hashlib
import hmac
import secrets
import string
import json
import re
import urllib.parse
import binascii
from pathlib import Path
from datetime import datetime

# Imports cryptographiques
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Imports optionnels
try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

try:
    import qrcode
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

if HAS_RICH:
    console = Console()

# Couleurs ANSI
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

BANNER = f"""
{Colors.CYAN}{Colors.BOLD}
  ████████╗ ██████╗██╗  ██╗ █████╗ ██████╗ ██╗███╗   ██╗      ██████╗██████╗ ██╗   ██╗██████╗ 
  ╚══██╔══╝██╔════╝██║  ██║██╔══██╗██╔══██╗██║████╗  ██║     ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗
     ██║   ██║     ███████║███████║██║  ██║██║██╔██╗ ██║     ██║     ██████╔╝ ╚████╔╝ ██████╔╝
     ██║   ██║     ██╔══██║██╔══██║██║  ██║██║██║╚██╗██║     ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝ 
     ██║   ╚██████╗██║  ██║██║  ██║██████╔╝██║██║ ╚████║     ╚██████╗██║  ██║   ██║   ██║     
     ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═══╝      ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝     
{Colors.END}
{Colors.BLUE}  ═══ SUITE CRYPTOGRAPHIE & STÉGANOGRAPHIE AVANCÉE ═══{Colors.END}
{Colors.YELLOW}  Créé par GONI (Tchad) - Communauté Hidden World{Colors.END}
"""

ZERO_WIDTH_CHARS = {
    '0': '\u200C',
    '1': '\u200D',
    ' ': '\uFEFF'
}

MORSE_CODE = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
    'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
    'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
    'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
    'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
    'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
    '3': '...--', '4': '....-', '5': '.....', '6': '-....',
    '7': '--...', '8': '---..', '9': '----.',
    ' ': '/', '.': '.-.-.-', ',': '--..--', '?': '..--..'
}


class TchadinCryp:
    def __init__(self):
        self.history = []
        
    def clear(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        
    def print_banner(self):
        self.clear()
        print(BANNER)
        
    def log(self, msg, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        colors = {
            "INFO": Colors.CYAN,
            "SUCCESS": Colors.GREEN,
            "WARNING": Colors.YELLOW,
            "DANGER": Colors.RED
        }
        color = colors.get(level, Colors.WHITE)
        print(f"{Colors.BOLD}[{timestamp}]{Colors.END} {color}[{level}]{Colors.END} {msg}")
        self.history.append({"time": timestamp, "level": level, "msg": msg})
        
    def get_input(self, prompt):
        return input(f"{Colors.GREEN}{Colors.BOLD}[TCHADIN-CRYP] ➜ {Colors.END}{prompt}")
        
    def print_menu(self):
        menu_items = [
            ("1", "🔐 Chiffrement symétrique", "AES, Fernet, XOR, César, Vigenère"),
            ("2", "🔑 Chiffrement asymétrique", "RSA génération/clés/chiffrement"),
            ("3", "🖼️ Stéganographie image", "Cacher du texte/fichier dans une image"),
            ("4", "📝 Stéganographie texte", "Zero-width characters"),
            ("5", "🎵 Stéganographie audio", "Cacher du texte dans un WAV"),
            ("6", "🔑 Hachage", "MD5, SHA, BLAKE2, HMAC"),
            ("7", "📝 Encodage/Décodage", "Base64, Hex, URL, ROT, Morse"),
            ("8", "🛠️ Outils", "Password, QR code, RSA keys, entropie"),
            ("9", "📜 Historique", "Voir les opérations récentes"),
            ("0", "🚪 Quitter", "Fermer TCHADIN-CRYP")
        ]
        
        if HAS_RICH:
            table = Table(title="MENU PRINCIPAL TCHADIN-CRYP", box=box.DOUBLE_EDGE)
            table.add_column("ID", style="cyan bold", justify="center")
            table.add_column("Module", style="blue bold")
            table.add_column("Description", style="white")
            for item in menu_items:
                table.add_row(item[0], item[1], item[2])
            console.print(Panel(table, border_style="cyan"))
        else:
            print(f"\n{Colors.CYAN}{Colors.BOLD}╔════════════════════════════════════════════════════════╗")
            print(f"║          MENU PRINCIPAL TCHADIN-CRYP                   ║")
            print(f"╚════════════════════════════════════════════════════════╝{Colors.END}\n")
            for item in menu_items:
                print(f"  {Colors.YELLOW}[{item[0]}]{Colors.END} {Colors.BLUE}{item[1]:<30}{Colors.END} - {item[2]}")
        print()

    # ==================== CHIFFREMENT SYMÉTRIQUE ====================
    def symmetric_crypto(self):
        self.print_banner()
        print(f"{Colors.CYAN}{Colors.BOLD}🔐 CHIFFREMENT SYMÉTRIQUE{Colors.END}\n")
        print("1. AES-256-GCM (mot de passe)")
        print("2. Fernet")
        print("3. XOR")
        print("4. César")
        print("5. Vigenère")
        print("6. Retour")
        
        choice = self.get_input("Choix: ").strip()
        
        if choice == '1':
            self.aes_encrypt()
        elif choice == '2':
            self.fernet_crypto()
        elif choice == '3':
            self.xor_crypto()
        elif choice == '4':
            self.caesar_crypto()
        elif choice == '5':
            self.vigenere_crypto()
            
    def aes_encrypt(self):
        text = self.get_input("Texte à chiffrer: ")
        password = self.get_input("Mot de passe: ")
        
        try:
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = kdf.derive(password.encode())
            
            iv = os.urandom(12)
            encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
            ciphertext = encryptor.update(text.encode()) + encryptor.finalize()
            
            result = base64.b64encode(salt + iv + encryptor.tag + ciphertext).decode()
            self.log(f"AES-256-GCM: {result}", "SUCCESS")
            self.log("Pour déchiffrer: utilisez le même mot de passe", "INFO")
        except Exception as e:
            self.log(f"Erreur AES: {e}", "DANGER")
            
    def fernet_crypto(self):
        text = self.get_input("Texte: ")
        mode = self.get_input("Chiffrer (c) ou Déchiffrer (d) ?: ").lower()
        
        try:
            if mode == 'c':
                key = Fernet.generate_key()
                f = Fernet(key)
                token = f.encrypt(text.encode())
                self.log(f"Clé: {key.decode()}", "SUCCESS")
                self.log(f"Chiffré: {token.decode()}", "SUCCESS")
            elif mode == 'd':
                key = self.get_input("Clé Fernet: ").encode()
                token = text.encode()
                f = Fernet(key)
                decrypted = f.decrypt(token)
                self.log(f"Déchiffré: {decrypted.decode()}", "SUCCESS")
        except Exception as e:
            self.log(f"Erreur Fernet: {e}", "DANGER")
            
    def xor_crypto(self):
        text = self.get_input("Texte: ")
        key = self.get_input("Clé: ")
        
        result = ""
        for i, char in enumerate(text):
            result += chr(ord(char) ^ ord(key[i % len(key)]))
        
        encoded = base64.b64encode(result.encode()).decode()
        self.log(f"XOR chiffré (Base64): {encoded}", "SUCCESS")
        
    def caesar_crypto(self):
        text = self.get_input("Texte: ")
        shift = int(self.get_input("Décalage (ex: 3): ") or "3")
        mode = self.get_input("Chiffrer (c) ou Déchiffrer (d) ?: ").lower()
        
        result = ""
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                if mode == 'c':
                    result += chr((ord(char) - base + shift) % 26 + base)
                else:
                    result += chr((ord(char) - base - shift) % 26 + base)
            else:
                result += char
        self.log(f"Résultat César: {result}", "SUCCESS")
        
    def vigenere_crypto(self):
        text = self.get_input("Texte: ")
        key = self.get_input("Clé: ").upper()
        mode = self.get_input("Chiffrer (c) ou Déchiffrer (d) ?: ").lower()
        
        result = ""
        key_len = len(key)
        j = 0
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                k = ord(key[j % key_len]) - ord('A')
                if mode == 'c':
                    result += chr((ord(char.upper()) - ord('A') + k) % 26 + base)
                else:
                    result += chr((ord(char.upper()) - ord('A') - k) % 26 + base)
                j += 1
            else:
                result += char
        self.log(f"Résultat Vigenère: {result}", "SUCCESS")

    # ==================== CHIFFREMENT ASYMÉTRIQUE ====================
    def asymmetric_crypto(self):
        self.print_banner()
        print(f"{Colors.CYAN}{Colors.BOLD}🔑 CHIFFREMENT ASYMÉTRIQUE RSA{Colors.END}\n")
        print("1. Générer une paire de clés RSA")
        print("2. Chiffrer un message avec clé publique")
        print("3. Déchiffrer un message avec clé privée")
        print("4. Retour")
        
        choice = self.get_input("Choix: ").strip()
        
        if choice == '1':
            self.generate_rsa_keys()
        elif choice == '2':
            self.rsa_encrypt()
        elif choice == '3':
            self.rsa_decrypt()
            
    def generate_rsa_keys(self):
        try:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()
            
            pem_private = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            pem_public = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            with open("private_key.pem", "wb") as f:
                f.write(pem_private)
            with open("public_key.pem", "wb") as f:
                f.write(pem_public)
                
            self.log("Clés RSA générées: private_key.pem, public_key.pem", "SUCCESS")
        except Exception as e:
            self.log(f"Erreur RSA: {e}", "DANGER")
            
    def rsa_encrypt(self):
        message = self.get_input("Message à chiffrer: ").encode()
        pub_path = self.get_input("Chemin clé publique (défaut: public_key.pem): ") or "public_key.pem"
        
        try:
            with open(pub_path, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())
            encrypted = public_key.encrypt(
                message,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(), label=None)
            )
            result = base64.b64encode(encrypted).decode()
            self.log(f"RSA chiffré: {result}", "SUCCESS")
        except Exception as e:
            self.log(f"Erreur chiffrement RSA: {e}", "DANGER")
            
    def rsa_decrypt(self):
        encrypted = base64.b64decode(self.get_input("Message chiffré (Base64): "))
        priv_path = self.get_input("Chemin clé privée (défaut: private_key.pem): ") or "private_key.pem"
        
        try:
            with open(priv_path, "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)
            decrypted = private_key.decrypt(
                encrypted,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(), label=None)
            )
            self.log(f"RSA déchiffré: {decrypted.decode()}", "SUCCESS")
        except Exception as e:
            self.log(f"Erreur déchiffrement RSA: {e}", "DANGER")

    # ==================== STÉGANOGRAPHIE IMAGE ====================
    def image_steganography(self):
        self.print_banner()
        print(f"{Colors.CYAN}{Colors.BOLD}🖼️ STÉGANOGRAPHIE IMAGE (LSB){Colors.END}\n")
        
        if not HAS_PIL:
            self.log("Pillow non installé. Installez: pip install Pillow", "DANGER")
            self.get_input("Appuyez sur Entrée...")
            return
            
        print("1. Cacher du texte dans une image")
        print("2. Extraire du texte d'une image")
        print("3. Retour")
        
        choice = self.get_input("Choix: ").strip()
        
        if choice == '1':
            self.hide_text_in_image()
        elif choice == '2':
            self.extract_text_from_image()
            
    def hide_text_in_image(self):
        image_path = self.get_input("Chemin image PNG: ")
        text = self.get_input("Texte à cacher: ")
        output = self.get_input("Image de sortie (défaut: output.png): ") or "output.png"
        
        try:
            img = Image.open(image_path)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            binary = ''.join(format(ord(c), '08b') for c in text) + '00000000'
            pixels = list(img.getdata())
            
            if len(binary) > len(pixels) * 3:
                self.log("Texte trop long pour cette image", "DANGER")
                return
                
            new_pixels = []
            binary_index = 0
            for pixel in pixels:
                new_pixel = list(pixel)
                for i in range(3):
                    if binary_index < len(binary):
                        new_pixel[i] = (new_pixel[i] & ~1) | int(binary[binary_index])
                        binary_index += 1
                new_pixels.append(tuple(new_pixel))
                
            new_img = Image.new(img.mode, img.size)
            new_img.putdata(new_pixels)
            new_img.save(output)
            self.log(f"Texte caché dans {output}", "SUCCESS")
        except Exception as e:
            self.log(f"Erreur stéganographie: {e}", "DANGER")
            
    def extract_text_from_image(self):
        image_path = self.get_input("Chemin image PNG: ")
        
        try:
            img = Image.open(image_path)
            pixels = list(img.getdata())
            binary = ""
            
            for pixel in pixels:
                for i in range(3):
                    binary += str(pixel[i] & 1)
                    
            chars = []
            for i in range(0, len(binary), 8):
                byte = binary[i:i+8]
                if byte == '00000000':
                    break
                chars.append(chr(int(byte, 2)))
                
            result = ''.join(chars)
            self.log(f"Texte extrait: {result}", "SUCCESS")
        except Exception as e:
            self.log(f"Erreur extraction: {e}", "DANGER")

    # ==================== STÉGANOGRAPHIE TEXTE ====================
    def text_steganography(self):
        self.print_banner()
        print(f"{Colors.CYAN}{Colors.BOLD}📝 STÉGANOGRAPHIE TEXTE{Colors.END}\n")
        print("1. Cacher du texte dans du texte (zero-width)")
        print("2. Extraire le texte caché")
        print("3. Retour")
        
        choice = self.get_input("Choix: ").strip()
        
        if choice == '1':
            self.hide_text_in_text()
        elif choice == '2':
            self.extract_text_from_text()
            
    def text_to_binary(self, text):
        return ''.join(format(ord(c), '08b') for c in text)
        
    def hide_text_in_text(self):
        cover = self.get_input("Texte visible (cover): ")
        secret = self.get_input("Texte secret: ")
        
        binary = self.text_to_binary(secret)
        hidden = ''
        for bit in binary:
            hidden += ZERO_WIDTH_CHARS[bit]
        
        # Insérer après le premier caractère
        result = cover[0] + hidden + cover[1:] if len(cover) > 1 else cover + hidden
        self.log(f"Texte avec secret: {result}", "SUCCESS")
        self.log("(Le texte secret est invisible)", "INFO")
        
    def extract_text_from_text(self):
        text = self.get_input("Collez le texte contenant le secret: ")
        
        binary = ""
        for char in text:
            if char == ZERO_WIDTH_CHARS['0']:
                binary += '0'
            elif char == ZERO_WIDTH_CHARS['1']:
                binary += '1'
                
        chars = []
        for i in range(0, len(binary), 8):
            byte = binary[i:i+8]
            if len(byte) < 8:
                break
            chars.append(chr(int(byte, 2)))
            
        result = ''.join(chars)
        self.log(f"Secret extrait: {result}", "SUCCESS")

    # ==================== STÉGANOGRAPHIE AUDIO ====================
    def audio_steganography(self):
        self.print_banner()
        print(f"{Colors.CYAN}{Colors.BOLD}🎵 STÉGANOGRAPHIE AUDIO WAV{Colors.END}\n")
        print("1. Cacher du texte dans un WAV")
        print("2. Extraire du texte d'un WAV")
        print("3. Retour")
        
        choice = self.get_input("Choix: ").strip()
        
        if choice == '1':
            self.hide_text_in_audio()
        elif choice == '2':
            self.extract_text_from_audio()
            
    def hide_text_in_audio(self):
        if not HAS_NUMPY:
            self.log("NumPy requis. Installez: pip install numpy", "DANGER")
            return
            
        audio_path = self.get_input("Chemin fichier WAV: ")
        text = self.get_input("Texte à cacher: ")
        output = self.get_input("Fichier de sortie (défaut: output.wav): ") or "output.wav"
        
        try:
            import wave
            with wave.open(audio_path, 'rb') as wav:
                params = wav.getparams()
                frames = bytearray(wav.readframes(params.nframes))
                
            binary = ''.join(format(ord(c), '08b') for c in text) + '00000000'
            
            if len(binary) > len(frames):
                self.log("Texte trop long pour ce fichier audio", "DANGER")
                return
                
            for i, bit in enumerate(binary):
                frames[i] = (frames[i] & ~1) | int(bit)
                
            with wave.open(output, 'wb') as wav:
                wav.setparams(params)
                wav.writeframes(bytes(frames))
                
            self.log(f"Texte caché dans {output}", "SUCCESS")
        except Exception as e:
            self.log(f"Erreur audio: {e}", "DANGER")
            
    def extract_text_from_audio(self):
        if not HAS_NUMPY:
            self.log("NumPy requis. Installez: pip install numpy", "DANGER")
            return
            
        audio_path = self.get_input("Chemin fichier WAV: ")
        
        try:
            import wave
            with wave.open(audio_path, 'rb') as wav:
                frames = bytearray(wav.readframes(wav.getnframes()))
                
            binary = ""
            for frame in frames:
                binary += str(frame & 1)
                
            chars = []
            for i in range(0, len(binary), 8):
                byte = binary[i:i+8]
                if byte == '00000000':
                    break
                chars.append(chr(int(byte, 2)))
                
            result = ''.join(chars)
            self.log(f"Texte extrait: {result}", "SUCCESS")
        except Exception as e:
            self.log(f"Erreur extraction audio: {e}", "DANGER")

    # ==================== HACHAGE ====================
    def hashing(self):
        self.print_banner()
        print(f"{Colors.CYAN}{Colors.BOLD}🔑 HACHAGE{Colors.END}\n")
        
        text = self.get_input("Texte à hasher: ")
        print("\n1. MD5")
        print("2. SHA1")
        print("3. SHA256")
        print("4. SHA512")
        print("5. SHA3-256")
        print("6. BLAKE2b")
        print("7. HMAC")
        
        choice = self.get_input("Choix: ").strip()
        
        try:
            data = text.encode()
            if choice == '1':
                result = hashlib.md5(data).hexdigest()
            elif choice == '2':
                result = hashlib.sha1(data).hexdigest()
            elif choice == '3':
                result = hashlib.sha256(data).hexdigest()
            elif choice == '4':
                result = hashlib.sha512(data).hexdigest()
            elif choice == '5':
                result = hashlib.sha3_256(data).hexdigest()
            elif choice == '6':
                result = hashlib.blake2b(data).hexdigest()
            elif choice == '7':
                secret = self.get_input("Clé secrète HMAC: ").encode()
                result = hmac.new(secret, data, hashlib.sha256).hexdigest()
            else:
                return
            self.log(f"Hash: {result}", "SUCCESS")
        except Exception as e:
            self.log(f"Erreur hash: {e}", "DANGER")

    # ==================== ENCODAGE ====================
    def encoding(self):
        self.print_banner()
        print(f"{Colors.CYAN}{Colors.BOLD}📝 ENCODAGE / DÉCODAGE{Colors.END}\n")
        print("1. Base64")
        print("2. Base32")
        print("3. Hexadécimal")
        print("4. URL encoding")
        print("5. ROT13")
        print("6. ROT47")
        print("7. Morse")
        print("8. Retour")
        
        choice = self.get_input("Choix: ").strip()
        mode = self.get_input("Encoder (e) ou Décoder (d) ?: ").lower()
        text = self.get_input("Texte: ")
        
        try:
            if choice == '1':
                result = base64.b64encode(text.encode()).decode() if mode == 'e' else base64.b64decode(text).decode()
            elif choice == '2':
                result = base64.b32encode(text.encode()).decode() if mode == 'e' else base64.b32decode(text).decode()
            elif choice == '3':
                result = text.encode().hex() if mode == 'e' else bytes.fromhex(text).decode()
            elif choice == '4':
                result = urllib.parse.quote(text) if mode == 'e' else urllib.parse.unquote(text)
            elif choice == '5':
                result = text.translate(str.maketrans(
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
                ))
            elif choice == '6':
                result = ''.join(chr(33 + ((ord(c) - 33 + 47) % 94)) if 33 <= ord(c) <= 126 else c for c in text) if mode == 'e' else \
                         ''.join(chr(33 + ((ord(c) - 33 - 47) % 94)) if 33 <= ord(c) <= 126 else c for c in text)
            elif choice == '7':
                if mode == 'e':
                    result = ' '.join(MORSE_CODE.get(c.upper(), '?') for c in text)
                else:
                    reverse_morse = {v: k for k, v in MORSE_CODE.items()}
                    result = ''.join(reverse_morse.get(c, '?') for c in text.split())
            else:
                return
            self.log(f"Résultat: {result}", "SUCCESS")
        except Exception as e:
            self.log(f"Erreur encodage: {e}", "DANGER")

    # ==================== OUTILS ====================
    def tools(self):
        self.print_banner()
        print(f"{Colors.CYAN}{Colors.BOLD}🛠️ OUTILS{Colors.END}\n")
        print("1. Générateur de mot de passe")
        print("2. Générateur de QR Code")
        print("3. Analyse d'entropie")
        print("4. Retour")
        
        choice = self.get_input("Choix: ").strip()
        
        if choice == '1':
            self.generate_password()
        elif choice == '2':
            self.generate_qr()
        elif choice == '3':
            self.analyze_entropy()
            
    def generate_password(self):
        length = int(self.get_input("Longueur (défaut 16): ") or "16")
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(chars) for _ in range(length))
        self.log(f"Mot de passe généré: {password}", "SUCCESS")
        
    def generate_qr(self):
        if not HAS_QRCODE:
            self.log("qrcode non installé. Installez: pip install qrcode", "DANGER")
            return
        text = self.get_input("Texte/URL pour le QR: ")
        filename = self.get_input("Nom du fichier (défaut: qr.png): ") or "qr.png"
        try:
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(text)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(filename)
            self.log(f"QR Code généré: {filename}", "SUCCESS")
        except Exception as e:
            self.log(f"Erreur QR: {e}", "DANGER")
            
    def analyze_entropy(self):
        text = self.get_input("Texte à analyser: ")
        if not text:
            return
        import math
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        length = len(text)
        entropy = -sum((count/length) * math.log2(count/length) for count in freq.values())
        self.log(f"Entropie: {entropy:.4f} bits/caractère", "SUCCESS")
        self.log(f"Unique chars: {len(freq)}/{length}", "INFO")

    # ==================== HISTORIQUE ====================
    def show_history(self):
        self.print_banner()
        print(f"{Colors.CYAN}{Colors.BOLD}📜 HISTORIQUE{Colors.END}\n")
        for entry in self.history[-20:]:
            print(f"[{entry['time']}] [{entry['level']}] {entry['msg']}")
        self.get_input("\nAppuyez sur Entrée...")

    # ==================== MAIN ====================
    def run(self):
        while True:
            self.print_banner()
            self.print_menu()
            choice = self.get_input("Choisissez une option: ").strip()
            
            if choice == '1':
                self.symmetric_crypto()
            elif choice == '2':
                self.asymmetric_crypto()
            elif choice == '3':
                self.image_steganography()
            elif choice == '4':
                self.text_steganography()
            elif choice == '5':
                self.audio_steganography()
            elif choice == '6':
                self.hashing()
            elif choice == '7':
                self.encoding()
            elif choice == '8':
                self.tools()
            elif choice == '9':
                self.show_history()
            elif choice == '0':
                self.log("Fermeture de TCHADIN-CRYP...", "INFO")
                break
            else:
                self.log("Option invalide", "WARNING")


def main():
    app = TchadinCryp()
    try:
        app.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Interruption par l'utilisateur{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}Erreur fatale: {e}{Colors.END}")


if __name__ == "__main__":
    main()