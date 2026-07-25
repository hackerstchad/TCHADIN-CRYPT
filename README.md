# 🔐 TCHADIN-CRYP - Suite de Cryptographie & Stéganographie
<img width="1024" height="1024" alt="WhatsApp Image 2026-07-25 at 10 20 14" src="https://github.com/user-attachments/assets/54378f23-9be0-41ca-8252-2931df87e49b" />


**Outils avancés pour cacher, chiffrer, hasher et protéger vos données**

Créé par GONI - Hacker Tchadien  
Communauté Hidden World

## 🛡️ Description

TCHADIN-CRYP est une suite complète de sécurité de l'information qui combine :
- **Cryptographie** : chiffrement symétrique et asymétrique
- **Stéganographie** : dissimulation de données dans images, textes et audio
- **Hachage** : multiples algorithmes de hash
- **Encodage** : Base64, Base32, Base58, Hex, URL, etc.
- **Outils utilitaires** : génération de mots de passe, QR codes, etc.

## ✨ Fonctionnalités Principales

### 🔒 Chiffrement
- AES-256 (GCM, CBC, ECB)
- RSA génération de clés, chiffrement/déchiffrement
- Fernet (chiffrement symétrique simple)
- Chiffrement César, Vigenère, XOR
- Chiffrement par mot de passe dérivé (PBKDF2)

### 🖼️ Stéganographie
- LSB (Least Significant Bit) sur images PNG
- Stéganographie texte (zero-width characters)
- Stéganographie audio (LSB sur fichiers WAV)
- Dissimulation de fichiers dans images

### 🔑 Hachage
- MD5, SHA1, SHA256, SHA512, SHA3, BLAKE2
- HMAC avec secret
- Vérification d'intégrité

### 📝 Encodage/Décodage
- Base64, Base32, Base58, Base85
- Hexadécimal
- URL encoding
- ROT13, ROT47
- Morse

### 🛠️ Outils
- Générateur de mots de passe forts
- Générateur de QR code
- Générateur de paires de clés RSA
- Analyse d'entropie

## 🚀 Installation

```bash
cd TCHADIN-CRYP
pip install -r requirements.txt
python tchadin_cryp.py
```

## 📖 Utilisation

1. Lancez l'application
2. Choisissez une catégorie dans le menu
3. Sélectionnez l'algorithme ou la méthode
4. Entrez vos données et obtenez le résultat

## 🔒 Sécurité

Tous les chiffrements sont effectués localement. Aucune donnée n'est envoyée sur Internet.

## 📝 Licence

Éducatif - Libre d'utilisation pour la protection de vos propres données
