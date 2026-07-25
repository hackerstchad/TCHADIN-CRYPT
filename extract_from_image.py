#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TCHADIN-CRYP - Extracteur de données cachées dans une image
Créé par GONI (Tchad) - Communauté Hidden World

Extrait du texte dissimulé dans une image PNG par stéganographie LSB.
"""

import sys
from PIL import Image


def extract_text(image_path):
    """Extrait le texte caché par LSB dans une image PNG"""
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

        return ''.join(chars)

    except FileNotFoundError:
        return "Erreur: fichier non trouvé"
    except Exception as e:
        return f"Erreur: {e}"


def main():
    if len(sys.argv) < 2:
        image_path = input("Chemin de l'image PNG: ").strip()
    else:
        image_path = sys.argv[1]

    print("[TCHADIN-CRYP] Extraction en cours...")
    result = extract_text(image_path)
    print("\nTexte extrait:")
    print(result)


if __name__ == "__main__":
    main()