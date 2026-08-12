#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TYPE-ENCODER
Outil éducatif avancé d'analyse et de conversion d'encodages de texte.
Créé par Hidden World Communauté Tchadienne.
Usage éducatif uniquement.
"""

import os
import sys
import base64
import binascii
from pathlib import Path
from time import sleep

VERSION = "1.0.0"
AUTEUR = "Hackers Tchadiens - Hidden World"

BANNER = r"""
╔══════════════════════════════════════════════════════════════════════╗
║  ████████╗██╗   ██╗██████╗ ███████╗    ███████╗███╗   ██╗ ██████╗  ║
║  ╚══██╔══╝╚██╗ ██╔╝██╔══██╗██╔════╝    ██╔════╝████╗  ██║██╔════╝  ║
║     ██║    ╚████╔╝ ██████╔╝█████╗      █████╗  ██╔██╗ ██║██║  ███╗ ║
║     ██║     ╚██╔╝  ██╔═══╝ ██╔══╝      ██╔══╝  ██║╚██╗██║██║   ██║ ║
║     ██║      ██║   ██║     ███████╗    ███████╗██║ ╚████║╚██████╔╝ ║
║     ╚═╝      ╚═╝   ╚═╝     ╚══════╝    ╚══════╝╚═╝  ╚═══╝ ╚═════╝  ║
║                                                                      ║
║        Analyse et conversion d'encodages de texte                   ║
║        UTF-8 | ASCII | Base64 | Hex | Binary | URL | ROT13          ║
╚══════════════════════════════════════════════════════════════════════╝
"""


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def pause():
    input("\n[Appuyez sur ENTRÉE pour continuer...]")


def progress_bar(label: str, duration: float = 1.0, steps: int = 50):
    print(f"\n{label}")
    for i in range(steps + 1):
        pct = i * 2
        bar = "█" * i + "░" * (steps - i)
        print(f"\r[{bar}] {pct}%", end="", flush=True)
        sleep(duration / steps)
    print("  [OK]")


def header(title: str):
    clear_screen()
    print("╔" + "═" * 70 + "╗")
    print("║" + title.center(70) + "║")
    print("╚" + "═" * 70 + "╝\n")


def detect_encoding(text: str):
    result = {
        "type": "unicode_string",
        "length_chars": len(text),
        "length_bytes_utf8": len(text.encode("utf-8")),
        "length_bytes_utf16": len(text.encode("utf-16-le")),
        "length_bytes_latin1": len(text.encode("latin-1", errors="ignore")),
        "is_ascii": all(ord(c) < 128 for c in text),
        "is_printable": all(c.isprintable() or c in "\n\r\t" for c in text),
        "sample_bytes_utf8": text.encode("utf-8")[:16].hex(" "),
    }
    return result


def to_ascii(text: str) -> str:
    return "".join(c if ord(c) < 128 else "?" for c in text)


def to_base64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def from_base64(data: str) -> str:
    return base64.b64decode(data.encode("ascii")).decode("utf-8")


def to_hex(text: str) -> str:
    return text.encode("utf-8").hex()


def from_hex(data: str) -> str:
    return bytes.fromhex(data).decode("utf-8")


def to_binary(text: str) -> str:
    return " ".join(format(b, "08b") for b in text.encode("utf-8"))


def from_binary(data: str) -> str:
    cleaned = data.replace(" ", "").replace("\n", "")
    return bytes(int(cleaned[i:i+8], 2) for i in range(0, len(cleaned), 8)).decode("utf-8")


def to_url(text: str) -> str:
    from urllib.parse import quote
    return quote(text, safe="")


def from_url(data: str) -> str:
    from urllib.parse import unquote
    return unquote(data)


def rot13(text: str) -> str:
    return text.translate(str.maketrans(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM"))


def analyze_text(text: str):
    header("ANALYSE D'ENCODAGE DE TEXTE")
    progress_bar("Analyse en cours...", duration=1.2)

    info = detect_encoding(text)

    print("\n╔" + "═" * 70 + "╗")
    print("║" + " RÉSULTATS DE L'ANALYSE ".center(70) + "║")
    print("╠" + "═" * 70 + "╣")
    print(f"║ Texte analysé        : {text[:50]}{'...' if len(text) > 50 else ''}".ljust(71) + "║")
    print(f"║ Nombre de caractères : {info['length_chars']}".ljust(71) + "║")
    print(f"║ Taille en UTF-8      : {info['length_bytes_utf8']} octets".ljust(71) + "║")
    print(f"║ Taille en UTF-16 LE  : {info['length_bytes_utf16']} octets".ljust(71) + "║")
    print(f"║ Taille en Latin-1    : {info['length_bytes_latin1']} octets".ljust(71) + "║")
    print(f"║ ASCII uniquement     : {'OUI' if info['is_ascii'] else 'NON'}".ljust(71) + "║")
    print(f"║ Caractères imprimables : {'OUI' if info['is_printable'] else 'NON'}".ljust(71) + "║")
    print(f"║ Échantillon UTF-8    : {info['sample_bytes_utf8']}".ljust(71) + "║")
    print("╚" + "═" * 70 + "╝")

    print("\n[ℹ] Explication :")
    if info["is_ascii"]:
        print("    Ce texte est en ASCII pur. Il est donc aussi compatible UTF-8 et Latin-1.")
    else:
        print("    Ce texte contient des caractères non-ASCII. UTF-8 est recommandé.")
    pause()


def convert_menu():
    header("CONVERSION ENTRE ENCODAGES")
    print("Source du texte :")
    print("  [1] Saisir du texte brut")
    print("  [2] Charger depuis un fichier .txt")
    choice = input("\nVotre choix : ").strip()

    text = ""
    if choice == "2":
        path = input("Chemin du fichier : ").strip()
        if not os.path.isfile(path):
            print("[ERREUR] Fichier introuvable.")
            pause()
            return
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
    else:
        text = input("\nEntrez le texte à convertir : ").strip()

    if not text:
        print("[ERREUR] Texte vide.")
        pause()
        return

    progress_bar("Conversion en cours...", duration=1.0)

    print("\n╔" + "═" * 70 + "╗")
    print("║" + " RÉSULTATS DE CONVERSION ".center(70) + "║")
    print("╠" + "═" * 70 + "╣")
    print(f"║ UTF-8 (texte)        : {text[:45]}{'...' if len(text) > 45 else ''}".ljust(71) + "║")
    print(f"║ ASCII                : {to_ascii(text)[:45]}{'...' if len(text) > 45 else ''}".ljust(71) + "║")
    print(f"║ Base64               : {to_base64(text)[:60]}".ljust(71) + "║")
    print(f"║ Hexadécimal (UTF-8)  : {to_hex(text)[:60]}".ljust(71) + "║")
    print(f"║ Binaire (UTF-8)      : {to_binary(text)[:60]}...".ljust(71) + "║")
    print(f"║ URL-encoded          : {to_url(text)[:60]}".ljust(71) + "║")
    print(f"║ ROT13                : {rot13(text)[:45]}{'...' if len(text) > 45 else ''}".ljust(71) + "║")
    print("╚" + "═" * 70 + "╝")

    output = input("\nSauvegarder dans un fichier ? [nom ou vide pour ignorer] : ").strip()
    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(f"Texte original : {text}\n\n")
            f.write(f"ASCII          : {to_ascii(text)}\n")
            f.write(f"Base64         : {to_base64(text)}\n")
            f.write(f"Hex            : {to_hex(text)}\n")
            f.write(f"Binary         : {to_binary(text)}\n")
            f.write(f"URL            : {to_url(text)}\n")
            f.write(f"ROT13          : {rot13(text)}\n")
        print(f"[✓] Sauvegardé dans : {os.path.abspath(output)}")
    pause()


def decode_menu():
    header("DÉCODAGE D'UN TEXTE ENCODÉ")
    print("Types supportés : Base64, Hex, Binary, URL, ROT13")
    data = input("Entrez le texte encodé : ").strip()
    if not data:
        print("[ERREUR] Entrée vide.")
        pause()
        return

    progress_bar("Tentatives de décodage...", duration=1.0)

    results = {}

    # Base64
    try:
        results["Base64"] = from_base64(data)
    except Exception:
        results["Base64"] = "[ÉCHEC]"

    # Hex
    try:
        results["Hex"] = from_hex(data)
    except Exception:
        results["Hex"] = "[ÉCHEC]"

    # Binary
    try:
        results["Binary"] = from_binary(data)
    except Exception:
        results["Binary"] = "[ÉCHEC]"

    # URL
    try:
        results["URL"] = from_url(data)
    except Exception:
        results["URL"] = "[ÉCHEC]"

    # ROT13 (toujours applicable)
    results["ROT13"] = rot13(data)

    print("\n╔" + "═" * 70 + "╗")
    print("║" + " RÉSULTATS DU DÉCODAGE ".center(70) + "║")
    print("╠" + "═" * 70 + "╣")
    for enc, value in results.items():
        display = value[:60] + "..." if len(value) > 60 else value
        print(f"║ {enc.ljust(10)} : {display}".ljust(71) + "║")
    print("╚" + "═" * 70 + "╝")
    pause()


def learning_menu():
    header("APPRENDRE LES ENCODAGES")
    encodings = [
        ("ASCII", "American Standard Code for Information Interchange. 128 caractères de base (lettres, chiffres, symboles)."),
        ("UTF-8", "Encodage Unicode variable. Compatible ASCII, supporte toutes les langues. Standard mondial."),
        ("UTF-16", "Encodage Unicode à 2 ou 4 octets par caractère. Utilisé par Windows et Java."),
        ("Latin-1 (ISO-8859-1)", "Encodage européen occidental sur 1 octet. Ne supporte pas les alphabets asiatiques."),
        ("Base64", "Conversion binaire → texte ASCII. Utilisé pour transférer des données dans du texte."),
        ("Hexadécimal", "Représentation binaire en base 16 (0-9, A-F). Chaque octet = 2 caractères hex."),
        ("Binaire", "Représentation en base 2 (0 et 1). Langage fondamental des ordinateurs."),
        ("URL Encoding", "Encode les caractères spéciaux pour les URLs (%20 pour l'espace, etc.)."),
        ("ROT13", "Chiffrement par décalage de 13 lettres. Simple et réversible."),
    ]
    for name, desc in encodings:
        print(f"\n[•] {name}")
        print(f"    {desc}")
    pause()


def about():
    header("À PROPOS")
    print(f"Nom     : TYPE-ENCODER")
    print(f"Version : {VERSION}")
    print(f"Auteur  : {AUTEUR}")
    print("\nOutil éducatif pour analyser, convertir et décoder des encodages de texte.")
    pause()


def main_menu():
    while True:
        clear_screen()
        print(BANNER)
        print("╔" + "═" * 70 + "╗")
        print("║" + " MENU PRINCIPAL ".center(70) + "║")
        print("╠" + "═" * 70 + "╣")
        print("║  [1] Analyser un texte (détecter l'encodage)                       ║")
        print("║  [2] Convertir un texte (UTF-8 → Base64 / Hex / Binary / URL...)   ║")
        print("║  [3] Décoder un texte encodé                                       ║")
        print("║  [4] Apprendre les types d'encodage                                ║")
        print("║  [5] À propos                                                      ║")
        print("║  [0] Quitter                                                       ║")
        print("╚" + "═" * 70 + "╝")
        choice = input("\nVotre choix : ").strip()

        if choice == "1":
            header("ANALYSE D'ENCODAGE")
            text = input("Entrez le texte à analyser : ").strip()
            if text:
                analyze_text(text)
        elif choice == "2":
            convert_menu()
        elif choice == "3":
            decode_menu()
        elif choice == "4":
            learning_menu()
        elif choice == "5":
            about()
        elif choice == "0":
            clear_screen()
            print("Merci d'avoir utilisé TYPE-ENCODER.".center(70))
            print("Hidden World Communauté Tchadienne".center(70))
            break
        else:
            print("\n[ERREUR] Choix invalide.")
            pause()


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\nInterrompu par l'utilisateur.")
