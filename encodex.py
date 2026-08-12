#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ENCODEX — Détecteur avancé de type d'encodage pour texte et données.
Créé par la communauté Hacker Tchadien / Hidden World.
Version : 2.0.0
"""

import os
import re
import sys
import json
import base64
import base58
import binascii
import argparse
import datetime
from pathlib import Path
from typing import List, Tuple, Dict, Optional
from urllib.parse import unquote

import chardet


try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
APP_NAME = "ENCODEX"
APP_VERSION = "2.0.0"
APP_AUTHOR = "Hacker Tchadien — Hidden World"

console = Console() if RICH_AVAILABLE else None


def info(msg: str):
    if console:
        console.print(f"[bold green][+][/bold green] {msg}")
    else:
        print(f"[+] {msg}")


def warn(msg: str):
    if console:
        console.print(f"[bold yellow][!][/bold yellow] {msg}")
    else:
        print(f"[!] {msg}")


def error(msg: str):
    if console:
        console.print(f"[bold red][x][/bold red] {msg}")
    else:
        print(f"[x] {msg}")


def section(title: str):
    if console:
        console.print(Panel(f"[bold bright_cyan]{title}[/bold bright_cyan]", border_style="cyan"))
    else:
        print(f"\n=== {title} ===\n")


# ---------------------------------------------------------------------------
# LOGO ASCII
# ---------------------------------------------------------------------------
def print_banner():
    banner = """
 ███████╗███╗   ██╗ ██████╗ ██████╗ ██████╗ ███████╗██╗  ██╗
 ██╔════╝████╗  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝╚██╗██╔╝
 █████╗  ██╔██╗ ██║██║     ██║   ██║██║  ██║█████╗   ╚███╔╝ 
 ██╔══╝  ██║╚██╗██║██║     ██║   ██║██║  ██║██╔══╝   ██╔██╗ 
 ███████╗██║ ╚████║╚██████╗╚██████╔╝██████╔╝███████╗██╔╝ ██╗
 ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
    """
    if console:
        console.print(Panel.fit(f"[bold cyan]{banner}[/bold cyan]\n"
                                f"[bold green]Détecteur de type d'encodage — v{APP_VERSION}[/bold green]\n"
                                f"[dim]Auteur: {APP_AUTHOR}[/dim]",
                                title=f"[bold]{APP_NAME}[/bold]",
                                border_style="green", box=box.DOUBLE))
    else:
        print(banner)
        print(f"ENCODEX v{APP_VERSION} — {APP_AUTHOR}\n")


# ---------------------------------------------------------------------------
# UTILITAIRES
# ---------------------------------------------------------------------------
def is_hex(s: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]+", s)) and len(s) % 2 == 0 and len(s) >= 2


def is_base64(s: str) -> bool:
    pattern = r"^[A-Za-z0-9+/]+={0,2}$"
    return bool(re.fullmatch(pattern, s)) and len(s) >= 4 and len(s) % 4 == 0


def is_base32(s: str) -> bool:
    pattern = r"^[A-Z2-7]+={0,6}$"
    return bool(re.fullmatch(pattern, s)) and len(s) >= 8 and len(s) % 8 == 0


def is_base58(s: str) -> bool:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    return all(c in alphabet for c in s) and len(s) >= 4


def is_binary(s: str) -> bool:
    return bool(re.fullmatch(r"[01\s]+", s)) and any(c in s for c in "01") and len(re.sub(r"\s", "", s)) >= 8


def is_url_encoded(s: str) -> bool:
    return "%" in s and bool(re.search(r"%[0-9a-fA-F]{2}", s))


def is_rot_format(s: str) -> bool:
    return s.isalpha() and len(s) >= 3


def is_morse(s: str) -> bool:
    return bool(re.fullmatch(r"[\.\-/\s]+", s)) and ("-" in s or "." in s)


def detect_charset(data: bytes) -> Dict[str, Any]:
    result = chardet.detect(data)
    return {
        "encoding": result.get("encoding", "inconnu"),
        "confidence": round(result.get("confidence", 0.0), 4),
        "language": result.get("language", "inconnu"),
    }


# ---------------------------------------------------------------------------
# DÉCODEURS
# ---------------------------------------------------------------------------
def try_decode_hex(s: str) -> Optional[str]:
    try:
        return bytes.fromhex(s).decode("utf-8", errors="replace")
    except Exception:
        return None


def try_decode_base64(s: str) -> Optional[str]:
    try:
        return base64.b64decode(s, validate=True).decode("utf-8", errors="replace")
    except Exception:
        return None


def try_decode_base32(s: str) -> Optional[str]:
    try:
        return base64.b32decode(s, casefold=True).decode("utf-8", errors="replace")
    except Exception:
        return None


def try_decode_base58(s: str) -> Optional[str]:
    try:
        return base58.b58decode(s).decode("utf-8", errors="replace")
    except Exception:
        return None


def try_decode_binary(s: str) -> Optional[str]:
    try:
        bits = re.sub(r"\s", "", s)
        n = int(bits, 2)
        byte_length = (n.bit_length() + 7) // 8
        return n.to_bytes(byte_length, "big").decode("utf-8", errors="replace")
    except Exception:
        return None


def try_decode_url(s: str) -> Optional[str]:
    try:
        decoded = unquote(s)
        return decoded if decoded != s else None
    except Exception:
        return None


def rot_all(s: str) -> List[Tuple[int, str]]:
    results = []
    for shift in range(1, 26):
        out = ""
        for ch in s:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                out += chr((ord(ch) - base + shift) % 26 + base)
            else:
                out += ch
        results.append((shift, out))
    return results


def morse_to_text(s: str) -> Optional[str]:
    MORSE = {
        ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
        "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
        "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
        ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
        "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
        "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
        "...--": "3", "....-": "4", ".....": "5", "-....": "6",
        "--...": "7", "---..": "8", "----.": "9",
    }
    words = s.strip().split(" / ")
    out = []
    for word in words:
        letters = word.split()
        out.append("".join(MORSE.get(l, "?") for l in letters))
    return " ".join(out)


# ---------------------------------------------------------------------------
# ANALYSE PRINCIPALE
# ---------------------------------------------------------------------------
def analyze_text(s: str) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []

    if is_hex(s):
        decoded = try_decode_hex(s)
        candidates.append({
            "type": "Hexadécimal (Base16)",
            "confidence": "Très haute" if decoded and decoded.isprintable() else "Haute",
            "decoded_preview": decoded[:200] if decoded else None,
        })

    if is_base64(s):
        decoded = try_decode_base64(s)
        candidates.append({
            "type": "Base64",
            "confidence": "Très haute" if decoded and all(ord(c) < 128 for c in decoded[:50]) else "Haute",
            "decoded_preview": decoded[:200] if decoded else None,
        })

    if is_base32(s):
        decoded = try_decode_base32(s)
        candidates.append({
            "type": "Base32",
            "confidence": "Haute",
            "decoded_preview": decoded[:200] if decoded else None,
        })

    if is_base58(s):
        decoded = try_decode_base58(s)
        candidates.append({
            "type": "Base58",
            "confidence": "Moyenne",
            "decoded_preview": decoded[:200] if decoded else None,
        })

    if is_binary(s):
        decoded = try_decode_binary(s)
        candidates.append({
            "type": "Binaire (Base2)",
            "confidence": "Haute" if decoded and decoded.isprintable() else "Moyenne",
            "decoded_preview": decoded[:200] if decoded else None,
        })

    if is_url_encoded(s):
        decoded = try_decode_url(s)
        candidates.append({
            "type": "URL Encoded (Percent-encoding)",
            "confidence": "Haute",
            "decoded_preview": decoded[:200] if decoded else None,
        })

    if is_morse(s):
        candidates.append({
            "type": "Code Morse",
            "confidence": "Moyenne",
            "decoded_preview": morse_to_text(s)[:200],
        })

    if is_rot_format(s):
        for shift, decoded in rot_all(s):
            # Heuristique simple: plus la phrase ressemble à du texte, plus c'est plausible
            score = sum(1 for c in decoded.lower() if c in "etaoinshrdlu") / max(len(decoded), 1)
            if score > 0.25:
                candidates.append({
                    "type": f"ROT{shift}",
                    "confidence": f"Plausible (score={score:.2f})",
                    "decoded_preview": decoded[:200],
                })

    # Détection charset brute via chardet
    if s:
        charset = detect_charset(s.encode("latin-1", errors="ignore"))
        candidates.append({
            "type": f"Encodage texte détecté: {charset['encoding']}",
            "confidence": f"{charset['confidence'] * 100:.1f}%",
            "decoded_preview": None,
        })

    # Cas par défaut
    if not candidates:
        candidates.append({
            "type": "Texte en clair / encodage inconnu",
            "confidence": "Faible",
            "decoded_preview": s[:200],
        })

    return candidates


def display_results(text: str, results: List[Dict[str, Any]]):
    section(f"Analyse ENCODEX pour: {text[:60]}{'...' if len(text) > 60 else ''}")
    if console:
        table = Table(title="[bold green]Types d'encodage détectés[/bold green]",
                      show_header=True, header_style="bold cyan", box=box.ROUNDED)
        table.add_column("#", width=4, justify="center")
        table.add_column("Type d'encodage", min_width=25)
        table.add_column("Confiance", min_width=12)
        table.add_column("Aperçu décodé", min_width=40)
        for i, r in enumerate(results, 1):
            preview = r.get("decoded_preview") or "—"
            preview = preview.replace("\n", " ").replace("\r", "")
            table.add_row(str(i), r["type"], str(r["confidence"]), preview[:80])
        console.print(table)
    else:
        for i, r in enumerate(results, 1):
            print(f"{i}. {r['type']} | Confiance: {r['confidence']}")
            if r.get("decoded_preview"):
                print(f"   Aperçu: {r['decoded_preview'][:80]}")


# ---------------------------------------------------------------------------
# MODE FICHIER / BATCH
# ---------------------------------------------------------------------------
def analyze_file(path: str) -> List[Dict[str, Any]]:
    with open(path, "rb") as f:
        raw = f.read()

    # Essayer plusieurs décodages
    candidates = []

    # Détection charset
    charset = detect_charset(raw)
    candidates.append({
        "type": f"Encodage détecté par chardet: {charset['encoding']}",
        "confidence": f"{charset['confidence'] * 100:.1f}%",
        "decoded_preview": raw.decode(charset["encoding"] or "utf-8", errors="replace")[:200],
    })

    # Si c'est du texte hex-like
    try:
        text = raw.decode("utf-8").strip()
        candidates.extend(analyze_text(text))
    except Exception:
        pass

    # Hash-like / entropie basique
    hex_digest = binascii.hexlify(raw[:16]).decode("ascii")
    candidates.append({
        "type": "Aperçu hexadécimal brut",
        "confidence": "Info",
        "decoded_preview": hex_digest,
    })

    return candidates


def batch_analyze(folder: str, output: Optional[str] = None):
    results = {}
    for p in Path(folder).iterdir():
        if p.is_file():
            try:
                results[str(p)] = analyze_file(str(p))
            except Exception as e:
                results[str(p)] = [{"type": "Erreur", "confidence": "—", "decoded_preview": str(e)}]

    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        info(f"Rapport batch sauvegardé: {output}")
    return results


# ---------------------------------------------------------------------------
# MENU INTERACTIF
# ---------------------------------------------------------------------------
def menu():
    print_banner()
    while True:
        if console:
            table = Table(title="[bold green]MENU ENCODEX[/bold green]", box=box.DOUBLE_EDGE)
            table.add_column("Choix", justify="center", style="cyan")
            table.add_column("Action")
            table.add_row("1", "Analyser un texte")
            table.add_row("2", "Analyser un fichier")
            table.add_row("3", "Analyser un dossier (batch)")
            table.add_row("4", "Encoder un texte (Base64 / Hex / URL)")
            table.add_row("5", "Générer un rapport d'exemple")
            table.add_row("0", "Quitter")
            console.print(table)
        else:
            print("\nMENU ENCODEX")
            print("1. Texte  2. Fichier  3. Batch  4. Encoder  0. Quitter")

        choice = input("\nChoix > ").strip()
        if choice == "1":
            text = input("Texte à analyser: ").strip()
            results = analyze_text(text)
            display_results(text, results)
        elif choice == "2":
            path = input("Chemin du fichier: ").strip()
            results = analyze_file(path)
            display_results(path, results)
        elif choice == "3":
            folder = input("Dossier: ").strip()
            out = input("Fichier de sortie JSON (optionnel): ").strip() or None
            batch_analyze(folder, output=out)
        elif choice == "4":
            text = input("Texte à encoder: ").strip()
            if console:
                table = Table(title="Résultats d'encodage", box=box.ROUNDED)
                table.add_column("Type")
                table.add_column("Résultat")
                table.add_row("Base64", base64.b64encode(text.encode()).decode())
                table.add_row("Hex", text.encode().hex())
                table.add_row("URL", " ".join(f"%{b:02X}" for b in text.encode()))
                console.print(table)
            else:
                print("Base64:", base64.b64encode(text.encode()).decode())
                print("Hex:", text.encode().hex())
        elif choice == "5":
            sample = "SGVsbG8gSGFja2VyIFRDSEFESUVO"
            display_results(sample, analyze_text(sample))
        elif choice == "0":
            info("Fermeture ENCODEX.")
            break
        else:
            warn("Choix invalide.")
        input("\nAppuyez sur Entrée pour continuer...")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        prog="encodex.py",
        description=f"{APP_NAME} v{APP_VERSION} — Détecteur de type d'encodage"
    )
    parser.add_argument("--menu", action="store_true", help="Lancer le menu interactif")
    parser.add_argument("--text", help="Texte à analyser")
    parser.add_argument("--file", help="Fichier à analyser")
    parser.add_argument("--batch", help="Dossier à analyser")
    parser.add_argument("--output", help="Fichier JSON de sortie")
    args = parser.parse_args()

    if not any([args.text, args.file, args.batch, args.menu]):
        menu()
        return

    if args.text:
        print_banner()
        display_results(args.text, analyze_text(args.text))
    elif args.file:
        print_banner()
        display_results(args.file, analyze_file(args.file))
    elif args.batch:
        print_banner()
        batch_analyze(args.batch, output=args.output)
    elif args.menu:
        menu()


if __name__ == "__main__":
    main()
