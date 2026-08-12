#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ENCODEX v3.0 — Détecteur universel de type d'encodage, de hachage et de format.
Créé par la communauté Hacker Tchadien / Hidden World.

Détecte : Hex, Base16/32/64/85/91/58, Binaire, URL, HTML, Unicode, JSON,
Morse, ROT, JWT, UUID, Hash, Chaîne encodée (chardet), etc.
"""

import os
import re
import sys
import json
import math
import base64
import base58
import base91
import binascii
import argparse
import datetime
import html
import string
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional
from urllib.parse import unquote
from collections import Counter

import chardet
import z85


try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.tree import Tree
    from rich.progress import track
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
APP_NAME = "ENCODEX"
APP_VERSION = "3.0.0"
APP_AUTHOR = "Hacker Tchadien — Hidden World"

console = Console() if RICH_AVAILABLE else None


def info(msg: str):
    (console.print(f"[bold green][+][/bold green] {msg}") if console else print(f"[+] {msg}"))


def warn(msg: str):
    (console.print(f"[bold yellow][!][/bold yellow] {msg}") if console else print(f"[!] {msg}"))


def error(msg: str):
    (console.print(f"[bold red][x][/bold red] {msg}") if console else print(f"[x] {msg}"))


def section(title: str):
    (console.print(Panel(f"[bold bright_cyan]{title}[/bold bright_cyan]", border_style="cyan"))
     if console else print(f"\n=== {title} ===\n"))


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
 ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝
    """
    if console:
        console.print(Panel.fit(
            f"[bold cyan]{banner}[/bold cyan]\n"
            f"[bold green]Détecteur de type d'encodage — v{APP_VERSION}[/bold green]\n"
            f"[dim]Auteur: {APP_AUTHOR}[/dim]",
            title=f"[bold]{APP_NAME}[/bold]",
            border_style="green", box=box.DOUBLE))
    else:
        print(banner)
        print(f"ENCODEX v{APP_VERSION} — {APP_AUTHOR}\n")


# ---------------------------------------------------------------------------
# UTILITAIRES GÉNÉRAUX
# ---------------------------------------------------------------------------
def clean(s: str) -> str:
    """Supprime les espaces de présentation."""
    return re.sub(r"[\s\-]+", "", s).strip()


def printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(1 for c in s if c.isprintable()) / len(s)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def entropy_score(data: bytes) -> str:
    e = shannon_entropy(data)
    if e < 3.5:
        return "Très faible (texte clair probable)"
    if e < 5.0:
        return "Faible (structure faible)"
    if e < 7.0:
        return "Moyenne (encodage/hachage possible)"
    return "Élevée (hachage / chiffrement probable)"


# ---------------------------------------------------------------------------
# HEURISTIQUES DE FORMAT
# ---------------------------------------------------------------------------
def is_hex(s: str) -> bool:
    s = clean(s)
    return bool(re.fullmatch(r"[0-9a-fA-F]+", s)) and len(s) >= 2 and len(s) % 2 == 0


def is_base64(s: str) -> bool:
    s = clean(s)
    return bool(re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s)) and len(s) >= 4 and len(s) % 4 == 0


def is_base64url(s: str) -> bool:
    s = clean(s)
    return bool(re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", s)) and len(s) >= 4 and len(s) % 4 == 0 and "_" in s or "-" in s


def is_base32(s: str) -> bool:
    s = clean(s)
    return bool(re.fullmatch(r"[A-Z2-7]+={0,6}", s)) and len(s) >= 8 and len(s) % 8 == 0


def is_base58(s: str) -> bool:
    alphabet = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
    s = clean(s)
    return len(s) >= 4 and all(c in alphabet for c in s)


def is_base85(s: str) -> bool:
    s = clean(s)
    return s.startswith("<~") and s.endswith("~>") and len(s) > 4


def is_base91(s: str) -> bool:
    alphabet = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~'")
    s = clean(s)
    return len(s) >= 4 and all(c in alphabet for c in s)


def is_z85(s: str) -> bool:
    alphabet = set("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#")
    s = clean(s)
    return len(s) >= 5 and len(s) % 5 == 0 and all(c in alphabet for c in s)


def is_binary(s: str) -> bool:
    s = clean(s)
    return bool(re.fullmatch(r"[01]+", s)) and len(s) >= 8 and len(s) % 8 == 0


def is_url_encoded(s: str) -> bool:
    return "%" in s and bool(re.search(r"%[0-9a-fA-F]{2}", s))


def is_html_entities(s: str) -> bool:
    return bool(re.search(r"&(?:#[0-9]+|#x[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*);", s))


def is_unicode_escape(s: str) -> bool:
    return bool(re.search(r"(\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}|\\x[0-9a-fA-F]{2})", s))


def is_json_escape(s: str) -> bool:
    return bool(re.search(r"(\\n|\\t|\\r|\\\\|\\\"|\\b|\\f)", s))


def is_morse(s: str) -> bool:
    s = s.strip()
    return bool(re.fullmatch(r"[\.\-/\s]+", s)) and ("-" in s or "." in s)


def is_rot_candidate(s: str) -> bool:
    return any(c.isalpha() for c in s) and len(s) >= 3


def is_jwt(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 3 and all(is_base64url(p) for p in parts)


def is_uuid(s: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", s))


def is_hash(s: str) -> Tuple[bool, str]:
    s = clean(s)
    lengths = {
        32: "MD5",
        40: "SHA-1",
        56: "SHA-224 / SHA3-224",
        64: "SHA-256 / SHA3-256 / BLAKE2s",
        96: "SHA-384 / SHA3-384",
        128: "SHA-512 / SHA3-512 / BLAKE2b",
    }
    if not bool(re.fullmatch(r"[0-9a-fA-F]+", s)):
        return False, ""
    return (True, lengths.get(len(s), "Hash hexadécimal de taille inhabituelle")) if len(s) in lengths else (False, "")


# ---------------------------------------------------------------------------
# DÉCODEURS
# ---------------------------------------------------------------------------
def try_decode_hex(s: str) -> Optional[str]:
    try:
        return bytes.fromhex(clean(s)).decode("utf-8", errors="replace")
    except Exception:
        return None


def try_decode_base64(s: str) -> Optional[str]:
    try:
        return base64.b64decode(clean(s), validate=True).decode("utf-8", errors="replace")
    except Exception:
        return None


def try_decode_base64url(s: str) -> Optional[str]:
    try:
        return base64.urlsafe_b64decode(clean(s) + "=" * (-len(clean(s)) % 4)).decode("utf-8", errors="replace")
    except Exception:
        return None


def try_decode_base32(s: str) -> Optional[str]:
    try:
        return base64.b32decode(clean(s), casefold=True).decode("utf-8", errors="replace")
    except Exception:
        return None


def try_decode_base58(s: str) -> Optional[str]:
    try:
        return base58.b58decode(clean(s)).decode("utf-8", errors="replace")
    except Exception:
        return None


def try_decode_base85(s: str) -> Optional[str]:
    try:
        return base64.b85decode(clean(s)).decode("utf-8", errors="replace")
    except Exception:
        return None


def try_decode_base91(s: str) -> Optional[str]:
    try:
        return base91.decode(clean(s).encode()).decode("utf-8", errors="replace")
    except Exception:
        return None


def try_decode_z85(s: str) -> Optional[str]:
    try:
        return z85.decode(clean(s).encode()).decode("utf-8", errors="replace")
    except Exception:
        return None


def try_decode_binary(s: str) -> Optional[str]:
    try:
        bits = clean(s)
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


def try_decode_html(s: str) -> Optional[str]:
    try:
        decoded = html.unescape(s)
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
    return " ".join(out) if out else None


def decode_jwt_payload(s: str) -> Optional[Dict[str, Any]]:
    try:
        parts = s.split(".")
        payload = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        return json.loads(payload.decode("utf-8", errors="replace"))
    except Exception:
        return None


def decode_unicode_escape(s: str) -> Optional[str]:
    try:
        return s.encode("utf-8").decode("unicode_escape")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# SCORING DE CONFIANCE
# ---------------------------------------------------------------------------
def score_decoded(text: str) -> float:
    """Score entre 0 et 1 reflétant la probabilité que le texte décodé soit du texte lisible."""
    if not text:
        return 0.0
    ratio = printable_ratio(text)
    if ratio < 0.7:
        return ratio
    common = sum(1 for c in text.lower() if c in "etaoinshrdlu ")
    common_score = common / max(len(text), 1)
    return min(1.0, 0.5 * ratio + 0.5 * common_score)


def confidence_label(score: float) -> str:
    if score >= 0.85:
        return "Très haute"
    if score >= 0.65:
        return "Haute"
    if score >= 0.45:
        return "Moyenne"
    if score >= 0.25:
        return "Faible"
    return "Très faible"


# ---------------------------------------------------------------------------
# ANALYSE PRINCIPALE
# ---------------------------------------------------------------------------
def analyze_text(s: str) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    original = s

    def add(label: str, decoded: Optional[str], extra: Optional[Dict[str, Any]] = None):
        score = score_decoded(decoded) if decoded else 0.0
        entry = {
            "type": label,
            "confidence": confidence_label(score),
            "score": round(score, 3),
            "decoded_preview": decoded[:200] if decoded else None,
        }
        if extra:
            entry.update(extra)
        candidates.append(entry)

    # Hash
    is_h, h_type = is_hash(s)
    if is_h:
        add(f"Hash probable : {h_type}", None, {"note": "Les hachages ne sont pas réversibles.", "entropy": "Élevée"})

    # UUID
    if is_uuid(s):
        add("UUID v4 (ou autre version)", None, {"note": "Identifiant universel unique.", "entropy": "Élevée"})

    # JWT
    if is_jwt(s):
        payload = decode_jwt_payload(s)
        add("JSON Web Token (JWT)", json.dumps(payload, indent=2, ensure_ascii=False) if payload else None,
            {"note": "Structure header.payload.signature", "entropy": "Élevée"})

    # Hexadécimal
    if is_hex(s):
        decoded = try_decode_hex(s)
        add("Hexadécimal (Base16)", decoded)

    # Binaire
    if is_binary(s):
        decoded = try_decode_binary(s)
        add("Binaire (Base2)", decoded)

    # Base64 URL-safe
    if is_base64url(s) and not is_jwt(s):
        decoded = try_decode_base64url(s)
        add("Base64 URL-safe (RFC 4648 §5)", decoded)

    # Base64 standard
    if is_base64(s):
        decoded = try_decode_base64(s)
        add("Base64 (RFC 4648 §4)", decoded)

    # Base32
    if is_base32(s):
        decoded = try_decode_base32(s)
        add("Base32 (RFC 4648 §6)", decoded)

    # Base58
    if is_base58(s):
        decoded = try_decode_base58(s)
        add("Base58 (Bitcoin)", decoded)

    # Base85 / Ascii85
    if is_base85(s):
        decoded = try_decode_base85(s)
        add("Base85 / Ascii85", decoded)

    # Z85
    if is_z85(s):
        decoded = try_decode_z85(s)
        add("Z85 (ZeroMQ)", decoded)

    # Base91
    if is_base91(s):
        decoded = try_decode_base91(s)
        add("Base91", decoded)

    # URL encoded
    if is_url_encoded(s):
        decoded = try_decode_url(s)
        add("URL Encoded (Percent-encoding RFC 3986)", decoded)

    # HTML entities
    if is_html_entities(s):
        decoded = try_decode_html(s)
        add("HTML Entities", decoded)

    # Unicode escapes
    if is_unicode_escape(s):
        decoded = decode_unicode_escape(s)
        add("Séquences d'échappement Unicode", decoded)

    # JSON escapes
    if is_json_escape(s):
        add("Séquences d'échappement JSON", s.encode().decode("unicode_escape"))

    # Morse
    if is_morse(s):
        add("Code Morse", morse_to_text(s))

    # ROT
    if is_rot_candidate(s):
        for shift, decoded in rot_all(s):
            sc = score_decoded(decoded)
            if sc > 0.35:
                add(f"ROT{shift}", decoded, {"score": round(sc, 3), "confidence": confidence_label(sc)})

    # Encodage texte via chardet
    if s:
        charset = detect_charset(s.encode("latin-1", errors="ignore"))
        add(f"Encodage texte détecté : {charset['encoding']}", None,
            {"confidence": f"{charset['confidence'] * 100:.1f}%", "language": charset.get("language", "inconnu")})

    # Divers
    if not candidates:
        add("Texte en clair / encodage non reconnu", s,
            {"note": "Aucune structure identifiée. Essayez de nettoyer les espaces."})

    # Trier par score décroissant
    candidates.sort(key=lambda x: x.get("score", 0), reverse=True)
    return candidates


def detect_charset(data: bytes) -> Dict[str, Any]:
    result = chardet.detect(data)
    return {
        "encoding": result.get("encoding", "inconnu"),
        "confidence": round(result.get("confidence", 0.0), 4),
        "language": result.get("language", "inconnu"),
    }


# ---------------------------------------------------------------------------
# ANALYSE DE FICHIER
# ---------------------------------------------------------------------------
def hex_dump(data: bytes, length: int = 16) -> str:
    lines = []
    for i in range(0, len(data), length):
        chunk = data[i:i + length]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hex_part:<{length * 3}} {ascii_part}")
    return "\n".join(lines[:20])


def analyze_file(path: str) -> Dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {"error": "Fichier introuvable"}
    raw = p.read_bytes()
    report = {
        "path": str(p),
        "size": len(raw),
        "entropy": round(shannon_entropy(raw), 4),
        "entropy_label": entropy_score(raw),
        "hex_preview": hex_dump(raw[:256]),
    }
    try:
        text = raw.decode("utf-8").strip()
        report["text_analysis"] = analyze_text(text)
    except Exception:
        report["text_analysis"] = []

    charset = detect_charset(raw)
    report["charset"] = charset
    return report


def batch_analyze(folder: str, output: Optional[str] = None) -> Dict[str, Any]:
    results = {}
    files = [p for p in Path(folder).iterdir() if p.is_file()]
    iterable = track(files, description="Analyse batch", console=console) if RICH_AVAILABLE else files
    for p in iterable:
        try:
            results[str(p)] = analyze_file(str(p))
        except Exception as e:
            results[str(p)] = {"error": str(e)}
    if output:
        Path(output).write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
        info(f"Rapport batch sauvegardé : {output}")
    return results


# ---------------------------------------------------------------------------
# AFFICHAGE
# ---------------------------------------------------------------------------
def display_results(text: str, results: List[Dict[str, Any]]):
    section(f"Analyse pour : {text[:70]}{'...' if len(text) > 70 else ''}")
    if console:
        table = Table(title="[bold green]Résultats ENCODEX[/bold green]",
                      show_header=True, header_style="bold cyan", box=box.ROUNDED)
        table.add_column("#", width=4, justify="center")
        table.add_column("Type d'encodage", min_width=30)
        table.add_column("Confiance", min_width=12)
        table.add_column("Score", min_width=8)
        table.add_column("Aperçu décodé", min_width=50)
        for i, r in enumerate(results, 1):
            preview = r.get("decoded_preview") or r.get("note") or "—"
            preview = str(preview).replace("\n", " ").replace("\r", "")[:90]
            table.add_row(str(i), r["type"], r["confidence"], str(r.get("score", "—")), preview)
        console.print(table)
    else:
        for i, r in enumerate(results, 1):
            print(f"{i}. {r['type']} | Confiance: {r['confidence']} | Score: {r.get('score', '—')}")
            if r.get("decoded_preview"):
                print(f"   Aperçu: {r['decoded_preview'][:80]}")


def display_file_report(path: str, report: Dict[str, Any]):
    section(f"Rapport fichier : {path}")
    if console:
        table = Table(title="[bold green]Métadonnées[/bold green]", box=box.ROUNDED)
        table.add_column("Propriété", style="cyan")
        table.add_column("Valeur", style="green")
        table.add_row("Taille", f"{report['size']} octets")
        table.add_row("Entropie", f"{report['entropy']} — {report['entropy_label']}")
        table.add_row("Charset détecté", f"{report['charset']['encoding']} ({report['charset']['confidence'] * 100:.1f}%)")
        console.print(table)
        console.print("\n[bold cyan]Aperçu hexadécimal :[/bold cyan]")
        console.print(Panel(report["hex_preview"], border_style="dim"))
    else:
        print(f"Taille : {report['size']} octets")
        print(f"Entropie : {report['entropy']} — {report['entropy_label']}")
        print(f"Charset : {report['charset']['encoding']}")
        print(report["hex_preview"])
    if report.get("text_analysis"):
        display_results("contenu texte", report["text_analysis"])


# ---------------------------------------------------------------------------
# ENCODEUR / OUTILS
# ---------------------------------------------------------------------------
def encode_text(text: str) -> Dict[str, str]:
    b = text.encode("utf-8")
    return {
        "Base64": base64.b64encode(b).decode(),
        "Base64 URL-safe": base64.urlsafe_b64encode(b).decode().rstrip("="),
        "Base32": base64.b32encode(b).decode(),
        "Base58": base58.b58encode(b).decode(),
        "Base85": base64.b85encode(b).decode(),
        "Base91": base91.encode(b).decode(),
        "Z85": z85.encode(b).decode(),
        "Hex": b.hex(),
        "Binaire": " ".join(f"{byte:08b}" for byte in b),
        "URL": "".join(f"%{byte:02X}" for byte in b),
        "HTML Entities": "".join(f"&#{ord(c)};" for c in text),
        "Unicode Escape": text.encode("unicode_escape").decode(),
    }


def show_encoded(text: str):
    section(f"Encodages de : {text[:60]}{'...' if len(text) > 60 else ''}")
    enc = encode_text(text)
    if console:
        table = Table(title="[bold green]Résultats d'encodage[/bold green]", box=box.ROUNDED)
        table.add_column("Type", style="cyan", min_width=20)
        table.add_column("Résultat", style="green", min_width=60)
        for k, v in enc.items():
            table.add_row(k, v[:120])
        console.print(table)
    else:
        for k, v in enc.items():
            print(f"{k}: {v}")


# ---------------------------------------------------------------------------
# MENU INTERACTIF
# ---------------------------------------------------------------------------
def menu():
    print_banner()
    while True:
        if console:
            table = Table(title=f"[bold green]{APP_NAME} v{APP_VERSION} — Menu[/bold green]", box=box.DOUBLE_EDGE)
            table.add_column("Choix", justify="center", style="cyan")
            table.add_column("Action")
            table.add_row("1", "Analyser un texte")
            table.add_row("2", "Analyser un fichier")
            table.add_row("3", "Analyser un dossier (batch)")
            table.add_row("4", "Encoder un texte")
            table.add_row("5", "Calculer l'entropie d'un texte")
            table.add_row("6", "Exemples de détection")
            table.add_row("0", "Quitter")
            console.print(table)
        else:
            print("\nMENU")
            print("1. Texte  2. Fichier  3. Batch  4. Encoder  5. Entropie  6. Exemples  0. Quitter")

        choice = input("\nChoix > ").strip()
        if choice == "1":
            text = input("Texte à analyser : ").strip()
            display_results(text, analyze_text(text))
        elif choice == "2":
            path = input("Chemin du fichier : ").strip()
            if Path(path).exists():
                display_file_report(path, analyze_file(path))
            else:
                error("Fichier introuvable.")
        elif choice == "3":
            folder = input("Dossier : ").strip()
            out = input("Fichier JSON de sortie (optionnel) : ").strip() or None
            batch_analyze(folder, output=out)
        elif choice == "4":
            text = input("Texte à encoder : ").strip()
            show_encoded(text)
        elif choice == "5":
            text = input("Texte : ").strip()
            data = text.encode("utf-8")
            info(f"Entropie Shannon : {shannon_entropy(data):.4f} bits/octet — {entropy_score(data)}")
        elif choice == "6":
            samples = [
                "SGVsbG8gSGFja2VyIFRDSEFESUVO",
                "48656c6c6f20576f726c64",
                "01001000 01100101 01101100 01101100 01101111",
                "Hello%20World%21",
                "&lt;script&gt;alert(1)&lt;/script&gt;",
                "U2FsdXRs",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            ]
            for s in samples:
                display_results(s, analyze_text(s))
                if console:
                    console.print("\n")
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
        description=f"{APP_NAME} v{APP_VERSION} — Détecteur avancé de type d'encodage"
    )
    parser.add_argument("--menu", action="store_true", help="Lancer le menu interactif")
    parser.add_argument("--text", help="Texte à analyser")
    parser.add_argument("--file", help="Fichier à analyser")
    parser.add_argument("--batch", help="Dossier à analyser")
    parser.add_argument("--output", help="Fichier JSON de sortie")
    parser.add_argument("--encode", help="Texte à encoder")
    parser.add_argument("--entropy", help="Texte dont on calcule l'entropie")
    args = parser.parse_args()

    if args.encode:
        print_banner()
        show_encoded(args.encode)
        return

    if args.entropy:
        print_banner()
        data = args.entropy.encode("utf-8")
        info(f"Entropie : {shannon_entropy(data):.4f} bits/octet — {entropy_score(data)}")
        return

    if args.text:
        print_banner()
        display_results(args.text, analyze_text(args.text))
        return

    if args.file:
        print_banner()
        display_file_report(args.file, analyze_file(args.file))
        return

    if args.batch:
        print_banner()
        batch_analyze(args.batch, output=args.output)
        return

    menu()


if __name__ == "__main__":
    main()
