#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                         MD5-AUDITOR v3.0                                     ║
║           Outil éducatif d'audit de hachages MD5 autorisé                    ║
║                                                                              ║
║  Créé par    : HIDDEN-WORLD Communauté Tchadienne                           ║
║  Développeur : GONI (Tchadien Hacker)                                        ║
║  Usage       : Tests de sécurité, apprentissage, audit autorisé uniquement   ║
╚══════════════════════════════════════════════════════════════════════════════╝

AVERTISSEMENT LÉGAL :
Ce script est fourni à des fins éducatives et d'audit de sécurité autorisé.
L'utilisation de cet outil sur des systèmes ou des hachages sans autorisation
explicite est illégale. L'auteur et la communauté HIDDEN-WORLD déclinent toute
responsabilité en cas d'utilisation malveillante.
"""

import hashlib
import itertools
import json
import os
import re
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from colorama import Fore, Style, init
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.tree import Tree
import pyfiglet

# ═══════════════════════════════════════════════════════════════════════════════
# INITIALISATION
# ═══════════════════════════════════════════════════════════════════════════════
init(autoreset=True)
console = Console()

BANNER = f"""
{Fore.CYAN}{pyfiglet.figlet_format("MD5-AUDITOR", font="slant")}{Style.RESET_ALL}
{Fore.YELLOW}  ╔══════════════════════════════════════════════════════════════╗
{Fore.YELLOW}  ║  Outil éducatif d'audit de hachages MD5 autorisé             ║
{Fore.YELLOW}  ║  Créé par HIDDEN-WORLD Communauté Tchadienne                 ║
{Fore.YELLOW}  ║  Développeur : GONI                                          ║
{Fore.YELLOW}  ╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""

# ═══════════════════════════════════════════════════════════════════════════════
# BASE DE DONNÉES DE HACHAGES COMMUNS (RAINBOW TABLE LOCALE ÉDUCATIVE)
# ═══════════════════════════════════════════════════════════════════════════════
COMMON_HASHES = {
    "5f4dcc3b5aa765d61d8327deb882cf99": "password",
    "e99a18c428cb38d5f260853678922e03": "abc123",
    "900150983cd24fb0d6963f7d28e17f72": "abc",
    "827ccb0eea8a706c4c34a16891f84e7b": "12345",
    "25d55ad283aa400af464c76d713c07ad": "12345678",
    "81dc9bdb52d04dc20036dbd8313ed055": "1234",
    "d8578edf8458ce06fbc5bb76a58c5ca4": "qwerty",
    "5ebe2294ecd0e0f08eab7690d2a6ee69": "secret",
    "21232f297a57a5a743894a0e4a801fc3": "admin",
    "098f6bcd4621d373cade4e832627b4f6": "test",
    "c20ad4d76fe97759aa27a0c99bff6710": "admin",
    "202cb962ac59075b964b07152d234b70": "123",
    "86f7e437faa5a7fce15d1ddcb9eaeaea": "a",
    "b026324c6904b2a9cb4b88d6d61c81d1": "111111",
    "4297f44b13955235245b2497399d7a93": "123123",
    "6c569aabbf0a1f5a6ed07f6e3f7e7e58": "letmein",
    "a3f390d88e4c41f2747bfa2f1b5f87db": "monkey",
    "f25a2fc72690b780b2a14e140ef6a9e0": "dragon",
    "7c6a180b36896a0a8c02787eeafb0e4c": "password1",
    "6c569aabbf0a1f5a6ed07f6e3f7e7e58": "master",
    "0d107d09f5bbe40cade3de5c71e9e9b7": "letmein",
    "5f4dcc3b5aa765d61d8327deb882cf99": "password",
    "63a9f0ea7bb98050796b649e85481845": "root",
    "5badcaf789d3d1d09794d8f021af4d0f": "ubuntu",
    "8846f7eaee8fb117ad06bdd830b7586c": "password",
    "3db12f5a7b2026e3c62c1fc34578e40f": "welcome",
    "a17554c58b4803d2c2d04347ff85b024": "shadow",
    "bbed9c062e4bce7e7d4e4f7c5a1e3a54": "sunshine",
    "e10adc3949ba59abbe56e057f20f883e": "123456",
    "25f9e794323b453885f5181f1b624d0b": "123456789",
    "8afa847f50a716e64932d995c8e7435a": "qwerty123",
    "fcea920f7412b5da7be0cf42b8c93759": "1234567",
    "601f1889667efaebb33b8c1257285da3": "iloveyou",
    "f806fc5a2a0d5ba2471600758452799c": "princess",
    "f7c3bc1d808e04732adf679965ccc34ca7ae3441": "football",
    "3rJIhdm0": "unknown",
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLASSE PRINCIPALE
# ═══════════════════════════════════════════════════════════════════════════════
class MD5Auditor:
    def __init__(self):
        self.start_time = None
        self.found = False
        self.result = None
        self.lock = threading.Lock()
        self.attempts = 0
        self.session_file = Path("md5_auditor_session.json")
        self.history = self._load_history()

    def _load_history(self):
        if self.session_file.exists():
            try:
                with open(self.session_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return []
        return []

    def _save_history(self):
        try:
            with open(self.session_file, "w", encoding="utf-8") as f:
                json.dump(self.history[-50:], f, indent=2, ensure_ascii=False)
        except Exception as e:
            console.print(f"[yellow]⚠ Impossible de sauvegarder l'historique : {e}[/yellow]")

    def _is_valid_md5(self, hash_value):
        return bool(re.fullmatch(r"^[a-fA-F0-9]{32}$", hash_value))

    def _md5(self, text):
        return hashlib.md5(text.encode("utf-8")).hexdigest()

    def _log_attempt(self, hash_value, method, plaintext=None, status="running"):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "hash": hash_value,
            "method": method,
            "status": status,
            "plaintext": plaintext,
        }
        self.history.append(entry)
        self._save_history()

    # ═══════════════════════════════════════════════════════════════════════════
    # 1. RECHERCHE DANS RAINBOW TABLE LOCALE
    # ═══════════════════════════════════════════════════════════════════════════
    def rainbow_lookup(self, target_hash):
        console.print(Panel.fit("[cyan]🔍 Recherche dans la rainbow table locale[/cyan]"))
        target = target_hash.lower()
        if target in COMMON_HASHES:
            result = COMMON_HASHES[target]
            console.print(f"[green]✅ TROUVÉ : {result}[/green]")
            self._log_attempt(target_hash, "rainbow_table", result, "cracked")
            return result
        console.print("[red]❌ Non trouvé dans la rainbow table locale.[/red]")
        return None

    # ═══════════════════════════════════════════════════════════════════════════
    # 2. ATTAQUE PAR DICTIONNAIRE
    # ═══════════════════════════════════════════════════════════════════════════
    def dictionary_attack(self, target_hash, wordlist_path=None, threads=4):
        console.print(Panel.fit("[cyan]📖 Attaque par dictionnaire[/cyan]"))
        target = target_hash.lower()

        if not wordlist_path:
            default_paths = [
                "/usr/share/wordlists/rockyou.txt",
                "rockyou.txt",
                "wordlist.txt",
                "passwords.txt",
                "dict.txt",
            ]
            for p in default_paths:
                if Path(p).exists():
                    wordlist_path = p
                    break

        if not wordlist_path or not Path(wordlist_path).exists():
            console.print("[red]❌ Aucun dictionnaire trouvé. Création d'un mini-dictionnaire intégré...[/red]")
            return self._builtin_dictionary_attack(target)

        console.print(f"[blue]📂 Dictionnaire : {wordlist_path}[/blue]")
        console.print(f"[blue]🧵 Threads : {threads}[/blue]")

        self.start_time = time.time()
        self.found = False
        self.result = None
        self.attempts = 0

        def worker(chunk):
            for word in chunk:
                if self.found:
                    return
                word = word.strip()
                with self.lock:
                    self.attempts += 1
                if self._md5(word) == target:
                    with self.lock:
                        self.found = True
                        self.result = word
                    return

        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                words = f.readlines()
        except Exception as e:
            console.print(f"[red]❌ Erreur lecture dictionnaire : {e}[/red]")
            return None

        chunk_size = max(1, len(words) // threads)
        chunks = [words[i:i + chunk_size] for i in range(0, len(words), chunk_size)]

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{Task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
        ) as progress:
            task = progress.add_task("[cyan]Test des mots...", total=len(words))

            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = [executor.submit(worker, chunk) for chunk in chunks]
                while any(not f.done() for f in futures):
                    progress.update(task, completed=min(self.attempts, len(words)))
                    time.sleep(0.1)
                    if self.found:
                        for f in futures:
                            f.cancel()
                        break
                for f in as_completed(futures):
                    pass

        elapsed = time.time() - self.start_time
        if self.result:
            console.print(f"[green]✅ TROUVÉ : {self.result} (en {self.attempts:,} essais, {elapsed:.2f}s)[/green]")
            self._log_attempt(target_hash, f"dictionary ({Path(wordlist_path).name})", self.result, "cracked")
            return self.result
        console.print(f"[red]❌ Non trouvé dans le dictionnaire ({self.attempts:,} essais, {elapsed:.2f}s)[/red]")
        self._log_attempt(target_hash, f"dictionary ({Path(wordlist_path).name})", status="failed")
        return None

    def _builtin_dictionary_attack(self, target):
        builtin = [
            "password", "123456", "12345678", "1234", "qwerty", "12345",
            "dragon", "pussy", "baseball", "football", "letmein", "monkey",
            "696969", "abc123", "mustang", "michael", "shadow", "master",
            "jordan", "superman", "harley", "1234567", "fuckme", "hunter",
            "fuckyou", "trustno1", "ranger", "buster", "thomas", "tigger",
            "robert", "soccer", "fucking", "batman", "test", "pass",
            "killer", "hockey", "george", "sexy", "andrew", "london",
            "coffee", "000000", "qazwsx", "alexis", "696969", "pepper",
            "user", "admin", "root", "ubuntu", "kali", "linux",
            "welcome", "login", "secret", "password123", "admin123",
            "qwerty123", "letmein123", "monkey123", "dragon123", "sunshine",
            "princess", "iloveyou", "baseball", "football", "soccer",
            "hockey", "basketball", "tennis", "golf", "swimming",
        ]
        for word in builtin:
            if self._md5(word) == target:
                console.print(f"[green]✅ TROUVÉ (dictionnaire intégré) : {word}[/green]")
                self._log_attempt(target, "builtin_dictionary", word, "cracked")
                return word
        console.print("[red]❌ Non trouvé dans le dictionnaire intégré.[/red]")
        return None

    # ═══════════════════════════════════════════════════════════════════════════
    # 3. ATTAQUE PAR FORCE BRUTE
    # ═══════════════════════════════════════════════════════════════════════════
    def brute_force_attack(self, target_hash, min_len=1, max_len=6, charset=None, threads=4):
        console.print(Panel.fit("[cyan]💥 Attaque par force brute[/cyan]"))
        target = target_hash.lower()

        if not charset:
            charset = string.ascii_lowercase + string.digits

        console.print(f"[blue]🔤 Charset : {charset}[/blue]")
        console.print(f"[blue]📏 Longueur : {min_len}-{max_len}[/blue]")
        console.print(f"[blue]🧵 Threads : {threads}[/blue]")

        self.start_time = time.time()
        self.found = False
        self.result = None
        self.attempts = 0

        def worker(length):
            if self.found:
                return
            for combo in itertools.product(charset, repeat=length):
                if self.found:
                    return
                candidate = "".join(combo)
                with self.lock:
                    self.attempts += 1
                if self._md5(candidate) == target:
                    with self.lock:
                        self.found = True
                        self.result = candidate
                    return

        total_combinations = sum(len(charset) ** length for length in range(min_len, max_len + 1))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{Task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
        ) as progress:
            task = progress.add_task("[cyan]Brute force...", total=total_combinations)

            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = [executor.submit(worker, length) for length in range(min_len, max_len + 1)]
                while any(not f.done() for f in futures):
                    progress.update(task, completed=min(self.attempts, total_combinations))
                    time.sleep(0.05)
                    if self.found:
                        for f in futures:
                            f.cancel()
                        break
                for f in as_completed(futures):
                    pass

        elapsed = time.time() - self.start_time
        if self.result:
            console.print(f"[green]✅ TROUVÉ : {self.result} (en {self.attempts:,} essais, {elapsed:.2f}s)[/green]")
            self._log_attempt(target_hash, "brute_force", self.result, "cracked")
            return self.result
        console.print(f"[red]❌ Non trouvé par force brute ({self.attempts:,} essais, {elapsed:.2f}s)[/red]")
        self._log_attempt(target_hash, "brute_force", status="failed")
        return None

    # ═══════════════════════════════════════════════════════════════════════════
    # 4. HYBRIDE : DICTIONNAIRE + RÈGLES DE MUTATION
    # ═══════════════════════════════════════════════════════════════════════════
    def hybrid_attack(self, target_hash, wordlist_path=None, threads=4):
        console.print(Panel.fit("[cyan]🔧 Attaque hybride (dictionnaire + mutations)[/cyan]"))
        target = target_hash.lower()

        if not wordlist_path or not Path(wordlist_path).exists():
            console.print("[yellow]⚠ Aucun dictionnaire fourni, utilisation du dictionnaire intégré.[/yellow]")
            base_words = ["password", "admin", "user", "login", "welcome", "secret", "123456"]
        else:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                base_words = [w.strip() for w in f if w.strip()]

        mutations = self._generate_mutations(base_words)
        console.print(f"[blue]🧬 Mutations générées : {len(mutations):,}[/blue]")

        self.start_time = time.time()
        self.found = False
        self.result = None
        self.attempts = 0

        def worker(chunk):
            for word in chunk:
                if self.found:
                    return
                with self.lock:
                    self.attempts += 1
                if self._md5(word) == target:
                    with self.lock:
                        self.found = True
                        self.result = word
                    return

        chunk_size = max(1, len(mutations) // threads)
        chunks = [mutations[i:i + chunk_size] for i in range(0, len(mutations), chunk_size)]

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{Task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
        ) as progress:
            task = progress.add_task("[cyan]Test des mutations...", total=len(mutations))
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = [executor.submit(worker, chunk) for chunk in chunks]
                while any(not f.done() for f in futures):
                    progress.update(task, completed=min(self.attempts, len(mutations)))
                    time.sleep(0.05)
                    if self.found:
                        for f in futures:
                            f.cancel()
                        break
                for f in as_completed(futures):
                    pass

        elapsed = time.time() - self.start_time
        if self.result:
            console.print(f"[green]✅ TROUVÉ : {self.result} (en {self.attempts:,} essais, {elapsed:.2f}s)[/green]")
            self._log_attempt(target_hash, "hybrid", self.result, "cracked")
            return self.result
        console.print(f"[red]❌ Non trouvé par attaque hybride ({self.attempts:,} essais, {elapsed:.2f}s)[/red]")
        self._log_attempt(target_hash, "hybrid", status="failed")
        return None

    def _generate_mutations(self, base_words):
        mutations = set()
        suffixes = ["", "1", "12", "123", "1234", "12345", "123456", "!", "@", "#", "2023", "2024", "2025"]
        for word in base_words:
            mutations.add(word)
            mutations.add(word.lower())
            mutations.add(word.upper())
            mutations.add(word.capitalize())
            mutations.add(word[::-1])
            for suffix in suffixes:
                mutations.add(word + suffix)
                mutations.add(word.capitalize() + suffix)
                mutations.add(word.upper() + suffix)
        return list(mutations)

    # ═══════════════════════════════════════════════════════════════════════════
    # 5. ANALYSE ET IDENTIFICATION DE HACHAGE
    # ═══════════════════════════════════════════════════════════════════════════
    def identify_hash(self, hash_value):
        console.print(Panel.fit("[cyan]🔬 Identification du hachage[/cyan]"))
        patterns = [
            (r"^[a-f0-9]{32}$", "MD5"),
            (r"^[a-f0-9]{40}$", "SHA-1"),
            (r"^[a-f0-9]{64}$", "SHA-256"),
            (r"^[a-f0-9]{128}$", "SHA-512"),
            (r"^\$2[aby]?\$\d{2}\$[./0-9A-Za-z]{53}$", "bcrypt"),
            (r"^\$argon2", "Argon2"),
            (r"^[0-9a-f]{32}:[0-9a-zA-Z]{16}$", "MD5 (salty)"),
        ]
        found = False
        for pattern, name in patterns:
            if re.match(pattern, hash_value, re.IGNORECASE):
                console.print(f"[green]✅ Type détecté : {name}[/green]")
                found = True
                break
        if not found:
            console.print("[yellow]⚠ Type de hachage non identifié ou non supporté.[/yellow]")
        return found

    # ═══════════════════════════════════════════════════════════════════════════
    # 6. COMPARAISON MD5 D'UN FICHIER
    # ═══════════════════════════════════════════════════════════════════════════
    def hash_file(self, file_path):
        console.print(Panel.fit("[cyan]📁 Hachage MD5 d'un fichier[/cyan]"))
        try:
            h = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            digest = h.hexdigest()
            console.print(f"[green]✅ MD5 : {digest}[/green]")
            return digest
        except Exception as e:
            console.print(f"[red]❌ Erreur : {e}[/red]")
            return None

    # ═══════════════════════════════════════════════════════════════════════════
    # 7. MODE TOUT-AUTO
    # ═══════════════════════════════════════════════════════════════════════════
    def auto_crack(self, target_hash, wordlist_path=None, max_brute_len=4, threads=4):
        console.print(Panel.fit("[cyan]🤖 Mode automatique complet[/cyan]"))
        if not self._is_valid_md5(target_hash):
            console.print("[red]❌ Hachage MD5 invalide.[/red]")
            return None

        methods = [
            ("Rainbow table", lambda: self.rainbow_lookup(target_hash)),
            ("Dictionnaire intégré", lambda: self._builtin_dictionary_attack(target_hash)),
            ("Dictionnaire fichier", lambda: self.dictionary_attack(target_hash, wordlist_path, threads)),
            ("Attaque hybride", lambda: self.hybrid_attack(target_hash, wordlist_path, threads)),
            ("Force brute", lambda: self.brute_force_attack(target_hash, 1, max_brute_len, string.ascii_lowercase + string.digits, threads)),
        ]

        for name, method in methods:
            if self.result:
                break
            console.print(f"\n[magenta]▶ Tentative : {name}[/magenta]")
            result = method()
            if result:
                console.print(Panel.fit(f"[bold green]🎉 MOT DE PASSE TROUVÉ : {result}[/bold green]"))
                return result

        console.print(Panel.fit("[bold red]💔 Échec : hachage non cassé avec les méthodes disponibles.[/bold red]"))
        return None

    # ═══════════════════════════════════════════════════════════════════════════
    # 8. HISTORIQUE
    # ═══════════════════════════════════════════════════════════════════════════
    def show_history(self):
        console.print(Panel.fit("[cyan]📜 Historique des audits[/cyan]"))
        if not self.history:
            console.print("[yellow]Aucun historique.[/yellow]")
            return
        table = Table(title="Dernières opérations")
        table.add_column("Date", style="cyan")
        table.add_column("Hash", style="magenta")
        table.add_column("Méthode", style="green")
        table.add_column("Résultat", style="yellow")
        for entry in self.history[-20:]:
            result = entry.get("plaintext") or entry.get("status", "-")
            table.add_row(
                entry.get("timestamp", "-")[:19],
                entry.get("hash", "-")[:16] + "...",
                entry.get("method", "-"),
                result,
            )
        console.print(table)

    # ═══════════════════════════════════════════════════════════════════════════
    # 9. GÉNÉRATEUR DE HASHES POUR TESTS
    # ═══════════════════════════════════════════════════════════════════════════
    def generate_test_hashes(self, words):
        console.print(Panel.fit("[cyan]🧪 Génération de hachages MD5 de test[/cyan]"))
        table = Table(title="Hachages de test")
        table.add_column("Texte", style="cyan")
        table.add_column("MD5", style="magenta")
        for word in words:
            table.add_row(word, self._md5(word))
        console.print(table)


# ═══════════════════════════════════════════════════════════════════════════════
# MENU INTERACTIF
# ═══════════════════════════════════════════════════════════════════════════════
def print_menu():
    menu_tree = Tree("[bold cyan]MENU PRINCIPAL MD5-AUDITOR[/bold cyan]")
    menu_tree.add("[1] 🔍 Recherche dans rainbow table")
    menu_tree.add("[2] 📖 Attaque par dictionnaire")
    menu_tree.add("[3] 💥 Attaque par force brute")
    menu_tree.add("[4] 🔧 Attaque hybride (mutations)")
    menu_tree.add("[5] 🤖 Mode automatique complet")
    menu_tree.add("[6] 🔬 Identifier un type de hachage")
    menu_tree.add("[7] 📁 Calculer MD5 d'un fichier")
    menu_tree.add("[8] 🧪 Générer des hachages de test")
    menu_tree.add("[9] 📜 Voir l'historique")
    menu_tree.add("[0] ❌ Quitter")
    console.print(menu_tree)


def main():
    auditor = MD5Auditor()
    print(BANNER)
    console.print(Panel.fit(
        "[bold red]⚠ ÉDUCATIF / AUDIT AUTORISÉ UNIQUEMENT ⚠[/bold red]\n"
        "L'utilisation non autorisée est illégale.\n"
        "Créé par HIDDEN-WORLD Communauté Tchadienne - GONI",
        title="AVERTISSEMENT",
        border_style="red"
    ))

    while True:
        print_menu()
        choice = console.input("\n[bold yellow]➤ Choix : [/bold yellow]").strip()

        if choice == "0":
            console.print("[green]👋 Au revoir ! Restez éthiques.[/green]")
            sys.exit(0)

        elif choice == "1":
            h = console.input("[cyan]Hash MD5 : [/cyan]").strip()
            if auditor._is_valid_md5(h):
                auditor.rainbow_lookup(h)
            else:
                console.print("[red]Hash invalide.[/red]")

        elif choice == "2":
            h = console.input("[cyan]Hash MD5 : [/cyan]").strip()
            path = console.input("[cyan]Chemin du dictionnaire (Entrée = auto) : [/cyan]").strip() or None
            threads = console.input("[cyan]Threads (défaut 4) : [/cyan]").strip() or "4"
            if auditor._is_valid_md5(h):
                auditor.dictionary_attack(h, path, int(threads))
            else:
                console.print("[red]Hash invalide.[/red]")

        elif choice == "3":
            h = console.input("[cyan]Hash MD5 : [/cyan]").strip()
            min_len = int(console.input("[cyan]Longueur minimale (défaut 1) : [/cyan]").strip() or "1")
            max_len = int(console.input("[cyan]Longueur maximale (défaut 4) : [/cyan]").strip() or "4")
            threads = int(console.input("[cyan]Threads (défaut 4) : [/cyan]").strip() or "4")
            charset_choice = console.input("[cyan]Charset : [1] minuscules+digits [2] ascii+digits [3] tous caractères (défaut 1) : [/cyan]").strip() or "1"
            if charset_choice == "2":
                charset = string.ascii_letters + string.digits
            elif charset_choice == "3":
                charset = string.printable.strip()
            else:
                charset = string.ascii_lowercase + string.digits
            if auditor._is_valid_md5(h):
                auditor.brute_force_attack(h, min_len, max_len, charset, threads)
            else:
                console.print("[red]Hash invalide.[/red]")

        elif choice == "4":
            h = console.input("[cyan]Hash MD5 : [/cyan]").strip()
            path = console.input("[cyan]Chemin du dictionnaire (Entrée = intégré) : [/cyan]").strip() or None
            threads = int(console.input("[cyan]Threads (défaut 4) : [/cyan]").strip() or "4")
            if auditor._is_valid_md5(h):
                auditor.hybrid_attack(h, path, threads)
            else:
                console.print("[red]Hash invalide.[/red]")

        elif choice == "5":
            h = console.input("[cyan]Hash MD5 : [/cyan]").strip()
            path = console.input("[cyan]Chemin du dictionnaire (Entrée = auto) : [/cyan]").strip() or None
            max_brute = int(console.input("[cyan]Longueur max brute force (défaut 4) : [/cyan]").strip() or "4")
            threads = int(console.input("[cyan]Threads (défaut 4) : [/cyan]").strip() or "4")
            if auditor._is_valid_md5(h):
                auditor.auto_crack(h, path, max_brute, threads)
            else:
                console.print("[red]Hash invalide.[/red]")

        elif choice == "6":
            h = console.input("[cyan]Hash à identifier : [/cyan]").strip()
            auditor.identify_hash(h)

        elif choice == "7":
            path = console.input("[cyan]Chemin du fichier : [/cyan]").strip()
            auditor.hash_file(path)

        elif choice == "8":
            words = console.input("[cyan]Mots séparés par des virgules : [/cyan]").strip().split(",")
            auditor.generate_test_hashes([w.strip() for w in words if w.strip()])

        elif choice == "9":
            auditor.show_history()

        else:
            console.print("[red]Choix invalide.[/red]")

        console.input("\n[dim]Appuyez sur Entrée pour continuer...[/dim]")
        os.system("cls" if os.name == "nt" else "clear")


if __name__ == "__main__":
    main()
