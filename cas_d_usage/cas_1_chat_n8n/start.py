#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
start.py — demarre le cas d'usage « chat n8n » : serveur MCP au choix,
service de journalisation, et n8n.

Ce script vit dans  cas_d_usage/cas_1_chat_n8n/  et ne deplace aucun fichier.
Il remonte l'arborescence pour trouver  serveur_mcp/  et propose TOUTES les
versions qui s'y trouvent, de la v1-0 a la v3.

Les versions recentes (v2-2, v3) ont un transport HTTP natif. Les plus
anciennes ne parlent que stdio : elles sont alors servies par un PONT
stdio <-> HTTP integre a ce script, qui expose les memes routes. n8n voit donc
la meme interface quelle que soit la version choisie, et AUCUN fichier de
serveur n'est modifie.

    uv run --no-project start.py                # menu de choix du serveur
    uv run --no-project start.py --serveur v2-2 # version imposee, sans menu
    uv run --no-project start.py --lister       # lister sans rien lancer
    uv run --no-project start.py --sans-n8n     # serveur + journalisation seuls

Portable : aucun chemin absolu. Deplacez ou renommez le projet, tout suit.
Bibliotheque standard uniquement.
"""

import argparse
import json
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ICI = Path(__file__).parent.resolve()          # .../cas_d_usage/cas_1_chat_n8n
PORT_MCP = int(os.environ.get("MCP_HTTP_PORT", "8733"))
PORT_LOG = int(os.environ.get("LOG_PORT", "8790"))

PROCS = []
PONTS = []          # [(PontStdio, ThreadingHTTPServer)]
ARRET = threading.Event()
RE_VER = re.compile(r'SERVER_VERSION\s*=\s*["\']([\d.]+)["\']')


# ---------------------------------------------------------------------------
#  Localisation du dossier des serveurs
# ---------------------------------------------------------------------------

def trouver_dossier_serveurs(indication=None) -> Path | None:
    """Remonte l'arborescence depuis ce script jusqu'a trouver serveur_mcp/."""
    if indication:
        p = Path(indication)
        if not p.is_absolute():
            p = (ICI / indication).resolve()
        return p if p.is_dir() else None
    env = os.environ.get("MCP_SERVEURS_DIR")
    if env and Path(env).is_dir():
        return Path(env).resolve()
    for parent in [ICI, *ICI.parents]:
        cand = parent / "serveur_mcp"
        if cand.is_dir():
            return cand.resolve()
    return None


def cle_tri(nom: str):
    """'v2-10' apres 'v2-2' : tri numerique sur les nombres du nom."""
    return [int(x) for x in re.findall(r"\d+", nom)] or [0]


def _cache_present(dossier: Path, src: str) -> bool:
    """Vrai si MITRE_DB/ contient les fichiers attendus par CE serveur."""
    attendus = set(re.findall(r'MITRE_DIR\s*/\s*"([^"]+\.json)"', src))
    d = dossier / "MITRE_DB"
    if not d.is_dir():
        return False
    presents = {p.name for p in d.glob("*.json")}
    return bool(attendus) and attendus <= presents


def inventorier(dossier: Path) -> list:
    """Liste les serveurs presents, avec version, capacite HTTP et cache."""
    trouves = []
    for py in dossier.rglob("mcp_mitre*.py"):
        if "__pycache__" in py.parts or "MITRE_DB" in py.parts:
            continue
        try:
            src = py.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if "SERVER_NAME" not in src or "def handle(" not in src:
            continue
        m = RE_VER.search(src)
        trouves.append({
            "path": py,
            "dossier": py.parent,
            # etiquette = nom du dossier de version (v2-2, v3...)
            "etiquette": py.parent.name,
            "version": m.group(1) if m else "?",
            "http": "def run_http" in src,
            # Les versions durcies refusent de demarrer en HTTP sans jeton :
            # il faut alors en fournir un (voir preparer_jeton).
            "exige_jeton": "MCP_HTTP_TOKEN" in src,
            # cache present = les fichiers que CETTE version attend
            "cache": _cache_present(py.parent, src),
        })
    trouves.sort(key=lambda s: cle_tri(s["etiquette"]), reverse=True)
    return trouves


def afficher_inventaire(serveurs, racine):
    print(f"\n  Serveurs disponibles dans {racine} :\n")
    for i, s in enumerate(serveurs, 1):
        rel = s["dossier"].relative_to(racine)
        marques = []
        if not s["http"]:
            marques.append("stdio — demarre via le pont HTTP")
        if s["exige_jeton"]:
            marques.append("exige un jeton")
        if not s["cache"]:
            marques.append("base MITRE a telecharger")
        suffixe = ("   (" + " ; ".join(marques) + ")") if marques else ""
        print(f"    {i}. {s['etiquette']:<6} v{s['version']:<7} [{rel}]{suffixe}")
    print()


def choisir(serveurs, racine, demande=None, sans_n8n=False):
    """Selection : par --serveur, sinon menu. n8n exige le mode HTTP."""
    if demande:
        for s in serveurs:
            if demande.lower() in (s["etiquette"].lower(), "v" + s["version"],
                                   s["version"]):
                return s
        print(f"[X] serveur « {demande} » introuvable.")
        afficher_inventaire(serveurs, racine)
        return None

    # Toutes les versions sont utilisables : celles sans transport reseau sont
    # servies via le pont stdio <-> HTTP integre a ce script.
    utilisables = serveurs

    if len(utilisables) == 1:
        s = utilisables[0]
        print(f"[start] serveur : {s['etiquette']} (v{s['version']})")
        return s

    if not sys.stdin.isatty():
        s = utilisables[0]
        print(f"[start] (mode non interactif) serveur le plus recent : "
              f"{s['etiquette']} (v{s['version']})")
        return s

    afficher_inventaire(utilisables, racine)
    while True:
        rep = input(f"  Serveur a demarrer [1-{len(utilisables)}, "
                    f"defaut 1] : ").strip()
        if rep == "":
            return utilisables[0]
        if rep.isdigit() and 1 <= int(rep) <= len(utilisables):
            return utilisables[int(rep) - 1]
        for s in utilisables:                     # tolere « v2-2 » tape a la main
            if rep.lower() == s["etiquette"].lower():
                return s
        print("  Entree invalide.")


def _fichiers_cache(dossier: Path):
    """Noms des fichiers de cache attendus par CE serveur.

    Les lignes v1.x et v2.x+ n'utilisent pas la meme source STIX, donc pas les
    memes noms de fichiers : mitre/cti donne enterprise.json / ics.json,
    attack-stix-data donne enterprise-attack.json / ics-attack.json. Copier un
    cache de l'une vers l'autre serait sans effet — le serveur ne trouverait
    pas ses fichiers et retelechargerait."""
    src = (dossier / "mcp_mitre.py")
    try:
        txt = src.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return set()
    noms = set(re.findall(r'MITRE_DIR\s*/\s*"([^"]+\.json)"', txt))
    return noms


def proposer_cache(choisi, serveurs):
    """Chaque version stocke sa propre base MITRE a cote d'elle. Si celle du
    serveur choisi manque mais qu'une autre version *au meme format* en a une,
    on la recopie : quelques secondes au lieu d'un telechargement complet."""
    if choisi["cache"]:
        return
    attendus = _fichiers_cache(choisi["dossier"])
    source = None
    for s in serveurs:
        if not s["cache"] or s["dossier"] == choisi["dossier"]:
            continue
        dispo = {p.name for p in (s["dossier"] / "MITRE_DB").glob("*.json")}
        # Le cache n'est utile que s'il contient les fichiers attendus.
        if attendus and attendus <= dispo:
            source = s
            break
    if not source:
        print("[start] base MITRE absente pour ce serveur : elle sera "
              "telechargee au demarrage (patientez, cela peut prendre une "
              "a plusieurs minutes selon la version).")
        return
    src = source["dossier"] / "MITRE_DB"
    dst = choisi["dossier"] / "MITRE_DB"
    print(f"[start] base MITRE absente pour {choisi['etiquette']} ; copie "
          f"depuis {source['etiquette']} (format compatible)...")
    try:
        shutil.copytree(src, dst, dirs_exist_ok=True)
        print("[start] cache copie.")
    except Exception as e:
        print(f"[!] copie impossible ({e}) — telechargement au demarrage.")


def preparer_jeton(choisi) -> dict:
    """Les versions durcies (v3+) refusent de demarrer en HTTP sans jeton
    d'authentification. Pour une demonstration locale, on en fournit un
    automatiquement — et on rappelle qu'il devra etre porte dans n8n."""
    env = dict(os.environ)
    if not choisi["exige_jeton"]:
        return env
    jeton = env.get("MCP_HTTP_TOKEN")
    if not jeton:
        jeton = "demo-locale-" + os.urandom(6).hex()
        env["MCP_HTTP_TOKEN"] = jeton
        print(f"[start] {choisi['etiquette']} exige une authentification : "
              f"jeton local genere.")
        print(f"[start] Dans n8n, noeud « MCP MITRE » : Authentication = "
              f"Bearer, jeton =")
        print(f"          {jeton}")
        print("[start] (definissez MCP_HTTP_TOKEN pour imposer le votre)")
    else:
        print(f"[start] {choisi['etiquette']} utilisera le jeton "
              f"MCP_HTTP_TOKEN de votre environnement.")
    return env



# ---------------------------------------------------------------------------
#  Pont stdio <-> HTTP
#
#  Les versions anterieures a la v2-2 n'ont aucun transport reseau : c'est leur
#  perimetre (stdio local). n8n, lui, ne parle que HTTP. Ce pont lance le
#  serveur en sous-processus, dialogue avec lui en stdio, et expose exactement
#  les memes routes qu'un serveur HTTP natif — de sorte que n8n ne voit aucune
#  difference, quelle que soit la version choisie.
#
#  Il ne modifie AUCUN fichier de serveur : c'est un harnais externe.
# ---------------------------------------------------------------------------

class PontStdio:
    """Dialogue avec un serveur MCP stdio et correle les reponses par `id`."""

    def __init__(self, chemin_serveur: Path, args_serveur=None):
        self.proc = subprocess.Popen(
            [sys.executable, str(chemin_serveur)] + list(args_serveur or []),
            cwd=str(chemin_serveur.parent),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", bufsize=1)
        self._attentes = {}                 # id JSON-RPC -> queue de reponse
        self._verrou = threading.Lock()     # une ecriture a la fois sur stdin
        threading.Thread(target=self._lire_sortie, daemon=True).start()
        threading.Thread(target=self._lire_erreurs, daemon=True).start()

    def _lire_sortie(self):
        for brut in iter(self.proc.stdout.readline, ""):
            ligne = brut.strip()
            if not ligne:
                continue
            try:
                msg = json.loads(ligne)
            except Exception:
                continue
            mid = msg.get("id")
            with self._verrou:
                q = self._attentes.pop(mid, None)
            if q is not None:
                q.put(msg)

    def _lire_erreurs(self):
        # Les journaux du serveur sortent sur stderr : on les relaie.
        for brut in iter(self.proc.stderr.readline, ""):
            if ARRET.is_set():
                break
            sys.stdout.write(f"[MITRE] {brut}")
            sys.stdout.flush()

    def envoyer(self, msg: dict, timeout=60):
        """Transmet un message. Retourne la reponse, ou None si notification."""
        if self.proc.poll() is not None:
            raise RuntimeError("le serveur MCP s'est arrete")
        mid = msg.get("id")
        q = None
        if mid is not None:
            q = queue.Queue(maxsize=1)
        with self._verrou:
            if q is not None:
                self._attentes[mid] = q
            self.proc.stdin.write(json.dumps(msg, ensure_ascii=False) + "\n")
            self.proc.stdin.flush()
        if q is None:
            return None                      # notification : pas de reponse
        try:
            return q.get(timeout=timeout)
        except queue.Empty:
            with self._verrou:
                self._attentes.pop(mid, None)
            raise RuntimeError("pas de reponse du serveur MCP")

    def arreter(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass


def faire_handler(pont: PontStdio, etiquette: str):
    """Construit le gestionnaire HTTP, avec les memes routes qu'un serveur
    HTTP natif : n8n fonctionne a l'identique quelle que soit la version."""

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = f"mcp-pont/{etiquette}"

        def log_message(self, *a):
            pass

        def _envoyer(self, code, corps=b"", ctype="application/json"):
            self.send_response(code)
            if corps:
                self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(corps)))
            self.end_headers()
            if corps:
                self.wfile.write(corps)

        def _json(self, code, obj):
            self._envoyer(code, json.dumps(obj, ensure_ascii=False).encode())

        def do_GET(self):
            chemin = self.path.split("?")[0].rstrip("/") or "/"
            if chemin == "/healthz":
                vivant = pont.proc.poll() is None
                self._json(200 if vivant else 503,
                           {"status": "ok" if vivant else "arrete",
                            "serveur": etiquette, "pont": True})
                return
            if chemin in ("/mcp", "/sse"):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                try:
                    if chemin == "/sse":
                        self.wfile.write(b"event: endpoint\ndata: /messages\n\n")
                        self.wfile.flush()
                    while not ARRET.is_set():
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                        time.sleep(15)
                except Exception:
                    return
                return
            self._json(404, {"erreur": "route inconnue"})

        def do_POST(self):
            chemin = self.path.split("?")[0].rstrip("/") or "/"
            if chemin not in ("/mcp", "/messages"):
                self._json(404, {"erreur": "route inconnue"})
                return
            n = int(self.headers.get("Content-Length") or 0)
            try:
                msg = json.loads(self.rfile.read(n).decode("utf-8"))
            except Exception:
                self._json(400, {"jsonrpc": "2.0", "id": None,
                                 "error": {"code": -32700,
                                           "message": "Parse error"}})
                return
            if isinstance(msg, list):
                self._json(400, {"jsonrpc": "2.0", "id": None,
                                 "error": {"code": -32600,
                                           "message": "un message par requete"}})
                return
            try:
                rep = pont.envoyer(msg)
            except Exception as e:
                self._json(502, {"jsonrpc": "2.0", "id": msg.get("id"),
                                 "error": {"code": -32000, "message": str(e)}})
                return
            if rep is None:
                self._envoyer(202)           # notification
                return
            accept = self.headers.get("Accept") or ""
            if "text/event-stream" in accept and "application/json" not in accept:
                corps = ("event: message\ndata: " +
                         json.dumps(rep, ensure_ascii=False) + "\n\n").encode()
                self._envoyer(200, corps, "text/event-stream")
            else:
                self._json(200, rep)

    return Handler


def demarrer_pont(choisi, port):
    """Lance le serveur stdio derriere un pont HTTP local."""
    pont = PontStdio(choisi["path"])
    httpd = ThreadingHTTPServer(("127.0.0.1", port),
                                faire_handler(pont, choisi["etiquette"]))
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    PONTS.append((pont, httpd))
    return pont


def verifier_serveur(s, port=8799, timeout=90):
    """Demarre reellement un serveur, lui parle en HTTP, et rend un verdict.

    C'est le test qui compte : il s'execute sur VOTRE machine avec VOS
    fichiers. Retourne (ok, mode, nb_outils, message)."""
    pont = httpd = proc = None
    env = dict(os.environ)
    mode = "natif" if s["http"] else "pont"
    try:
        if s["http"]:
            if s["exige_jeton"] and not env.get("MCP_HTTP_TOKEN"):
                env["MCP_HTTP_TOKEN"] = "verif-" + os.urandom(4).hex()
            proc = subprocess.Popen(
                [sys.executable, str(s["path"]), "--http", "--port", str(port)],
                cwd=str(s["dossier"]), env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace")
        else:
            pont = PontStdio(s["path"])
            httpd = ThreadingHTTPServer(
                ("127.0.0.1", port), faire_handler(pont, s["etiquette"]))
            httpd.daemon_threads = True
            threading.Thread(target=httpd.serve_forever, daemon=True).start()

        base = f"http://127.0.0.1:{port}"
        fin = time.time() + timeout
        vivant = False
        while time.time() < fin:
            if proc is not None and proc.poll() is not None:
                return False, mode, 0, "le serveur s'est arrete au demarrage"
            try:
                urllib.request.urlopen(base + "/healthz", timeout=2)
                vivant = True
                break
            except Exception:
                time.sleep(0.5)
        if not vivant:
            return False, mode, 0, "pas de reponse dans le delai imparti"

        entetes = {"Content-Type": "application/json"}
        if env.get("MCP_HTTP_TOKEN") and s["exige_jeton"]:
            entetes["Authorization"] = f"Bearer {env['MCP_HTTP_TOKEN']}"

        def appel(obj):
            r = urllib.request.Request(base + "/mcp",
                                       data=json.dumps(obj).encode(),
                                       headers=entetes)
            with urllib.request.urlopen(r, timeout=30) as rep:
                return json.loads(rep.read())

        appel({"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": "2025-11-25",
                          "clientInfo": {"name": "verification",
                                         "version": "1"}}})
        outils = appel({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        n = len(outils["result"]["tools"])
        rep = appel({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                     "params": {"name": "search_techniques",
                                "arguments": {"query": "phishing"}}})
        if "result" not in rep:
            return False, mode, n, "appel d'outil en echec"
        return True, mode, n, ""
    except Exception as e:
        return False, mode, 0, str(e)[:90]
    finally:
        try:
            if httpd:
                httpd.shutdown()
            if pont:
                pont.arreter()
            if proc and proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)
        except Exception:
            pass


def mode_verification(serveurs, racine) -> int:
    """Teste chaque serveur trouve et affiche un tableau de verdicts."""
    print(f"\n  Verification reelle de chaque serveur ({racine}).")
    print("  Chaque version est demarree, interrogee, puis arretee.\n")
    print(f"  {'Version':<8} {'Decl.':<7} {'Transport':<10} {'Outils':<7} Verdict")
    print("  " + "-" * 62)
    echecs = 0
    for s in serveurs:
        ok, mode, n, msg = verifier_serveur(s)
        decl = "HTTP" if s["http"] else "stdio"
        verdict = "OK" if ok else f"ECHEC — {msg}"
        if not ok:
            echecs += 1
        print(f"  {s['etiquette']:<8} {decl:<7} {mode:<10} "
              f"{(str(n) if n else '-'):<7} {verdict}")
    print()
    if echecs:
        print(f"  {echecs} serveur(s) en echec — voyez le message associe.")
    else:
        print("  Tous les serveurs repondent en HTTP et servent leurs outils.")
    return 1 if echecs else 0


# ---------------------------------------------------------------------------
#  Processus
# ---------------------------------------------------------------------------

def relais(nom, proc):
    try:
        for ligne in proc.stdout:
            if ARRET.is_set():
                break
            sys.stdout.write(f"[{nom}] {ligne}")
            sys.stdout.flush()
    except Exception:
        pass


def lancer(nom, cmd, cwd=None, env=None):
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    p = subprocess.Popen(cmd, cwd=str(cwd or ICI), env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, encoding="utf-8", errors="replace",
                         creationflags=flags)
    PROCS.append((nom, p))
    threading.Thread(target=relais, args=(nom, p), daemon=True).start()
    return p


def attendre_http(url, timeout=60):
    fin = time.time() + timeout
    while time.time() < fin:
        try:
            with urllib.request.urlopen(url, timeout=2):
                return True
        except Exception:
            time.sleep(0.5)
    return False


def trouver_npx():
    for nom in ("npx", "npx.cmd"):
        c = shutil.which(nom)
        if c:
            return c
    if os.name == "nt":
        for base in (os.environ.get("ProgramFiles", r"C:\Program Files"),
                     os.environ.get("APPDATA", "")):
            if base:
                cand = Path(base) / "nodejs" / "npx.cmd"
                if cand.exists():
                    return str(cand)
    return None


def arreter_tout():
    ARRET.set()
    for pont, httpd in PONTS:
        try:
            httpd.shutdown()
        except Exception:
            pass
        pont.arreter()
    for nom, p in reversed(PROCS):
        if p.poll() is None:
            try:
                if os.name == "nt":
                    p.send_signal(signal.CTRL_BREAK_EVENT)
                else:
                    p.terminate()
            except Exception:
                pass
    fin = time.time() + 8
    for nom, p in PROCS:
        try:
            p.wait(timeout=max(0.1, fin - time.time()))
        except Exception:
            p.kill()
    print("\n[start] tout est arrete.")


# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Demarre le chat n8n avec le serveur MCP de votre choix.")
    ap.add_argument("--serveur", help="version a lancer (ex. v2-2), sans menu")
    ap.add_argument("--serveurs-dir", help="chemin de serveur_mcp/ si la "
                                           "detection automatique echoue")
    ap.add_argument("--lister", action="store_true",
                    help="lister les serveurs disponibles et quitter")
    ap.add_argument("--verifier", action="store_true",
                    help="tester reellement chaque serveur (demarrage + appel "
                         "d'outil) et afficher un verdict")
    ap.add_argument("--sans-n8n", action="store_true", help="ne pas lancer n8n")
    args = ap.parse_args()

    print("Chat MITRE ATT&CK — demarrage")
    print(f"Cas d'usage : {ICI}")

    racine = trouver_dossier_serveurs(args.serveurs_dir)
    if racine is None:
        print("[X] dossier « serveur_mcp » introuvable en remontant depuis ce "
              "script.")
        print("    Indiquez-le : --serveurs-dir \"..\\..\\serveur_mcp\"")
        return 1

    serveurs = inventorier(racine)
    if not serveurs:
        print(f"[X] aucun mcp_mitre*.py trouve sous {racine}")
        return 1

    if args.lister:
        afficher_inventaire(serveurs, racine)
        return 0

    if args.verifier:
        return mode_verification(serveurs, racine)

    choisi = choisir(serveurs, racine, args.serveur, args.sans_n8n)
    if choisi is None:
        return 1

    logsvc = ICI / "log_service.py"
    base = ICI / "logs.db"
    if not logsvc.exists():
        print(f"[X] log_service.py absent de {ICI}")
        return 1
    if not base.exists():
        print("[X] logs.db absente — lancez d'abord : "
              "uv run --no-project setup.py")
        return 1

    proposer_cache(choisi, serveurs)

    py = sys.executable
    print(f"\n[start] serveur {choisi['etiquette']} (v{choisi['version']}) "
          f"sur 127.0.0.1:{PORT_MCP}...")

    if choisi["http"]:
        # Transport reseau natif (v2-2, v3).
        env_srv = preparer_jeton(choisi)
        # cwd = dossier du serveur : base MITRE et journal restent chez lui
        lancer("MITRE", [py, str(choisi["path"]), "--http",
                         "--port", str(PORT_MCP)], cwd=choisi["dossier"],
               env=env_srv)
    else:
        # Version sans transport reseau : pont stdio <-> HTTP integre.
        print(f"[start] {choisi['etiquette']} n'a pas de transport reseau : "
              f"demarrage via le pont HTTP integre.")
        try:
            demarrer_pont(choisi, PORT_MCP)
        except Exception as e:
            print(f"[X] impossible de demarrer le pont : {e}")
            arreter_tout()
            return 1

    if not attendre_http(f"http://127.0.0.1:{PORT_MCP}/healthz", 120):
        print("[X] le serveur ne repond pas — voyez les lignes [MITRE]")
        arreter_tout()
        return 1
    print("[start] serveur pret.")

    print(f"[start] journalisation sur 127.0.0.1:{PORT_LOG}...")
    lancer("LOGS", [py, str(logsvc), "--db", str(base),
                    "--port", str(PORT_LOG)])
    if not attendre_http(f"http://127.0.0.1:{PORT_LOG}/healthz", 20):
        print("[X] le service de journalisation ne repond pas")
        arreter_tout()
        return 1
    print("[start] journalisation prete.")

    if not args.sans_n8n:
        npx = trouver_npx()
        if not npx:
            print("[X] npx introuvable : installez Node.js LTS puis rouvrez "
                  "le terminal, ou relancez avec --sans-n8n.")
            arreter_tout()
            return 1
        print("[start] n8n (1er lancement : plusieurs minutes)...")
        lancer("N8N", [npx, "n8n"])
        if attendre_http("http://localhost:5678", 300):
            print("\n[start] PRET — ouvrez http://localhost:5678")
        else:
            print("[!] n8n tarde a repondre ; voyez les lignes [N8N]")
    else:
        print("\n[start] PRET (n8n non lance).")

    print(f"[start] serveur {choisi['etiquette']} | "
          f"MCP http://127.0.0.1:{PORT_MCP}/mcp | "
          f"stats http://127.0.0.1:{PORT_LOG}/stats")
    print("[start] Ctrl+C pour tout arreter.\n")

    try:
        while (any(p.poll() is None for _, p in PROCS)
               or any(pt.proc.poll() is None for pt, _ in PONTS)):
            time.sleep(1)
            for nom, p in PROCS:
                if p.poll() is not None and not ARRET.is_set():
                    print(f"[!] {nom} s'est arrete (code {p.returncode}) — "
                          f"arret de l'ensemble")
                    arreter_tout()
                    return 1
    except KeyboardInterrupt:
        print("\n[start] arret demande...")
        arreter_tout()
    return 0


if __name__ == "__main__":
    sys.exit(main())
