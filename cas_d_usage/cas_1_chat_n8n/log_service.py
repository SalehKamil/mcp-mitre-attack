#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
log_service.py — service de journalisation pour le workflow n8n.

Remplace le noeud communautaire n8n-nodes-sqlite3 (dont l'installation echoue
sur certains postes Windows) : n8n envoie l'objet de log par un simple noeud
HTTP Request natif, et ce service ecrit dans SQLite.

Bibliotheque standard Python UNIQUEMENT (http.server + sqlite3) :
aucune installation, aucune compilation, rien a ajouter dans n8n.

    uv run --no-project log_service.py
    uv run --no-project log_service.py --db "C:\\mcp-attack\\logs.db" --port 8790

Routes :
    POST /log      corps JSON = l'objet produit par le noeud "Assemble log".
                   Ecrit 1 ligne dans `executions` et N lignes dans
                   `execution_mitre_ids`. Idempotent par execution_id
                   (INSERT OR REPLACE / OR IGNORE) : rejouer un log ne
                   duplique rien.
    GET  /stats    petites statistiques (taux d'ancrage, volumes) — pratique
                   pour verifier sans outil SQLite.
    GET  /healthz  sonde de vivacite.

Comme le serveur MCP : ecoute limitee par defaut a 127.0.0.1, aucune
authentification a ce jalon (la securisation releve du chapitre 3).
"""

import argparse
import json
import re
import sqlite3
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE_DIR = Path(__file__).parent
DEFAULT_DB = BASE_DIR / "logs.db"
MAX_BODY = 1 * 1024 * 1024

# Une seule ecriture a la fois : SQLite s'accommode mal des ecrivains
# concurrents, et un chat n'en produit de toute facon qu'une par tour.
_write_lock = threading.Lock()
DB_PATH = str(DEFAULT_DB)



# ---------------------------------------------------------------------------
#  Skills — intelligence procedurale servie A L'EXECUTION
#
#  Les skills sont lus sur le disque a chaque requete (avec un cache par date
#  de modification). Ajouter un dossier dans github/skills/ suffit : il est
#  immediatement disponible dans le chat, sans regenerer ni reimporter le
#  workflow.
#
#  Le prompt est assemble ici plutot que dans n8n, pour trois raisons :
#    - les references d'un skill sont concatenees (n8n n'a pas de chargement
#      progressif) ;
#    - les noms d'outils perimes sont corriges (mitre_status -> mitre_stats) ;
#    - la liste des outils reellement exposes par le serveur est injectee en
#      tete, ce qui evite que le modele invoque un outil inexistant.
# ---------------------------------------------------------------------------

ALIAS_OUTILS = {"mitre_status": "mitre_stats",
                "search_datasources": "get_datasources"}
OUTILS_FANTOMES = {"get_run_metrics"}

_cache_skills = {"signature": None, "donnees": None}


def _dossier_skills():
    for parent in [BASE_DIR, *BASE_DIR.parents]:
        for rel in ("github/skills", "skills", ".github/skills"):
            c = parent / rel
            if c.is_dir():
                return c.resolve()
    return None


def _outils_serveur():
    """Outils reellement exposes, lus sur la version la plus recente."""
    for parent in [BASE_DIR, *BASE_DIR.parents]:
        d = parent / "serveur_mcp"
        if d.is_dir():
            best, best_v = set(), []
            for p in d.rglob("mcp_mitre*.py"):
                if "__pycache__" in p.parts:
                    continue
                src = p.read_text(encoding="utf-8", errors="replace")
                m = re.search(r'SERVER_VERSION\s*=\s*["\']([\d.]+)["\']', src)
                v = [int(x) for x in m.group(1).split(".")] if m else [0]
                if v > best_v:
                    best_v = v
                    best = set(re.findall(r'^@tool\("([a-z_]+)"', src, re.M))
            return best
    return set()


def _sans_frontmatter(txt: str) -> str:
    if txt.startswith("---"):
        fin = txt.find("\n---", 3)
        if fin != -1:
            return txt[fin + 4:].lstrip("\n")
    return txt


def _corriger(txt: str, dispo: set):
    for ancien, nouveau in ALIAS_OUTILS.items():
        if nouveau in dispo:
            txt = re.sub(rf"\b{ancien}\b", nouveau, txt)
    for f in OUTILS_FANTOMES:
        txt = re.sub(rf"^.*\b{f}\b.*$\n?", "", txt, flags=re.M)
    return txt


def _outils_exiges(txt: str) -> set:
    cites = set(re.findall(r"`([a-z_]{4,})\(", txt)) | \
            set(re.findall(r"`([a-z_]{4,})`", txt))
    cites = {ALIAS_OUTILS.get(c, c) for c in cites}
    return {c for c in cites
            if c.startswith(("get_", "search_", "list_", "mitre_"))
            and c not in OUTILS_FANTOMES}


def charger_skills(force=False):
    """Inventorie les skills et construit leurs prompts. Cache invalide des
    qu'un fichier change : editer un skill prend effet immediatement."""
    d = _dossier_skills()
    if not d:
        return {"dossier": None, "skills": {}}
    fichiers = sorted(d.rglob("*.md"))
    signature = tuple((str(f), f.stat().st_mtime) for f in fichiers)
    if not force and _cache_skills["signature"] == signature:
        return _cache_skills["donnees"]

    dispo = _outils_serveur()
    skills = {}
    for sk in sorted(d.glob("*/SKILL.md")):
        brut = sk.read_text(encoding="utf-8", errors="replace")
        m = re.search(r"^name:\s*(.+)$", brut, re.M)
        nom = (m.group(1).strip() if m else sk.parent.name)
        refs = sorted((sk.parent / "references").glob("*.md")) \
            if (sk.parent / "references").is_dir() else []

        noyau = _corriger(_sans_frontmatter(brut), dispo)
        entete = ["Tu operes dans un agent n8n connecte au serveur MCP "
                  "MITRE ATT&CK.", "",
                  "OUTILS REELLEMENT DISPONIBLES (n'en invoque aucun autre) :",
                  "  " + ", ".join(sorted(dispo)) + "." if dispo else "",
                  "", "Reponds en francais. Format simple et professionnel, "
                  "sans emoji.", "", "=" * 70]
        complet = "\n".join(entete + [noyau.rstrip()])
        exiges = _outils_exiges(brut)
        for r in refs:
            t = _corriger(_sans_frontmatter(
                r.read_text(encoding="utf-8", errors="replace")), dispo)
            exiges |= _outils_exiges(t)
            complet += "\n\n" + "-" * 70 + \
                       f"\n### Reference : {r.name}\n\n" + t.rstrip()
        skills[nom] = {
            "nom": nom,
            "dossier": sk.parent.name,
            "references": [r.name for r in refs],
            "outils_exiges": sorted(exiges),
            "outils_manquants": sorted(exiges - dispo) if dispo else [],
            "noyau": "\n".join(entete + [noyau.rstrip()]),
            "complet": complet,
        }
    donnees = {"dossier": str(d), "skills": skills}
    _cache_skills.update(signature=signature, donnees=donnees)
    return donnees


def resoudre_skill(nom, mode="complet"):
    """Trouve un skill par nom. Resolution deterministe :
    nom exact > nom de dossier > prefixe unique > fragment unique.
    Un fragment correspondant a plusieurs skills est declare AMBIGU : on ne
    devine pas, on retombe sur le defaut et on signale les candidats."""
    data = charger_skills()
    sk = data["skills"]
    if not sk:
        return None, [], None
    noms = list(sk)
    defaut = next((n for n in noms if sk[n]["references"]), noms[0])
    if not nom:
        return sk[defaut], noms, None

    cle = nom.strip().lower()

    def segments(n):
        # « assistant-mitre-cti » -> {assistant, mitre, cti}
        return set(re.split(r"[^a-z0-9]+", n.lower())) - {""}

    # 1. nom ou dossier exact
    exact = [n for n in noms if n.lower() == cle
             or sk[n]["dossier"].lower() == cle]
    if exact:
        return sk[exact[0]], noms, None
    # 2. segment exact — « cti », « sigma », « attack »
    #    (evite qu'un fragment traverse les mots : « cti » dans « detection »)
    seg = [n for n in noms if cle in segments(n) | segments(sk[n]["dossier"])]
    if len(seg) == 1:
        return sk[seg[0]], noms, None
    # 3. debut du nom
    prefixe = [n for n in noms if n.lower().startswith(cle)]
    if len(prefixe) == 1:
        return sk[prefixe[0]], noms, None
    # 4. debut d'un segment
    segpre = [n for n in noms
              if any(m.startswith(cle)
                     for m in segments(n) | segments(sk[n]["dossier"]))]
    if len(segpre) == 1:
        return sk[segpre[0]], noms, None
    # 5. fragment quelconque, en dernier recours
    fragment = [n for n in noms if cle in n.lower()]
    if len(fragment) == 1:
        return sk[fragment[0]], noms, None

    candidats = seg or prefixe or segpre or fragment
    return sk[defaut], noms, {"demande": nom, "candidats": sorted(candidats)}


# ---------------------------------------------------------------------------
#  Ecriture
# ---------------------------------------------------------------------------

EXEC_COLS = ("execution_id", "request_ts", "session_id", "user_id", "question",
             "answer", "model", "tokens_input", "tokens_output", "started_at",
             "finished_at", "latency_ms", "mcp_used", "mcp_call_count",
             "mcp_tools", "status", "error_message",
             "mitre_release_enterprise", "mitre_release_ics")


def write_log(obj: dict) -> dict:
    """Ecrit un objet de log. Retourne un petit compte-rendu."""
    if not isinstance(obj, dict):
        raise ValueError("le corps doit etre un objet JSON")
    if not obj.get("execution_id"):
        raise ValueError("champ obligatoire manquant : execution_id")
    if not obj.get("question"):
        raise ValueError("champ obligatoire manquant : question")

    row = []
    for c in EXEC_COLS:
        v = obj.get(c)
        if c == "mcp_tools" and not isinstance(v, str):
            v = json.dumps(v or [], ensure_ascii=False)
        row.append(v)

    ids = obj.get("mitre_ids") or []
    with _write_lock:
        con = sqlite3.connect(DB_PATH, timeout=10)
        try:
            con.execute(
                f"INSERT OR REPLACE INTO executions ({','.join(EXEC_COLS)}) "
                f"VALUES ({','.join('?' * len(EXEC_COLS))})", row)
            n_ids = 0
            for it in ids:
                if not isinstance(it, dict) or not it.get("mitre_id"):
                    continue
                con.execute(
                    "INSERT OR IGNORE INTO execution_mitre_ids "
                    "(execution_id, id_type, mitre_id, matrix, relation) "
                    "VALUES (?,?,?,?,?)",
                    (obj["execution_id"], it.get("id_type") or "technique",
                     it["mitre_id"], it.get("matrix"),
                     it.get("relation") or "requested"))
                n_ids += 1
            con.commit()
        finally:
            con.close()
    return {"ok": True, "execution_id": obj["execution_id"],
            "mitre_ids_ecrits": n_ids}


def read_stats() -> dict:
    con = sqlite3.connect(DB_PATH, timeout=10)
    try:
        tours, ancres = con.execute(
            "SELECT COUNT(*), COALESCE(SUM(mcp_used),0) FROM executions"
        ).fetchone()
        n_ids = con.execute(
            "SELECT COUNT(*) FROM execution_mitre_ids").fetchone()[0]
        top = con.execute(
            "SELECT mitre_id, COUNT(DISTINCT execution_id) n "
            "FROM execution_mitre_ids GROUP BY mitre_id "
            "ORDER BY n DESC LIMIT 5").fetchall()
        lat = con.execute(
            "SELECT ROUND(AVG(latency_ms)) FROM executions "
            "WHERE status='ok'").fetchone()[0]
    finally:
        con.close()
    return {"tours": tours,
            "taux_ancrage_pct": round(100.0 * ancres / tours, 1) if tours else None,
            "identifiants_cites": n_ids,
            "latence_moyenne_ms": lat,
            "top_identifiants": [{"mitre_id": m, "tours": n} for m, n in top]}


# ---------------------------------------------------------------------------
#  HTTP
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "mitre-log-service/1.0"

    def log_message(self, fmt, *a):      # silence du log d'acces par defaut
        pass

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/") or "/"
        if path == "/healthz":
            self._json(200, {"status": "ok", "db": DB_PATH})
        elif path == "/skills":
            data = charger_skills()
            if not data["dossier"]:
                self._json(404, {"erreur": "dossier de skills introuvable"})
                return
            self._json(200, {
                "dossier": data["dossier"],
                "skills": [{"nom": v["nom"], "dossier": v["dossier"],
                            "references": v["references"],
                            "outils_exiges": v["outils_exiges"],
                            "outils_manquants": v["outils_manquants"]}
                           for v in data["skills"].values()]})
        elif path == "/skill":
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(self.path).query)
            nom = (q.get("nom") or [""])[0]
            mode = (q.get("mode") or ["complet"])[0]
            sk, noms, souci = resoudre_skill(nom, mode)
            if sk is None:
                self._json(404, {"erreur": "aucun skill disponible"})
                return
            corps = {
                "nom": sk["nom"],
                "skills_disponibles": noms,
                "outils_manquants": sk["outils_manquants"],
                "system_prompt": sk["noyau" if mode == "noyau" else "complet"]}
            if souci:
                corps["avertissement"] = souci
                # Le modele doit pouvoir le dire a l'utilisateur.
                if souci["candidats"]:
                    corps["system_prompt"] += (
                        f"\n\nNOTE : « {souci['demande']} » designe plusieurs "
                        f"skills ({', '.join(souci['candidats'])}). "
                        f"Le skill par defaut a ete applique ; signale-le a "
                        f"l'utilisateur et invite-le a preciser.")
                else:
                    corps["system_prompt"] += (
                        f"\n\nNOTE : le skill « {souci['demande']} » n'existe "
                        f"pas. Skills disponibles : {', '.join(noms)}. "
                        f"Le skill par defaut a ete applique ; signale-le.")
            self._json(200, corps)
        elif path == "/stats":
            try:
                self._json(200, read_stats())
            except sqlite3.Error as e:
                self._json(500, {"ok": False, "erreur": str(e)})
        else:
            self._json(404, {"erreur": "route inconnue"})

    def do_POST(self):
        path = self.path.split("?")[0].rstrip("/") or "/"
        if path != "/log":
            self._json(404, {"erreur": "route inconnue"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            self._json(413, {"ok": False, "erreur": "corps trop volumineux"})
            return
        try:
            obj = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            self._json(400, {"ok": False, "erreur": "JSON illisible"})
            return
        try:
            self._json(200, write_log(obj))
        except ValueError as e:
            self._json(400, {"ok": False, "erreur": str(e)})
        except sqlite3.Error as e:
            # ex. base verrouillee par une synchro cloud : message explicite
            self._json(500, {"ok": False, "erreur": f"sqlite: {e}"})


def main() -> int:
    global DB_PATH
    ap = argparse.ArgumentParser(description="Service de journalisation n8n -> SQLite")
    ap.add_argument("--db", default=str(DEFAULT_DB),
                    help=f"chemin de logs.db (defaut : {DEFAULT_DB})")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8790)
    args = ap.parse_args()

    db = Path(args.db)
    if db.is_dir():
        db = db / "logs.db"
    DB_PATH = str(db)

    if not db.exists():
        print(f"[X] Base introuvable : {db}")
        print("    Creez-la d'abord :  uv run --no-project init_db.py")
        return 1

    # Verifie que le schema attendu est present.
    con = sqlite3.connect(DB_PATH)
    tables = {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    con.close()
    if not {"executions", "execution_mitre_ids"} <= tables:
        print(f"[X] La base {db} n'a pas le schema attendu "
              f"(tables presentes : {sorted(tables)})")
        print("    Appliquez le schema :  uv run --no-project init_db.py")
        return 1

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    httpd.daemon_threads = True
    print(f"[INFO] Journalisation : http://{args.host}:{args.port}/log  (POST)")
    print(f"[INFO] Statistiques   : http://{args.host}:{args.port}/stats")
    print(f"[INFO] Base           : {DB_PATH}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
