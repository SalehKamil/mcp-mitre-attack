#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
setup.py — prepare le cas d'usage « chat n8n ».

    uv run --no-project setup.py           # installation
    uv run --no-project setup.py --check   # verifier sans rien modifier

Ne touche a rien hors de ce dossier : les serveurs restent ou ils sont, dans
serveur_mcp/. Idempotent, relancable sans risque.
"""

import argparse
import json
import shutil
import sqlite3
import sys
from pathlib import Path

ICI = Path(__file__).parent.resolve()
SCHEMA = ICI / "schema_logs.sql"
BASE = ICI / "logs.db"
LOGSVC = ICI / "log_service.py"
def _trouver_workflow():
    """N'importe quel workflow_*.json convient : le nom peut varier selon le
    skill charge. On prefere celui qui porte un skill."""
    cands = sorted(ICI.glob("workflow_*.json"))
    if not cands:
        return ICI / "workflow_mitre_chat.json"
    avec_skill = [c for c in cands if "skill" in c.stem]
    return (avec_skill or cands)[0]


WORKFLOW = _trouver_workflow()

OK, KO, INFO, WARN = "  [OK]", "  [X] ", "  [i] ", "  [!] "


def titre(t):
    print(f"\n=== {t} " + "=" * max(0, 58 - len(t)))


def trouver_serveurs():
    """Localise serveur_mcp/ en remontant, et compte les serveurs."""
    for parent in [ICI, *ICI.parents]:
        d = parent / "serveur_mcp"
        if d.is_dir():
            n = [p for p in d.rglob("mcp_mitre*.py")
                 if "__pycache__" not in p.parts]
            return d, n
    return None, []


def prerequis() -> bool:
    titre("1/3 — Prerequis")
    ok = True

    v = sys.version_info
    print(f"{OK if v >= (3, 8) else KO} Python {v.major}.{v.minor}.{v.micro}"
          f"{'' if v >= (3, 8) else '  (3.8 minimum)'}")
    ok &= v >= (3, 8)

    if shutil.which("npx") or shutil.which("npx.cmd"):
        print(f"{OK} Node.js / npx (necessaire pour n8n)")
    else:
        print(f"{KO} npx introuvable : installez Node.js LTS "
              f"(https://nodejs.org) puis ROUVREZ le terminal")
        ok = False

    for f in (SCHEMA, LOGSVC, WORKFLOW, ICI / "start.py"):
        if f.exists():
            print(f"{OK} {f.name}")
        else:
            print(f"{KO} manquant dans ce dossier : {f.name}")
            ok = False

    d, serveurs = trouver_serveurs()
    if d:
        print(f"{OK} serveur_mcp trouve : {d}")
        print(f"{INFO} {len(serveurs)} serveur(s) detecte(s) — "
              f"« start.py --lister » pour le detail")
    else:
        print(f"{KO} dossier serveur_mcp introuvable en remontant depuis ici")
        ok = False
    return ok


def base_de_logs() -> bool:
    titre("2/3 — Base de journalisation")
    if not SCHEMA.exists():
        print(f"{KO} schema_logs.sql absent")
        return False
    schema = SCHEMA.read_text(encoding="utf-8")

    indices = ("mon disque", "google drive", "onedrive", "dropbox", "icloud")
    if any(i in str(ICI).lower() for i in indices):
        print(f"{WARN} dossier synchronise (Drive/OneDrive...) : journal "
              f"SQLite en mode DELETE")
        print(f"       pour une campagne de mesures, preferez un dossier local")
        schema = schema.replace("PRAGMA journal_mode = WAL;",
                                "PRAGMA journal_mode = DELETE;")
    try:
        con = sqlite3.connect(str(BASE))
        con.executescript(schema)
        con.commit()
        tables = sorted(r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%'"))
        con.close()
    except sqlite3.Error as e:
        print(f"{KO} SQLite : {e}")
        return False
    print(f"{OK} logs.db prete ({', '.join(tables)})")
    return True


def rappel_workflow():
    titre("3/3 — Workflow n8n")
    if WORKFLOW.exists():
        try:
            wf = json.loads(WORKFLOW.read_text(encoding="utf-8"))
            print(f"{OK} {WORKFLOW.name} ({len(wf.get('nodes', []))} noeuds) "
                  f"— a importer dans n8n")
        except Exception:
            print(f"{WARN} {WORKFLOW.name} illisible")
    else:
        print(f"{KO} {WORKFLOW.name} absent")


def suite():
    titre("Etapes suivantes")
    print("""
  1. Demarrer (le script propose la version du serveur) :

        uv run --no-project start.py

  2. Dans n8n (http://localhost:5678), la premiere fois seulement :
       a. creer le compte proprietaire local ;
       b. importer  workflow_mitre_chat.json ;
       c. noeud « Claude Sonnet » : credential avec votre cle API Anthropic,
          puis CHOISIR le modele dans la liste ;
       d. Save, puis bouton Chat.

  Adresses (deja reglees dans le workflow) :
        serveur MCP     http://127.0.0.1:8733/mcp
        journalisation  http://127.0.0.1:8790/log
        statistiques    http://127.0.0.1:8790/stats
""")


def main() -> int:
    ap = argparse.ArgumentParser(description="Prepare le cas d'usage chat n8n")
    ap.add_argument("--check", action="store_true",
                    help="verifier sans rien modifier")
    args = ap.parse_args()

    print("Cas d'usage 1 — chat n8n : installation")
    print(f"Dossier : {ICI}")

    ok = prerequis()
    if args.check:
        titre("Etat")
        print(f"{OK if BASE.exists() else KO} logs.db "
              f"{'presente' if BASE.exists() else 'absente'}")
        return 0 if ok else 1

    if not ok:
        print("\nCorrigez les points [X] ci-dessus, puis relancez.")
        return 1
    if not base_de_logs():
        return 1
    rappel_workflow()
    suite()
    return 0


if __name__ == "__main__":
    sys.exit(main())
