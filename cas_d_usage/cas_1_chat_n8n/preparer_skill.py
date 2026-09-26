#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
preparer_skill.py — transforme un skill en UN fichier texte a coller dans n8n.

    uv run --no-project preparer_skill.py

Produit un fichier .txt par skill dans  skills_prets/ .
Dans n8n : noeud « AI Agent » > Options > System Message > coller le contenu.
Changer de skill = coller un autre fichier. C'est tout.

Ce que le script fait pour vous :
  - fusionne SKILL.md et ses references en un seul texte (n8n n'a pas de
    chargement progressif) ;
  - retire l'en-tete YAML, inutile a n8n ;
  - corrige les noms d'outils perimes (mitre_status -> mitre_stats) ;
  - retire les mentions d'outils inexistants ;
  - ajoute en tete la liste des outils reellement exposes par votre serveur.

Pour ajouter VOTRE skill : creez un dossier dans github/skills/, avec un
SKILL.md (et un sous-dossier references/ si vous voulez), puis relancez.
Bibliotheque standard uniquement.
"""

import argparse
import re
import sys
from pathlib import Path

ICI = Path(__file__).parent.resolve()
ALIAS = {"mitre_status": "mitre_stats", "search_datasources": "get_datasources"}
FANTOMES = {"get_run_metrics"}


def trouver(nom_dossier, depuis=ICI):
    for parent in [depuis, *depuis.parents]:
        for rel in (nom_dossier, f"github/{nom_dossier}", f".github/{nom_dossier}"):
            c = parent / rel
            if c.is_dir():
                return c.resolve()
    return None


def outils_du_serveur():
    d = trouver("serveur_mcp")
    if not d:
        return set()
    best, best_v = set(), []
    for p in d.rglob("mcp_mitre*.py"):
        if "__pycache__" in p.parts:
            continue
        src = p.read_text(encoding="utf-8", errors="replace")
        m = re.search(r'SERVER_VERSION\s*=\s*["\']([\d.]+)["\']', src)
        v = [int(x) for x in m.group(1).split(".")] if m else [0]
        if v > best_v:
            best_v, best = v, set(re.findall(r'^@tool\("([a-z_]+)"', src, re.M))
    return best


def sans_frontmatter(txt):
    if txt.startswith("---"):
        fin = txt.find("\n---", 3)
        if fin != -1:
            return txt[fin + 4:].lstrip("\n")
    return txt


def nettoyer(txt, dispo):
    for ancien, nouveau in ALIAS.items():
        if nouveau in dispo:
            txt = re.sub(rf"\b{ancien}\b", nouveau, txt)
    for f in FANTOMES:
        txt = re.sub(rf"^.*\b{f}\b.*$\n?", "", txt, flags=re.M)
    return txt


def preparer(dossier_skill: Path, dispo: set) -> tuple:
    sk = dossier_skill / "SKILL.md"
    brut = sk.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"^name:\s*(.+)$", brut, re.M)
    nom = (m.group(1).strip() if m else dossier_skill.name)

    parties = []
    if dispo:
        parties += [
            "OUTILS DISPONIBLES (n'en invoque aucun autre) :",
            "  " + ", ".join(sorted(dispo)) + ".",
            "",
            "Reponds en francais. Format simple et professionnel, sans emoji.",
            "", "=" * 70, ""]
    parties.append(nettoyer(sans_frontmatter(brut), dispo).rstrip())

    refs = sorted((dossier_skill / "references").glob("*.md")) \
        if (dossier_skill / "references").is_dir() else []
    for r in refs:
        parties += ["", "-" * 70, f"### Reference : {r.name}", "",
                    nettoyer(sans_frontmatter(
                        r.read_text(encoding="utf-8", errors="replace")),
                        dispo).rstrip()]

    texte = "\n".join(parties)
    manquants = sorted({o for o in
                        (set(re.findall(r"`([a-z_]{4,})\(", texte)) |
                         set(re.findall(r"`([a-z_]{4,})`", texte)))
                        if o.startswith(("get_", "search_", "list_", "mitre_"))
                        and dispo and o not in dispo})
    return nom, texte, len(refs), manquants


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Prepare un fichier skill a coller dans n8n")
    ap.add_argument("--skills-dir", help="chemin de github/skills")
    ap.add_argument("--sortie", default="skills_prets",
                    help="dossier de sortie (defaut : skills_prets)")
    args = ap.parse_args()

    d = trouver("skills") if not args.skills_dir else Path(args.skills_dir)
    if not d or not d.is_dir():
        print("[X] dossier de skills introuvable.")
        print("    Attendu : github/skills/  (ou --skills-dir CHEMIN)")
        return 1
    print(f"Skills : {d}")

    dispo = outils_du_serveur()
    print(f"Outils du serveur : {len(dispo) or 'non detectes'}")

    dossiers = sorted(p.parent for p in d.glob("*/SKILL.md"))
    if not dossiers:
        print(f"[X] aucun SKILL.md sous {d}")
        return 1

    sortie = Path(args.sortie)
    if not sortie.is_absolute():
        sortie = ICI / sortie
    sortie.mkdir(parents=True, exist_ok=True)

    print()
    for ds in dossiers:
        nom, texte, nrefs, manquants = preparer(ds, dispo)
        f = sortie / f"{nom}.txt"
        f.write_text(texte, encoding="utf-8")
        print(f"  {f.name:<34} {len(texte):>6} car. "
              f"(~{len(texte)//4} jetons, {nrefs} reference(s))")
        if manquants:
            print(f"      [!] outils cites mais absents du serveur : "
                  f"{', '.join(manquants)}")

    print(f"\n  Fichiers dans : {sortie}")
    print("""
  DANS n8n, pour charger un skill :
    1. ouvrir le noeud « AI Agent » ;
    2. Options > System Message ;
    3. coller le contenu du fichier .txt voulu ;
    4. Save.

  Changer de skill = coller un autre fichier.
  Ajouter le votre  = creer un dossier dans github/skills/ avec un SKILL.md,
                      relancer ce script, coller le .txt produit.
""")
    return 0


if __name__ == "__main__":
    sys.exit(main())
