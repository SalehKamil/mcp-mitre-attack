#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""
gitmanager.py — Gestionnaire Git / GitHub interactif.

Lancement :
    uv run gitmanager.py
    (ou : python gitmanager.py)

Aucune dependance externe, aucun outil externe requis a part `git`.
L'API GitHub est appelee directement via urllib (pas besoin de `gh`).
"""

import base64
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from getpass import getpass
from pathlib import Path

CONFIG = Path.home() / ".gitmanager.json"
DEFAULT_API = "https://api.github.com"

GITIGNORE = """__pycache__/
*.py[cod]
*.so
.venv/
venv/
env/
.env
.env.*
*.log
.pytest_cache/
.mypy_cache/
.ruff_cache/
dist/
build/
*.egg-info/
node_modules/
.idea/
.vscode/
.DS_Store
Thumbs.db
"""


# --------------------------------------------------------------------------
# Affichage
# --------------------------------------------------------------------------

def _ansi_on():
    if os.name == "nt":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            return False
    return sys.stdout.isatty()


COLOR = _ansi_on()


def c(txt, code):
    return f"\033[{code}m{txt}\033[0m" if COLOR else txt


def titre(t):
    print()
    print(c("=" * 62, "36"))
    print(c(f"  {t}", "1;36"))
    print(c("=" * 62, "36"))


def ok(t):
    print(c(f"  [OK] {t}", "32"))


def warn(t):
    print(c(f"  [!]  {t}", "33"))


def err(t):
    print(c(f"  [X]  {t}", "31"))


def info(t):
    print(c(f"  ->   {t}", "90"))


# --------------------------------------------------------------------------
# Saisie
# --------------------------------------------------------------------------

def ask(question, defaut=None, obligatoire=True):
    suffixe = f" [{defaut}]" if defaut else ""
    while True:
        rep = input(c(f"  {question}{suffixe} : ", "1")).strip()
        if not rep and defaut is not None:
            return defaut
        if rep:
            return rep
        if not obligatoire:
            return ""
        warn("Une valeur est requise.")


def ask_yn(question, defaut=False):
    d = "O/n" if defaut else "o/N"
    rep = input(c(f"  {question} [{d}] : ", "1")).strip().lower()
    if not rep:
        return defaut
    return rep in ("o", "oui", "y", "yes")


def pause():
    input(c("\n  -- Entree pour revenir au menu --", "90"))


# --------------------------------------------------------------------------
# Configuration locale
# --------------------------------------------------------------------------

def charger():
    if CONFIG.exists():
        try:
            return json.loads(CONFIG.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def sauver(cfg):
    CONFIG.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    try:
        os.chmod(CONFIG, 0o600)
    except Exception:
        pass


def get_token(cfg, obligatoire=True):
    """Recupere le token : config > variable d'env > saisie."""
    tok = cfg.get("token") or os.environ.get("GITHUB_TOKEN", "")
    if tok:
        return tok
    if not obligatoire:
        return ""
    print()
    info("Un jeton d'acces personnel (PAT) est necessaire.")
    info("Creation : https://github.com/settings/tokens  (token classic)")
    info("Portees   : 'repo'  (+ 'delete_repo' pour la suppression)")
    tok = getpass(c("  Colle ton token (masque) : ", "1")).strip()
    if tok and ask_yn("Memoriser ce token dans ~/.gitmanager.json ?", True):
        cfg["token"] = tok
        sauver(cfg)
        ok(f"Token enregistre dans {CONFIG}")
    return tok


# --------------------------------------------------------------------------
# Git
# --------------------------------------------------------------------------

def git(*args, cwd=None, check=False, quiet=False):
    """Execute une commande git. Retourne (code, stdout, stderr)."""
    cmd = ["git"] + [str(a) for a in args]
    if not quiet:
        print(c("  $ " + " ".join(cmd), "90"))
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if not quiet:
        for flux in (p.stdout, p.stderr):
            if flux and flux.strip():
                for ligne in flux.strip().splitlines():
                    print("     " + ligne)
    if check and p.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} a echoue")
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()


def git_ok():
    if shutil.which("git"):
        return True
    err("git est introuvable dans le PATH.")
    info("Windows : winget install --id Git.Git -e")
    info("Linux   : sudo apt install git")
    return False


def est_repo(chemin="."):
    code, out, _ = git("rev-parse", "--is-inside-work-tree",
                       cwd=chemin, quiet=True)
    return code == 0 and out == "true"


def branche_courante(chemin="."):
    """Nom de la branche, y compris sur un depot sans aucun commit."""
    for args in (("branch", "--show-current"), ("symbolic-ref", "--short", "HEAD")):
        code, out, _ = git(*args, cwd=chemin, quiet=True)
        if code == 0 and out and out != "HEAD":
            return out
    return "main"


def branches_locales(chemin="."):
    code, out, _ = git("branch", "--format=%(refname:short)", cwd=chemin, quiet=True)
    return [b.strip() for b in out.splitlines() if b.strip()] if code == 0 else []


def assurer_branche(chemin, branche):
    """Garantit que la branche demandee est bien la branche courante."""
    cur = branche_courante(chemin)
    if cur == branche:
        return True
    if branche in branches_locales(chemin):
        code, _, _ = git("checkout", branche, cwd=chemin)
        return code == 0
    print()
    warn(f"La branche courante est '{cur}', pas '{branche}'.")
    print(f"    1. Renommer '{cur}' en '{branche}'   (git branch -M)")
    print(f"    2. Creer une nouvelle branche '{branche}'   (git checkout -b)")
    print(f"    3. Garder '{cur}' et pousser celle-ci")
    choix = ask("Choix", "1")
    if choix == "2":
        code, _, _ = git("checkout", "-b", branche, cwd=chemin)
        return code == 0
    if choix == "3":
        return cur
    code, _, _ = git("branch", "-M", branche, cwd=chemin)
    return code == 0


def remotes(chemin="."):
    code, out, _ = git("remote", cwd=chemin, quiet=True)
    return [r for r in out.splitlines() if r.strip()] if code == 0 else []


def url_remote(nom, chemin="."):
    code, out, _ = git("remote", "get-url", nom, cwd=chemin, quiet=True)
    return out if code == 0 else ""


def choisir_dossier(cfg):
    defaut = cfg.get("dernier_dossier") or os.getcwd()
    chemin = ask("Dossier du projet", defaut)
    chemin = os.path.expandvars(os.path.expanduser(chemin.strip().strip('"')))
    if not os.path.isdir(chemin):
        err(f"Dossier introuvable : {chemin}")
        return None
    cfg["dernier_dossier"] = chemin
    sauver(cfg)
    return chemin


def choisir_remote(chemin, defaut="origin"):
    rs = remotes(chemin)
    if not rs:
        return None
    if len(rs) == 1:
        return rs[0]
    print()
    for i, r in enumerate(rs, 1):
        print(f"    {i}. {r}  ->  {url_remote(r, chemin)}")
    choix = ask("Quel remote ?", defaut)
    if choix.isdigit() and 1 <= int(choix) <= len(rs):
        return rs[int(choix) - 1]
    return choix if choix in rs else rs[0]


# --------------------------------------------------------------------------
# URL / token
# --------------------------------------------------------------------------

def injecter_token(url, token, user=""):
    """Insere le token dans une URL https pour un push sans invite."""
    if not token or not url.startswith("https://"):
        return url
    reste = url[len("https://"):]
    if "@" in reste.split("/")[0]:
        return url  # deja des identifiants
    ident = f"{user}:{token}" if user else token
    return f"https://{ident}@{reste}"


def masquer(url):
    return re.sub(r"https://[^@/]+@", "https://***@", url)


def api_depuis_url(url):
    """Deduit l'endpoint API depuis une URL de depot (github.com ou Enterprise)."""
    m = re.search(r"https://(?:[^@/]+@)?([^/]+)/", url)
    if not m:
        return DEFAULT_API
    host = m.group(1)
    return DEFAULT_API if host == "github.com" else f"https://{host}/api/v3"


def owner_repo(url):
    """Extrait (owner, repo) d'une URL GitHub."""
    m = re.search(r"[:/]([^/:]+)/([^/]+?)(?:\.git)?/?$", url.rstrip("/"))
    return (m.group(1), m.group(2)) if m else (None, None)


# --------------------------------------------------------------------------
# API GitHub (urllib, sans dependance)
# --------------------------------------------------------------------------

def api(methode, chemin, cfg, data=None, base=None):
    """Appel REST GitHub. Retourne (status, objet_json_ou_texte)."""
    base = base or cfg.get("api", DEFAULT_API)
    token = get_token(cfg)
    if not token:
        return 0, {"message": "Aucun token fourni."}
    url = base.rstrip("/") + chemin
    corps = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=corps, method=methode)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("User-Agent", "gitmanager-script")
    if corps:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            brut = r.read().decode("utf-8") or "{}"
            try:
                return r.status, json.loads(brut)
            except json.JSONDecodeError:
                return r.status, {"raw": brut}
    except urllib.error.HTTPError as e:
        brut = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(brut)
        except json.JSONDecodeError:
            return e.code, {"message": brut[:400]}
    except urllib.error.URLError as e:
        return 0, {"message": f"Reseau/proxy : {e.reason}"}


def utilisateur_courant(cfg):
    code, rep = api("GET", "/user", cfg)
    if code == 200:
        return rep.get("login")
    err(f"Authentification echouee ({code}) : {rep.get('message')}")
    return None


# --------------------------------------------------------------------------
# Actions
# --------------------------------------------------------------------------

def action_auth(cfg):
    titre("1. Authentification GitHub")
    if cfg.get("token") and ask_yn("Un token est deja enregistre. Le remplacer ?", False):
        cfg.pop("token", None)
        sauver(cfg)
    api_base = ask("Endpoint API (Entreprise : https://github.xxx.com/api/v3)",
                   cfg.get("api", DEFAULT_API))
    cfg["api"] = api_base
    sauver(cfg)
    login = utilisateur_courant(cfg)
    if not login:
        return
    ok(f"Connecte en tant que : {login}")
    cfg["login"] = login
    nom = ask("Nom pour les commits (git user.name)", cfg.get("nom", login))
    email = ask("Email pour les commits (git user.email)", cfg.get("email", ""))
    cfg["nom"], cfg["email"] = nom, email
    sauver(cfg)
    git("config", "--global", "user.name", nom)
    git("config", "--global", "user.email", email)
    git("config", "--global", "init.defaultBranch", "main")
    helper = "manager" if os.name == "nt" else "store"
    git("config", "--global", "credential.helper", helper)
    ok("Configuration git globale mise a jour.")


def creer_depot_distant(cfg, nom, prive, org=""):
    data = {"name": nom, "private": prive, "auto_init": False}
    chemin = f"/orgs/{org}/repos" if org else "/user/repos"
    code, rep = api("POST", chemin, cfg, data)
    if code == 201:
        ok(f"Depot cree : {rep.get('html_url')} ({'prive' if prive else 'public'})")
        return rep.get("clone_url")
    if code == 422:
        warn("Ce depot existe deja cote GitHub — on le reutilise.")
        proprio = org or cfg.get("login") or utilisateur_courant(cfg)
        code2, rep2 = api("GET", f"/repos/{proprio}/{nom}", cfg)
        if code2 == 200:
            return rep2.get("clone_url")
    err(f"Creation impossible ({code}) : {rep.get('message')}")
    return None


def action_init_push(cfg):
    titre("2. git init + premier push")
    chemin = choisir_dossier(cfg)
    if not chemin:
        return
    if est_repo(chemin):
        warn("Ce dossier est deja un depot git.")
        if not ask_yn("Continuer quand meme (add + commit + push) ?", True):
            return
    else:
        git("init", cwd=chemin)

    nom = ask("git user.name", cfg.get("nom", ""))
    email = ask("git user.email", cfg.get("email", ""))
    cfg["nom"], cfg["email"] = nom, email
    sauver(cfg)
    git("config", "user.name", nom, cwd=chemin)
    git("config", "user.email", email, cwd=chemin)

    gi = Path(chemin) / ".gitignore"
    if not gi.exists() and ask_yn("Creer un .gitignore standard (Python/Node) ?", True):
        gi.write_text(GITIGNORE, encoding="utf-8")
        ok(".gitignore cree")

    url = ""
    if ask_yn("Creer un nouveau depot sur GitHub ?", True):
        login = cfg.get("login") or utilisateur_courant(cfg)
        if not login:
            return
        defaut_nom = re.sub(r"[^A-Za-z0-9._-]+", "-", os.path.basename(chemin)).strip("-")
        rnom = ask("Nom du depot", defaut_nom)
        org = ask("Organisation (vide = compte perso)", "", obligatoire=False)
        prive = ask_yn("Depot prive ?", True)
        url = creer_depot_distant(cfg, rnom, prive, org) or ""
        if not url:
            return
    else:
        url = ask("URL du depot distant (https://.../xxx.git)")

    branche = ask("Nom de la branche", "main")
    message = ask("Message du commit", "Initial commit")

    git("branch", "-M", branche, cwd=chemin)
    git("add", "-A", cwd=chemin)
    print()
    git("status", "--short", cwd=chemin)
    print()
    if not ask_yn("Les fichiers ci-dessus sont corrects ?", True):
        warn("Annule. Ajuste ton .gitignore puis recommence.")
        return
    code, _, _ = git("commit", "-m", message, cwd=chemin)
    if code != 0:
        warn("Rien a committer (ou commit refuse) — on tente le push malgre tout.")

    nom_remote = ask("Nom du remote", "origin")
    if nom_remote in remotes(chemin):
        git("remote", "set-url", nom_remote, url, cwd=chemin)
    else:
        git("remote", "add", nom_remote, url, cwd=chemin)

    pousser(cfg, chemin, nom_remote, branche, force=False, amont=True)


def pousser(cfg, chemin, nom_remote, branche, force=False, amont=False):
    """Push en injectant le token dans l'URL (aucune invite, pas besoin de gh)."""
    url = url_remote(nom_remote, chemin)
    if not url:
        err(f"Remote '{nom_remote}' introuvable.")
        return False
    base = api_depuis_url(url)
    token = get_token(cfg, obligatoire=False)
    cible = injecter_token(url, token, cfg.get("login", "")) if token else url

    args = ["push"]
    if amont:
        args.append("-u")
    if force:
        args.append("--force-with-lease")
    args += [cible, branche]

    print(c(f"  $ git push {'-u ' if amont else ''}"
            f"{'--force-with-lease ' if force else ''}"
            f"{masquer(cible)} {branche}", "90"))
    p = subprocess.run(["git"] + args, cwd=chemin, capture_output=True,
                       text=True, encoding="utf-8", errors="replace")
    sortie = masquer((p.stdout or "") + (p.stderr or ""))
    for ligne in sortie.strip().splitlines():
        print("     " + ligne)

    if p.returncode == 0:
        # On fixe l'amont sur le nom du remote, pas sur l'URL avec token
        if amont:
            git("branch", "--set-upstream-to",
                f"{nom_remote}/{branche}", branche, cwd=chemin, quiet=True)
        ok(f"Push reussi vers {nom_remote}/{branche}  ({masquer(url)})")
        return True
    err("Le push a echoue.")
    if "rejected" in sortie or "non-fast-forward" in sortie:
        info("Le distant contient des commits absents en local.")
        info("-> Choix 3 (mettre a jour) ou choix 4 (ecraser).")
    if "403" in sortie or "Authentication" in sortie:
        info("Token invalide ou portee 'repo' manquante -> choix 1.")
    return False


def action_maj(cfg):
    titre("3. Mettre a jour un depot existant (sans ecraser)")
    chemin = choisir_dossier(cfg)
    if not chemin or not est_repo(chemin):
        err("Ce dossier n'est pas un depot git.")
        return
    nom_remote = choisir_remote(chemin) or ask("Nom du remote", "origin")
    branche = ask("Branche", branche_courante(chemin))
    res = assurer_branche(chemin, branche)
    if isinstance(res, str):
        branche = res

    git("add", "-A", cwd=chemin)
    git("status", "--short", cwd=chemin)
    code, out, _ = git("status", "--porcelain", cwd=chemin, quiet=True)
    if out:
        message = ask("Message du commit", "Mise a jour")
        git("commit", "-m", message, cwd=chemin)
    else:
        info("Aucune modification locale a committer.")

    info("Recuperation du distant puis rebase (l'historique distant est conserve).")
    url = url_remote(nom_remote, chemin)
    token = get_token(cfg, obligatoire=False)
    cible = injecter_token(url, token, cfg.get("login", "")) if token else url
    subprocess.run(["git", "fetch", cible, branche], cwd=chemin,
                   capture_output=True, text=True)

    code, _, sortie = git("rebase", "FETCH_HEAD", cwd=chemin)
    if code != 0:
        err("Conflit de rebase.")
        info("Resous les conflits, puis : git add . && git rebase --continue")
        info("Pour abandonner : git rebase --abort")
        return
    pousser(cfg, chemin, nom_remote, branche, force=False)


def action_ecraser(cfg):
    titre("4. Ecraser le depot distant (force push)")
    warn("Cette operation remplace l'historique distant. Irreversible.")
    chemin = choisir_dossier(cfg)
    if not chemin or not est_repo(chemin):
        err("Ce dossier n'est pas un depot git.")
        return
    nom_remote = choisir_remote(chemin) or ask("Nom du remote", "origin")
    branche = ask("Branche", branche_courante(chemin))
    res = assurer_branche(chemin, branche)
    if isinstance(res, str):
        branche = res
    url = url_remote(nom_remote, chemin)
    print()
    warn(f"Cible : {masquer(url)}  branche {branche}")
    if ask("Tape ECRASER en majuscules pour confirmer") != "ECRASER":
        info("Annule.")
        return

    git("add", "-A", cwd=chemin)
    _, out, _ = git("status", "--porcelain", cwd=chemin, quiet=True)
    if out:
        git("commit", "-m", ask("Message du commit", "Mise a jour forcee"), cwd=chemin)
    pousser(cfg, chemin, nom_remote, branche, force=True)


def action_visibilite(cfg):
    titre("5. Rendre le depot public ou prive")
    login = cfg.get("login") or utilisateur_courant(cfg)
    if not login:
        return
    proprio = ask("Proprietaire (user ou organisation)", login)
    depot = ask("Nom du depot")
    code, rep = api("GET", f"/repos/{proprio}/{depot}", cfg)
    if code != 200:
        err(f"Depot introuvable ({code}) : {rep.get('message')}")
        return
    actuel = "prive" if rep.get("private") else "public"
    info(f"Visibilite actuelle : {actuel}")
    cible = ask("Nouvelle visibilite (public / prive)",
                "public" if actuel == "prive" else "prive")
    prive = cible.lower().startswith("p") and "ub" not in cible.lower()
    if prive == rep.get("private"):
        info("Deja dans cet etat, rien a faire.")
        return
    if not prive:
        warn("Rendre public expose tout l'historique, y compris les anciens commits.")
        if not ask_yn("Confirmer le passage en PUBLIC ?", False):
            return
    code, rep = api("PATCH", f"/repos/{proprio}/{depot}", cfg, {"private": prive})
    if code == 200:
        ok(f"{proprio}/{depot} est maintenant {'prive' if prive else 'public'}.")
    else:
        err(f"Echec ({code}) : {rep.get('message')}")


def action_supprimer(cfg):
    titre("6. Supprimer un depot GitHub")
    warn("Suppression definitive cote GitHub. Le dossier local n'est pas touche.")
    login = cfg.get("login") or utilisateur_courant(cfg)
    if not login:
        return
    proprio = ask("Proprietaire", login)
    depot = ask("Nom du depot")
    code, rep = api("GET", f"/repos/{proprio}/{depot}", cfg)
    if code != 200:
        err(f"Depot introuvable ({code}) : {rep.get('message')}")
        return
    info(f"Trouve : {rep.get('full_name')} — {rep.get('html_url')}")
    if ask(f"Retape '{depot}' exactement pour confirmer la suppression") != depot:
        info("Annule.")
        return
    code, rep = api("DELETE", f"/repos/{proprio}/{depot}", cfg)
    if code == 204:
        ok(f"{proprio}/{depot} supprime.")
    elif code == 403:
        err("Refuse : le token n'a pas la portee 'delete_repo'.")
        info("Regenere un token en cochant delete_repo, puis choix 1.")
    else:
        err(f"Echec ({code}) : {rep.get('message')}")


def action_cloner(cfg):
    titre("7. Cloner un depot")
    url = ask("URL complete du depot (https://.../xxx.git)")
    dest_parent = ask("Dossier de destination", cfg.get("dernier_dossier", os.getcwd()))
    dest_parent = os.path.expandvars(os.path.expanduser(dest_parent.strip().strip('"')))
    os.makedirs(dest_parent, exist_ok=True)
    _, defaut_nom = owner_repo(url)
    dossier = ask("Nom du dossier local", defaut_nom or "depot")

    token = get_token(cfg, obligatoire=False)
    cible = injecter_token(url, token, cfg.get("login", "")) if token else url
    print(c(f"  $ git clone {masquer(cible)} {dossier}", "90"))
    p = subprocess.run(["git", "clone", cible, dossier], cwd=dest_parent,
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    for ligne in masquer((p.stdout or "") + (p.stderr or "")).strip().splitlines():
        print("     " + ligne)
    if p.returncode != 0:
        err("Clone echoue.")
        return
    chemin = os.path.join(dest_parent, dossier)
    # Nettoie l'URL pour ne pas laisser le token dans .git/config
    git("remote", "set-url", "origin", url, cwd=chemin, quiet=True)
    cfg["dernier_dossier"] = chemin
    sauver(cfg)
    ok(f"Clone dans {chemin}")

    if ask_yn("Ajouter un second remote (ex: depot entreprise) ?", False):
        nom2 = ask("Nom du remote", "entreprise")
        url2 = ask("URL du remote (https://.../entreprise/repo.git)")
        git("remote", "add", nom2, url2, cwd=chemin)
        ok(f"Remote '{nom2}' ajoute.")


def action_push_existant(cfg):
    titre("8. Push depuis un .git existant")
    chemin = choisir_dossier(cfg)
    if not chemin or not est_repo(chemin):
        err("Ce dossier n'est pas un depot git.")
        return

    rs = remotes(chemin)
    print()
    if rs:
        info("Remotes configures :")
        for r in rs:
            print(f"     {r:<12} -> {url_remote(r, chemin)}")
    else:
        warn("Aucun remote configure.")

    if not rs or ask_yn("Ajouter / modifier un remote ?", not rs):
        nom_remote = ask("Nom du remote", "origin" if not rs else "entreprise")
        url = ask("URL du depot (https://.../owner/repo.git)")
        if nom_remote in remotes(chemin):
            git("remote", "set-url", nom_remote, url, cwd=chemin)
        else:
            git("remote", "add", nom_remote, url, cwd=chemin)
    else:
        nom_remote = choisir_remote(chemin)

    branche = ask("Branche a pousser", branche_courante(chemin))
    res = assurer_branche(chemin, branche)
    if isinstance(res, str):
        branche = res
    elif not res:
        err("Impossible de se placer sur cette branche.")
        return

    gi = Path(chemin) / ".gitignore"
    if not gi.exists():
        warn("Aucun .gitignore — risque de pousser .venv, .env, caches...")
        if ask_yn("En creer un standard maintenant ?", True):
            gi.write_text(GITIGNORE, encoding="utf-8")
            ok(".gitignore cree")

    git("add", "-A", cwd=chemin)
    print()
    git("status", "--short", cwd=chemin)
    _, out, _ = git("status", "--porcelain", cwd=chemin, quiet=True)
    if out:
        message = ask("Message du commit", "Mise a jour")
        git("commit", "-m", message, cwd=chemin)
    else:
        info("Aucune modification a committer.")

    print()
    print("    1. Mettre a jour  (fetch + rebase, conserve l'historique distant)")
    print("    2. Ecraser        (force push, remplace le distant)")
    print("    3. Push simple    (echoue si le distant a de l'avance)")
    mode = ask("Mode", "1")

    if mode == "1":
        url = url_remote(nom_remote, chemin)
        token = get_token(cfg, obligatoire=False)
        cible = injecter_token(url, token, cfg.get("login", "")) if token else url
        r = subprocess.run(["git", "fetch", cible, branche], cwd=chemin,
                           capture_output=True, text=True)
        if r.returncode == 0:
            code, _, _ = git("rebase", "FETCH_HEAD", cwd=chemin)
            if code != 0:
                err("Conflit. Resous puis : git add . && git rebase --continue")
                return
        else:
            info("Branche absente du distant — premier push.")
        pousser(cfg, chemin, nom_remote, branche, force=False, amont=True)
    elif mode == "2":
        if ask("Tape ECRASER pour confirmer") != "ECRASER":
            info("Annule.")
            return
        pousser(cfg, chemin, nom_remote, branche, force=True, amont=True)
    else:
        pousser(cfg, chemin, nom_remote, branche, force=False, amont=True)


def action_etat(cfg):
    titre("9. Etat du depot local")
    chemin = choisir_dossier(cfg)
    if not chemin:
        return
    if not est_repo(chemin):
        warn("Pas un depot git (aucun .git).")
        return
    print()
    info(f"Branche : {branche_courante(chemin)}")
    for r in remotes(chemin):
        print(f"     {r:<12} -> {url_remote(r, chemin)}")
    print()
    git("status", "--short", "--branch", cwd=chemin)
    print()
    git("log", "--oneline", "-10", "--decorate", cwd=chemin)


def action_oublier(cfg):
    titre("10. Oublier le token enregistre")
    if cfg.pop("token", None):
        sauver(cfg)
        ok("Token supprime de ~/.gitmanager.json")
    else:
        info("Aucun token enregistre.")


# --------------------------------------------------------------------------
# Menu
# --------------------------------------------------------------------------

MENU = [
    ("Authentification GitHub + config git (nom, email, token)", action_auth),
    ("git init + creation du depot + premier push", action_init_push),
    ("Mettre a jour un depot existant (sans ecraser)", action_maj),
    ("Ecraser un depot existant (force push)", action_ecraser),
    ("Rendre un depot public / prive", action_visibilite),
    ("Supprimer un depot GitHub", action_supprimer),
    ("Cloner un depot depuis son URL", action_cloner),
    ("Push depuis un .git existant (maj / ecraser / simple)", action_push_existant),
    ("Voir l'etat du depot local", action_etat),
    ("Oublier le token enregistre", action_oublier),
]


def main():
    if not git_ok():
        sys.exit(1)
    cfg = charger()
    while True:
        titre("GESTIONNAIRE GIT / GITHUB")
        compte = cfg.get("login", "non connecte")
        jeton = "oui" if (cfg.get("token") or os.environ.get("GITHUB_TOKEN")) else "non"
        print(c(f"  Compte : {compte}    Token : {jeton}    "
                f"API : {cfg.get('api', DEFAULT_API)}", "90"))
        print()
        for i, (libelle, _) in enumerate(MENU, 1):
            print(f"   {i:>2}. {libelle}")
        print(f"   {'0':>2}. Quitter")
        print()
        choix = input(c("  Choix : ", "1;33")).strip()
        if choix in ("0", "q", "quit", "exit"):
            print("\n  A bientot.\n")
            return
        if choix.isdigit() and 1 <= int(choix) <= len(MENU):
            try:
                MENU[int(choix) - 1][1](cfg)
            except KeyboardInterrupt:
                print()
                warn("Operation interrompue.")
            except Exception as e:
                err(f"Erreur : {e}")
            pause()
        else:
            warn("Choix invalide.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Interrompu.\n")
