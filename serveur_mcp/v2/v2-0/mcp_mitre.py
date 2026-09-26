# Version 2.0 du serveur MCP MITRE ATT&CK - hybride Enterprise (IT) + ICS (OT).
"""MCP MITRE ATT&CK - serveur stdio exposant les matrices Enterprise et ICS.

Refonte complete du moteur de la v1.1. Le squelette est conserve (stdio
JSON-RPC, bibliotheque standard uniquement, journal d'audit JSONL, base
hybride cloisonnee par matrice) ; le coeur est reecrit :

  - lecture des DEUX modeles de detection ATT&CK (strategies/analytics des
    releases >= 18, champs herites des releases <= 17.1) ;
  - libelles de sources de logs assainis (champ `channel` filtre) ;
  - recherche par mots entiers racinises, score normalise [0..1] + preuves ;
  - redirection des identifiants revoques, resolue transitivement ;
  - numero de release ATT&CK rappele dans chaque reponse (`db_version`) ;
  - garde-fous de la v1.1 conserves : cache incomplet refuse, base preservee
    en cas d'echec de mise a jour, `--test` qui sort en erreur, arguments
    invalides documentes, normalisation des identifiants, homonymes de
    tactiques signales, alias `mitre_*`.

Usage:
  python mcp_mitre.py             Demarre le serveur MCP (stdio).
  python mcp_mitre.py --test      Verifie la base et sort en code 1 si KO.
  python mcp_mitre.py --no-audit  Demarre sans journal d'audit.
  python mcp_mitre.py --help      Affiche ce message.

Variables d'environnement:
  MITRE_CACHE   Repertoire du cache local     (defaut: MITRE_DB/ a cote du script).
  MITRE_LOGS    Repertoire du journal d'audit (defaut: Logs/ a cote du script).
"""

import json
import sys
import os
import re
import time
import queue
import logging
import threading
import urllib.request
from pathlib import Path
from datetime import datetime

for _s in (sys.stdin, sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

SERVER_NAME = "mcp-mitre-attack"
SERVER_VERSION = "2.0"

#  Sources : depot STIX canonique de MITRE (seul a porter le numero de release)

STIX_BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
SOURCES = (
    ("Enterprise", f"{STIX_BASE}/enterprise-attack/enterprise-attack.json",
     "enterprise-attack.json"),
    ("ICS", f"{STIX_BASE}/ics-attack/ics-attack.json", "ics-attack.json"),
)
MATRIX_NAMES = tuple(m for m, _, _ in SOURCES)

BASE_DIR = Path(__file__).resolve().parent
CACHE_DIR = Path(os.getenv("MITRE_CACHE", BASE_DIR / "MITRE_DB"))
LOGS_DIR = Path(os.getenv("MITRE_LOGS", BASE_DIR / "Logs"))
AUDIT_LOG_PATH = LOGS_DIR / "mcp_audit.jsonl"

#  Parametres de recherche, de sortie et de fraicheur

MAX_QUERY_LEN = 256
MAX_ID_LEN = 64
SEARCH_DEFAULT_LIMIT = 10
SEARCH_MAX_LIMIT = 40
SCORE_STRONG = 0.6            # >= : candidat fort
SCORE_WEAK = 0.3              # <  : correspondance faible
LIST_CAP = 20                 # plafond des listes annexes d'une technique
STALE_DAYS = 30
DOWNLOAD_TIMEOUT = 120
RETRY_COOLDOWN = 60           # secondes entre deux tentatives de rattrapage

# Un `channel` n'est retenu pour composer un libelle que s'il ressemble a un
# canal et non a une phrase : MITRE y publie parfois la logique de detection
# complete en texte libre (jusqu'a 225 caracteres).
CHANNEL_MAX_LEN = 40
NULL_LABELS = {"none", "n/a", "na", "-", "null", ""}

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s",
                    handlers=[logging.StreamHandler(sys.stderr)])
log = logging.getLogger("mcp-mitre")


#  Journal d'audit JSONL (thread dedie, jamais bloquant pour les reponses)

class AuditWriter:
    def __init__(self, path):
        self._q = queue.Queue(maxsize=10000)
        self._stop = threading.Event()
        self._f = None
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._f = open(path, "a", encoding="utf-8")
        except Exception as e:
            log.warning(f"Audit desactive ({e})")
            return
        self._t = threading.Thread(target=self._run, daemon=True, name="audit")
        self._t.start()

    def write(self, rec):
        if not self._f:
            return
        try:
            self._q.put_nowait(rec)
        except queue.Full:
            pass

    def _flush(self, batch):
        if not batch:
            return
        try:
            self._f.write("".join(json.dumps(r, ensure_ascii=False) + "\n"
                                  for r in batch))
            self._f.flush()
        except Exception as e:
            log.warning(f"Audit error: {e}")

    def _run(self):
        while not self._stop.is_set():
            try:
                batch = [self._q.get(timeout=1.0)]
            except queue.Empty:
                continue
            while True:
                try:
                    batch.append(self._q.get_nowait())
                except queue.Empty:
                    break
            self._flush(batch)
        batch = []                       # drain final : rien n'est perdu
        while True:
            try:
                batch.append(self._q.get_nowait())
            except queue.Empty:
                break
        self._flush(batch)
        try:
            self._f.close()
        except Exception:
            pass

    def shutdown(self):
        if not self._f:
            return
        self._stop.set()
        try:
            self._t.join(timeout=3.0)
        except Exception:
            pass


_audit = None if "--no-audit" in sys.argv else AuditWriter(AUDIT_LOG_PATH)


def audit(event, **data):
    if _audit:
        _audit.write({"ts": datetime.now().isoformat(), "event": event, **data})


#  Lexique : tokenisation, racinisation, nettoyage, normalisation

# Grammaire anglaise + boilerplate ATT&CK ("Adversaries may use...") qui ne
# discrimine rien puisque present dans presque toutes les descriptions.
_STOPWORDS = {
    "the", "and", "for", "via", "with", "that", "this", "from", "are", "was",
    "were", "will", "have", "has", "had", "not", "but", "when", "then", "than",
    "they", "their", "them", "there", "these", "those", "within", "upon",
    "into", "its", "also", "such", "may", "can", "could", "would", "should",
    "use", "used", "uses", "using", "usage", "other", "another",
    "adversary", "adversaries", "attacker", "attackers",
}

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_ID_IN_TEXT_RE = re.compile(r"\bt\d{4}(?:\.\d{1,3})?\b")
_SUBID_RE = re.compile(r"^(T\d{4})\.(\d{1,3})$")
_CITATION_RE = re.compile(r"\(Citation:[^)]*\)")
_MD_LINK_RE = re.compile(r"\[([^\]]*)\]\([^)]*\)")
_TAG_RE = re.compile(r"<[^>]{1,80}>")


def _stem(w: str) -> str:
    """Racinisation legere et SYMETRIQUE : la forme au singulier et la forme
    au pluriel doivent converger vers la meme racine, sinon une requete au
    singulier ne trouve pas un corpus au pluriel.

    Le suffixe 'es' n'est retire que derriere s/x/z/h/o ('processes',
    'classes'), sinon c'est le simple 's' qui part ('files' -> 'file'), puis
    un 'e' final ('file' -> 'fil', 'schedule' -> 'schedul'), ce qui aligne
    aussi les formes en -ed ('scheduled' -> 'schedul').
    'ss' est protege : 'access' ne devient pas 'acces'."""
    prev = None
    while w != prev:
        prev = w
        if w.endswith("ing") and len(w) - 3 >= 3:
            w = w[:-3]
            continue
        if w.endswith("ed") and len(w) - 2 >= 3:
            w = w[:-2]
            continue
        if w.endswith("es") and len(w) - 2 >= 3 and w[-3] in "sxzho":
            w = w[:-2]
            continue
        if w.endswith("s") and not w.endswith("ss") and len(w) - 1 >= 3:
            w = w[:-1]
            continue
        if w.endswith("e") and len(w) - 1 >= 3:
            w = w[:-1]
            continue
    return w


def _tokens(text: str) -> set:
    """Tokens significatifs racinises. Les tokens contenant un chiffre
    (4688, t1003, sha256, c2) sont gardes des 2 caracteres et non racinises."""
    out = set()
    for w in _TOKEN_RE.findall((text or "").lower()):
        if w in _STOPWORDS:
            continue
        if any(c.isdigit() for c in w):
            if len(w) >= 2:
                out.add(w)
            continue
        if len(w) < 3:
            continue
        s = _stem(w)
        if s not in _STOPWORDS:
            out.add(s)
    return out


def _clean_text(d: str) -> str:
    d = _CITATION_RE.sub(" ", d or "")
    d = _MD_LINK_RE.sub(r"\1", d)
    d = _TAG_RE.sub(" ", d)
    return d


def _snippet(description: str, max_len: int = 220) -> str:
    d = " ".join(_clean_text(description).split())
    cut = d.find(". ")
    s = d[: cut + 1] if 0 < cut < max_len else d[:max_len]
    return s.strip()


def _norm_id(value: str) -> str:
    """T1059.1, t1059.01 et T1059.001 designent la meme sous-technique ;
    MITRE ne connait que la forme a trois decimales."""
    v = (value or "").strip().upper().replace(" ", "")
    m = _SUBID_RE.match(v)
    if m:
        return f"{m.group(1)}.{int(m.group(2)):03d}"
    return v


def _validate(value, max_len: int, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"'{field}' doit etre une chaine")
    value = value.strip()
    if len(value) > max_len:
        raise ValueError(f"'{field}' depasse {max_len} caracteres")
    if any(ord(c) < 32 for c in value):
        raise ValueError(f"'{field}' contient des caracteres de controle")
    return value


_MATRIX_ALIASES = {
    "enterprise": "Enterprise", "ent": "Enterprise", "it": "Enterprise",
    "ics": "ICS", "ot": "ICS", "scada": "ICS", "industriel": "ICS",
}


def _matrix(value: str):
    """Normalise un filtre de matrice. Une valeur non reconnue leve une
    erreur explicite : la v1.1 renvoyait silencieusement zero resultat."""
    if not value:
        return None
    v = _validate(value, 24, "matrix").lower()
    if not v:
        return None
    if v in _MATRIX_ALIASES:
        return _MATRIX_ALIASES[v]
    raise ValueError(
        f"matrice '{value}' inconnue - valeurs acceptees : "
        f"Enterprise, ICS (ou IT, OT, SCADA)")


def _label_ok(s: str) -> bool:
    return bool(s) and s.strip().lower() not in NULL_LABELS


def _channel_ok(ch: str) -> bool:
    """Un canal exploitable est court et sans espace ('socket/connect',
    'EventCode=4688'). Au-dela, MITRE y met de la prose : on l'ignore."""
    ch = (ch or "").strip()
    return (_label_ok(ch) and len(ch) <= CHANNEL_MAX_LEN and " " not in ch)


def J(o):
    return json.dumps(o, ensure_ascii=False, separators=(",", ":"))


def _capped(ids, resolve, cap=LIST_CAP):
    """Liste annexe bornee : total exact, elements resolus, drapeau."""
    items = [resolve(x) for x in ids[:cap]]
    items = [x for x in items if x]
    return {"count": len(ids), "items": items, "truncated": len(ids) > cap}


#  Base de connaissance MITRE ATT&CK (Enterprise + ICS)

class MitreDB:

    def __init__(self, autoload=True):
        self.tactics = {}       # TA0006     -> dict (matrix: chaine)
        self.techniques = {}    # T1003      -> dict (matrix: chaine)
        self.mitigations = {}   # M1027      -> dict (matrix: chaine)
        self.groups = {}        # G0016      -> dict (matrices: liste)
        self.software = {}      # S0002      -> dict (matrices: liste)
        self.datasources = {}   # libelle    -> set(ids de techniques)
        self.redirects = {}     # id revoque -> {replaced_by, name, alive}
        self.order = {}         # matrice    -> [ids de tactiques, ordre officiel]
        self.versions = {}      # matrice    -> {release, modified, source, fetched}
        self.loaded_at = ""
        self.ready = False
        self._last_try = 0.0
        self._lock = threading.Lock()
        if autoload:
            self.load_or_download()

    #  Etat

    def matrices_chargees(self):
        return [m for m in MATRIX_NAMES
                if any(t["matrix"] == m for t in self.techniques.values())]

    def liens_tactiques(self, matrix=None):
        return sum(len(t["tactics"]) for t in self.techniques.values()
                   if matrix is None or t["matrix"] == matrix)

    def check(self):
        """Une base n'est declaree prete que si CHAQUE matrice attendue est
        presente, peuplee, et reliee a ses tactiques. Sans ce controle, un
        cache tronque ferait demarrer le serveur sur une base amputee : le
        modele mapperait des signaux IT dans la matrice industrielle sans
        aucun moyen de s'en apercevoir."""
        problemes = []
        for m in MATRIX_NAMES:
            n = sum(1 for t in self.techniques.values() if t["matrix"] == m)
            if not n:
                problemes.append(f"matrice {m} absente ou vide")
                continue
            if m not in self.versions:
                problemes.append(f"matrice {m} sans metadonnees de release")
            if not self.liens_tactiques(m):
                problemes.append(f"matrice {m} sans lien tactique-technique")
        if not self.datasources:
            problemes.append("index des sources de donnees vide")
        return problemes

    def age_days(self):
        ts = [v.get("fetched") for v in self.versions.values() if v.get("fetched")]
        if not ts:
            return None
        try:
            oldest = min(datetime.fromisoformat(t) for t in ts)
            return round((datetime.now() - oldest).total_seconds() / 86400, 1)
        except Exception:
            return None

    #  Chargement

    def load_or_download(self):
        for matrix, url, fname in SOURCES:
            path = CACHE_DIR / fname
            if not self._load_file(path, matrix):
                self._fetch(matrix, url, path, commit=True)
        self._finalize()
        self._settle()

    def _settle(self):
        self.loaded_at = datetime.now().isoformat()
        problemes = self.check()
        self.ready = not problemes
        if problemes:
            log.error("Base incomplete : " + " | ".join(problemes))
            audit("db_incomplete", problemes=problemes)

    def _load_file(self, path, matrix) -> bool:
        if not (path.exists() and path.stat().st_size > 0):
            return False
        try:
            stix = json.loads(path.read_text(encoding="utf-8"))
            self._parse(stix, matrix, source="cache")
        except Exception as e:
            log.warning(f"Cache {matrix} illisible ({e}) : retelechargement")
            audit("cache_invalid", matrix=matrix, error=str(e))
            return False
        n = sum(1 for t in self.techniques.values() if t["matrix"] == matrix)
        if not n:
            log.warning(f"Cache {matrix} sans technique : retelechargement")
            audit("cache_incomplete", matrix=matrix)
            self._purge(matrix)
            return False
        rel = self.versions.get(matrix, {}).get("release", "?")
        log.info(f"Cache {matrix} charge : {n} techniques (release {rel}).")
        audit("db_loaded", matrix=matrix, source="cache", release=rel,
              techniques=n)
        return True

    def _purge(self, matrix):
        """Retire tout ce qui provient d'une matrice dont le chargement a
        echoue, pour ne pas laisser de residus avant retelechargement."""
        for store in (self.tactics, self.techniques, self.mitigations):
            for k in [k for k, v in store.items() if v.get("matrix") == matrix]:
                del store[k]
        for store in (self.groups, self.software):
            for k, v in list(store.items()):
                if matrix in v["matrices"]:
                    v["matrices"].remove(matrix)
                if not v["matrices"]:
                    del store[k]
        self.versions.pop(matrix, None)
        self.order.pop(matrix, None)

    def _fetch(self, matrix, url, path, commit=True):
        """Telecharge et analyse un bundle. commit=True ecrit le cache
        (remplacement atomique). Renvoie (ok, message, raw)."""
        try:
            log.info(f"Telechargement MITRE {matrix}...")
            audit("download_start", matrix=matrix, url=url)
            t0 = time.time()
            req = urllib.request.Request(
                url, headers={"User-Agent": f"MCP-MITRE/{SERVER_VERSION}"})
            with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT) as r:
                raw = r.read()
            stix = json.loads(raw)
            self._parse(stix, matrix, source="download")
            if commit:
                self._write_cache(path, raw)
            ms = int((time.time() - t0) * 1000)
            rel = self.versions.get(matrix, {}).get("release", "?")
            log.info(f"MITRE {matrix} pret (release {rel}, {ms} ms).")
            audit("download_complete", matrix=matrix, duration_ms=ms,
                  release=rel)
            return True, "ok", raw
        except Exception as e:
            log.error(f"Telechargement {matrix} echoue : {e}")
            audit("download_error", matrix=matrix, error=str(e))
            return False, str(e), None

    @staticmethod
    def _write_cache(path, raw):
        try:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(raw)
            tmp.replace(path)          # atomique : jamais de JSON tronque
        except Exception as e:
            log.warning(f"Cache non ecrit : {e}")

    def ensure(self):
        """Rattrapage si la base n'est pas prete, avec temporisation : la
        v1.1 relancait un telechargement complet a CHAQUE appel d'outil."""
        if self.ready:
            return True
        with self._lock:
            if self.ready:
                return True
            if time.time() - self._last_try < RETRY_COOLDOWN:
                return False
            self._last_try = time.time()
            for matrix, url, fname in SOURCES:
                if matrix not in self.matrices_chargees():
                    self._purge(matrix)
                    self._fetch(matrix, url, CACHE_DIR / fname, commit=True)
            self._finalize()
            self._settle()
        return self.ready

    def adopt(self, other):
        """Remplace le contenu par celui d'une base fraichement construite."""
        for a in ("tactics", "techniques", "mitigations", "groups", "software",
                  "datasources", "redirects", "order", "versions"):
            setattr(self, a, getattr(other, a))
        self.loaded_at = datetime.now().isoformat()
        self.ready = not self.check()

    #  Parsing STIX : deux passes (collecter, puis relier)

    @staticmethod
    def _ext_id(o) -> str:
        for r in o.get("external_references", []):
            if (r.get("source_name") in ("mitre-attack", "mitre-ics-attack")
                    and r.get("external_id")):
                return r["external_id"]
        return ""

    @staticmethod
    def _url(o) -> str:
        for r in o.get("external_references", []):
            if "mitre" in r.get("source_name", "") and r.get("url"):
                return r["url"]
        return ""

    def _parse(self, stix, matrix, source=""):
        """PASSE 1 : tout collecter. PASSE 2 : tout relier. L'ordre des objets
        dans le bundle, et celui des matrices entre elles, sont indifferents."""
        sid2ext = {}       # id STIX -> id ATT&CK (objets revoques compris)
        revoked = {}       # id STIX revoque -> (id ATT&CK, nom)
        components = {}    # id STIX x-mitre-data-component -> nom
        strategies = {}    # id STIX detection-strategy -> {name, analytic_refs}
        analytics = {}     # id STIX analytic -> dict
        matrix_obj = None
        rels = []
        release = ""
        modified = ""

        for o in stix.get("objects", []):
            ot = o.get("type", "")

            if ot == "x-mitre-collection":
                release = o.get("x_mitre_version", "")
                modified = o.get("modified", "")
                continue
            if ot == "relationship":
                if not (o.get("revoked") or o.get("x_mitre_deprecated")):
                    rels.append(o)
                continue
            if ot == "x-mitre-matrix":
                matrix_obj = o
                continue

            aid = self._ext_id(o)
            if aid:
                sid2ext[o["id"]] = aid

            if o.get("revoked") or o.get("x_mitre_deprecated"):
                if ot == "attack-pattern" and aid:
                    revoked[o["id"]] = (aid, o.get("name", ""))
                # Les composants deprecies restent resolubles pour les
                # libelles herites, sans etre indexes pour eux-memes.
                if ot == "x-mitre-data-component":
                    components[o["id"]] = o.get("name", "")
                continue

            if ot == "x-mitre-tactic" and aid:
                self.tactics[aid] = {
                    "id": aid, "name": o.get("name", ""), "matrix": matrix,
                    "shortname": o.get("x_mitre_shortname", ""),
                    "description": o.get("description", ""),
                    "techniques": [], "url": self._url(o),
                }
            elif ot == "attack-pattern" and aid:
                desc = o.get("description", "")
                # Champs herites (releases <= 17.1) : "Command: Command
                # Execution" -> on ne garde que le composant.
                legacy_ds = set()
                for s in o.get("x_mitre_data_sources", []):
                    lab = s.split(":", 1)[-1].strip() if ":" in s else s.strip()
                    if _label_ok(lab):
                        legacy_ds.add(lab)
                self.techniques[aid] = {
                    "id": aid, "name": o.get("name", ""), "matrix": matrix,
                    "technique_version": o.get("x_mitre_version", ""),
                    "is_subtechnique": bool(o.get("x_mitre_is_subtechnique")),
                    "parent_id": aid.split(".")[0] if "." in aid else None,
                    "subtechniques": [], "description": desc,
                    "platforms": o.get("x_mitre_platforms", []),
                    "phases": [k.get("phase_name", "")
                               for k in o.get("kill_chain_phases", [])],
                    "tactics": [], "detections": [],
                    "data_sources": legacy_ds,
                    "legacy_detection": o.get("x_mitre_detection", ""),
                    "mitigations": [], "groups": [], "software": [],
                    "url": self._url(o),
                    "_tok_name": _tokens(o.get("name", "")),
                    "_tok_desc": _tokens(_clean_text(desc)),
                    "_snippet": _snippet(desc),
                }
            elif ot == "course-of-action" and aid:
                self.mitigations[aid] = {
                    "id": aid, "name": o.get("name", ""), "matrix": matrix,
                    "description": o.get("description", ""),
                    "techniques": [], "url": self._url(o),
                }
            elif ot == "intrusion-set" and aid:
                g = self.groups.setdefault(aid, {
                    "id": aid, "name": o.get("name", ""),
                    "description": o.get("description", ""),
                    "aliases": o.get("aliases", []),
                    "matrices": [], "techniques": [], "software": [],
                    "url": self._url(o),
                })
                if matrix not in g["matrices"]:
                    g["matrices"].append(matrix)
            elif ot in ("malware", "tool") and aid:
                s = self.software.setdefault(aid, {
                    "id": aid, "name": o.get("name", ""), "type": ot,
                    "description": o.get("description", ""),
                    "platforms": o.get("x_mitre_platforms", []),
                    "aliases": o.get("x_mitre_aliases", o.get("aliases", [])),
                    "matrices": [], "techniques": [], "url": self._url(o),
                })
                if matrix not in s["matrices"]:
                    s["matrices"].append(matrix)
            elif ot == "x-mitre-data-component":
                components[o["id"]] = o.get("name", "")
            elif ot == "x-mitre-detection-strategy":
                strategies[o["id"]] = {
                    "id": aid, "name": o.get("name", ""),
                    "analytic_refs": o.get("x_mitre_analytic_refs", []),
                }
            elif ot == "x-mitre-analytic":
                analytics[o["id"]] = {
                    "name": o.get("name", ""),
                    "description": _snippet(o.get("description", ""), 300),
                    "platforms": o.get("x_mitre_platforms", []),
                    "log_sources": [], "components": [],
                    "_refs": o.get("x_mitre_log_source_references", []),
                }

        # Les composants peuvent etre publies apres les analytics : on resout
        # les references une fois le bundle entierement collecte.
        for a in analytics.values():
            for ref in a.pop("_refs"):
                nm = (ref.get("name") or "").strip()
                ch = (ref.get("channel") or "").strip()
                if _label_ok(nm):
                    if nm not in a["log_sources"]:
                        a["log_sources"].append(nm)
                    if _channel_ok(ch):
                        composite = f"{nm}:{ch}"
                        if composite not in a["log_sources"]:
                            a["log_sources"].append(composite)
                comp = components.get(ref.get("x_mitre_data_component_ref", ""), "")
                if _label_ok(comp) and comp not in a["components"]:
                    a["components"].append(comp)

        # --- Ordre officiel de la kill chain, lu dans l'objet publie --------
        if matrix_obj:
            order = [sid2ext[r] for r in matrix_obj.get("tactic_refs", [])
                     if r in sid2ext and sid2ext[r] in self.tactics]
        else:
            order = []
        self.order[matrix] = order or sorted(
            t for t, v in self.tactics.items() if v["matrix"] == matrix)

        # --- PASSE 2a : tactiques <-> techniques, CLOISONNE PAR MATRICE -----
        # Les shortnames ("persistence", "execution"...) existent dans les
        # deux matrices : sans cloisonnement, une technique industrielle
        # serait rattachee a la tactique Enterprise homonyme.
        short2ta = {v["shortname"]: k for k, v in self.tactics.items()
                    if v["matrix"] == matrix and v["shortname"]}
        for tid, t in self.techniques.items():
            if t["matrix"] != matrix:
                continue
            for phase in t["phases"]:
                ta = short2ta.get(phase)
                if ta and tid not in self.tactics[ta]["techniques"]:
                    self.tactics[ta]["techniques"].append(tid)
                    t["tactics"].append({"id": ta,
                                         "name": self.tactics[ta]["name"]})

        # --- PASSE 2b : relations STIX --------------------------------------
        linked_subs = set()
        for o in rels:
            rt = o.get("relationship_type", "")
            src, tgt = o.get("source_ref", ""), o.get("target_ref", "")

            if rt == "revoked-by" and src in revoked:
                old_id, old_name = revoked[src]
                new_id = sid2ext.get(tgt, "")
                if new_id:
                    self.redirects[old_id] = {"replaced_by": new_id,
                                              "name": old_name}
                continue

            if rt == "detects":
                # Modele courant (releases >= 18) : strategie -> technique
                if src in strategies:
                    t = self.techniques.get(sid2ext.get(tgt, ""))
                    if t is not None:
                        st = strategies[src]
                        t["detections"].append({
                            "id": st["id"], "strategy": st["name"],
                            "analytics": [analytics[a] for a in st["analytic_refs"]
                                          if a in analytics],
                        })
                    continue
                # Modele herite (releases <= 17.1) : composant -> technique
                if src in components:
                    t = self.techniques.get(sid2ext.get(tgt, ""))
                    if t is not None and _label_ok(components[src]):
                        t["data_sources"].add(components[src])
                    continue
                continue

            s_ext, t_ext = sid2ext.get(src, ""), sid2ext.get(tgt, "")
            if not s_ext or not t_ext:
                continue
            if rt == "subtechnique-of" and s_ext in self.techniques:
                p = self.techniques.get(t_ext)
                if p is not None:
                    self.techniques[s_ext]["parent_id"] = t_ext
                    if s_ext not in p["subtechniques"]:
                        p["subtechniques"].append(s_ext)
                    linked_subs.add(s_ext)
            elif (rt == "mitigates" and s_ext in self.mitigations
                    and t_ext in self.techniques):
                if t_ext not in self.mitigations[s_ext]["techniques"]:
                    self.mitigations[s_ext]["techniques"].append(t_ext)
                if s_ext not in self.techniques[t_ext]["mitigations"]:
                    self.techniques[t_ext]["mitigations"].append(s_ext)
            elif rt == "uses" and t_ext in self.techniques:
                if s_ext in self.groups:
                    if t_ext not in self.groups[s_ext]["techniques"]:
                        self.groups[s_ext]["techniques"].append(t_ext)
                    if s_ext not in self.techniques[t_ext]["groups"]:
                        self.techniques[t_ext]["groups"].append(s_ext)
                elif s_ext in self.software:
                    if t_ext not in self.software[s_ext]["techniques"]:
                        self.software[s_ext]["techniques"].append(t_ext)
                    if s_ext not in self.techniques[t_ext]["software"]:
                        self.techniques[t_ext]["software"].append(s_ext)
            elif (rt == "uses" and s_ext in self.groups
                    and t_ext in self.software):
                if t_ext not in self.groups[s_ext]["software"]:
                    self.groups[s_ext]["software"].append(t_ext)

        # Repli par numerotation pour une sous-technique sans relation.
        for tid, t in self.techniques.items():
            if (t["matrix"] == matrix and t["is_subtechnique"]
                    and tid not in linked_subs):
                p = self.techniques.get(t["parent_id"])
                if p and tid not in p["subtechniques"]:
                    p["subtechniques"].append(tid)

        # --- Index des sources de donnees : libelles complets ---------------
        for tid, t in self.techniques.items():
            if t["matrix"] != matrix:
                continue
            labels = {s.strip() for s in t["data_sources"] if _label_ok(s)}
            for det in t["detections"]:
                for a in det["analytics"]:
                    labels.update(x.strip() for x in a["log_sources"])
                    labels.update(x.strip() for x in a["components"])
            t["data_sources"] = labels
            for label in labels:
                self.datasources.setdefault(label, set()).add(tid)

        self.versions[matrix] = {
            "release": release, "modified": modified,
            "source": "attack-stix-data", "fetched": datetime.now().isoformat(),
            "detection_model": ("strategies" if strategies else
                                ("herite" if any(
                                    t["data_sources"] for t in self.techniques.values()
                                    if t["matrix"] == matrix) else "absent")),
        }

    def _finalize(self):
        """Post-traitement commun aux deux matrices."""
        # Redirections resolues TRANSITIVEMENT : MITRE chaine parfois deux
        # revocations (T1073 -> T1574.002 -> T1574.001). Sans cela, le modele
        # recoit une redirection vers un identifiant lui aussi revoque.
        for old in list(self.redirects):
            cur = self.redirects[old]["replaced_by"]
            seen = {old}
            hops = 0
            while cur in self.redirects and cur not in seen and hops < 10:
                seen.add(cur)
                cur = self.redirects[cur]["replaced_by"]
                hops += 1
            self.redirects[old]["replaced_by"] = cur
            self.redirects[old]["alive"] = cur in self.techniques
        for t in self.techniques.values():
            t["subtechniques"].sort()
        for ta in self.tactics.values():
            ta["techniques"].sort()


db = MitreDB()


def _db_version() -> dict:
    v = {m: x.get("release", "") for m, x in db.versions.items()}
    return v or {"note": "base vide"}


def _resolve(store, q):
    """Resolution par identifiant, nom exact, alias, puis nom partiel.
    Le mode est TOUJOURS rendu : la v1.1 renvoyait un match partiel
    arbitraire sans dire que la correspondance etait approximative."""
    if not q:
        return None, None, []
    k = q.strip().upper()
    if k in store:
        return store[k], "id", []
    ql = q.strip().lower()
    for v in store.values():
        if v["name"].lower() == ql:
            return v, "nom", []
    for v in store.values():
        if any((a or "").lower() == ql for a in v.get("aliases", [])):
            return v, "alias", []
    cands = [v for v in store.values() if ql in v["name"].lower()]
    if cands:
        cands.sort(key=lambda v: (len(v["name"]), v["id"]))
        return cands[0], "partiel", [{"id": c["id"], "name": c["name"]}
                                     for c in cands[:10]]
    return None, None, []


#  Outils MCP

TOOLS = {}
ALIASES = {}


def tool(name, desc, params=None, aliases=()):
    def deco(fn):
        props, req = {}, []
        for pn, (pt, rq, pd) in (params or {}).items():
            props[pn] = {"type": pt, "description": pd}
            if rq:
                req.append(pn)
        TOOLS[name] = {"handler": fn,
                       "schema": {"name": name, "description": desc,
                                  "inputSchema": {"type": "object",
                                                  "properties": props,
                                                  "required": req}}}
        for a in aliases:
            ALIASES[a] = name
        return fn
    return deco


@tool("get_tactics",
      "Les tactiques ATT&CK dans l'ordre officiel de la kill chain, par "
      "matrice. Sans argument : les deux matrices.",
      {"matrix": ("string", False, "Enterprise, ICS, ou vide pour les deux")},
      aliases=("mitre_tactics",))
def get_tactics(matrix=""):
    want = _matrix(matrix)
    out = {}
    for mx in MATRIX_NAMES:
        if want and mx != want:
            continue
        out[mx] = [{"id": tid, "name": db.tactics[tid]["name"],
                    "shortname": db.tactics[tid]["shortname"],
                    "technique_count": len(db.tactics[tid]["techniques"])}
                   for tid in db.order.get(mx, []) if tid in db.tactics]
    return J({"db_version": _db_version(), "matrices": out})


@tool("get_tactic",
      "Une tactique et ses techniques. Accepte un identifiant ou un nom ; "
      "neuf noms existent dans les deux matrices (Persistence, Execution...) "
      "et doivent etre leves par l'argument matrix. L'homonyme est toujours "
      "signale.",
      {"id": ("string", True, "ex: TA0002, TA0110 ou Execution"),
       "matrix": ("string", False, "Enterprise ou ICS, pour lever un homonyme")},
      aliases=("mitre_tactic",))
def get_tactic(id, matrix=""):
    want = _matrix(matrix)
    q = _validate(id, MAX_ID_LEN, "id")
    store = {k: v for k, v in db.tactics.items()
             if not want or v["matrix"] == want}
    t, mode, cands = _resolve(store, q)
    if not t:
        return J({"error": f"Tactique '{q}' non trouvee",
                  "matrix_filtre": want or "aucun",
                  "db_version": _db_version()})
    twins = [{"id": x["id"], "matrix": x["matrix"]} for x in db.tactics.values()
             if x["name"].lower() == t["name"].lower() and x["id"] != t["id"]]
    techs = [tid for tid in t["techniques"] if tid in db.techniques]
    parents = [tid for tid in techs if not db.techniques[tid]["is_subtechnique"]]
    r = {"db_version": _db_version(), "id": t["id"], "name": t["name"],
         "matrix": t["matrix"], "description": _snippet(t["description"], 400),
         "technique_count": len(techs),
         "parent_technique_count": len(parents),
         "techniques": [{"id": tid, "name": db.techniques[tid]["name"],
                         "subtechniques": len(db.techniques[tid]["subtechniques"])}
                        for tid in parents],
         "url": t["url"]}
    if twins:
        r["homonyme_autre_matrice"] = twins
    if mode == "partiel":
        r["resolution"] = {"mode": "partiel", "candidats": cands}
    return J(r)


@tool("get_technique",
      "Detail complet d'une technique Enterprise (T1***) ou ICS (T0***), pour "
      "CONFIRMER un candidat de mapping : description, matrice, tactiques, "
      "plateformes, detections (strategies + analytics + sources de logs), "
      "sous-techniques, groupes, software, mitigations. Un identifiant "
      "revoque est redirige vers son remplacant vivant.",
      {"id": ("string", True, "ex: T1059.001, t1059.1 ou T0831")},
      aliases=("mitre_technique",))
def get_technique(id):
    tid = _norm_id(_validate(id, MAX_ID_LEN, "id"))
    t = db.techniques.get(tid)
    if not t:
        r = db.redirects.get(tid)
        if r:
            return J({"db_version": _db_version(), "redirect": True,
                      "requested": tid, "name": r["name"],
                      "replaced_by": r["replaced_by"],
                      "remplacant_vivant": r.get("alive", False),
                      "note": f"'{tid}' est revoquee : consulter "
                              f"{r['replaced_by']} via get_technique"})
        return J({"error": f"Technique '{tid}' non trouvee",
                  "db_version": _db_version()})
    return J({
        "db_version": _db_version(),
        "id": t["id"], "name": t["name"], "matrix": t["matrix"],
        "technique_version": t["technique_version"],
        "is_subtechnique": t["is_subtechnique"],
        "parent": ({"id": t["parent_id"],
                    "name": db.techniques[t["parent_id"]]["name"]}
                   if t["is_subtechnique"] and t["parent_id"] in db.techniques
                   else None),
        "tactics": t["tactics"], "platforms": t["platforms"],
        "description": _clean_text(t["description"]).strip(),
        "detections": t["detections"],
        "legacy_detection": t["legacy_detection"],
        "data_sources": sorted(t["data_sources"]),
        "subtechniques": [{"id": s, "name": db.techniques[s]["name"]}
                          for s in t["subtechniques"] if s in db.techniques],
        "groups": _capped(t["groups"], lambda g: {
            "id": g, "name": db.groups[g]["name"],
            "matrices": db.groups[g]["matrices"]} if g in db.groups else None),
        "software": _capped(t["software"], lambda s: {
            "id": s, "name": db.software[s]["name"],
            "type": db.software[s]["type"]} if s in db.software else None),
        "mitigations": _capped(t["mitigations"], lambda m: {
            "id": m, "name": db.mitigations[m]["name"]}
            if m in db.mitigations else None),
        "url": t["url"],
    })


@tool("get_mitigations",
      "Les contre-mesures officielles associees a une technique, avec leur "
      "description. Chemin inverse de get_mitigation.",
      {"technique_id": ("string", True, "ex: T1059.001 ou T0831")},
      aliases=("mitre_mitigations",))
def get_mitigations(technique_id):
    tid = _norm_id(_validate(technique_id, MAX_ID_LEN, "technique_id"))
    t = db.techniques.get(tid)
    if not t:
        r = db.redirects.get(tid)
        if r:
            return J({"db_version": _db_version(), "redirect": True,
                      "requested": tid, "replaced_by": r["replaced_by"]})
        return J({"error": f"Technique '{tid}' non trouvee",
                  "db_version": _db_version()})
    return J({"db_version": _db_version(), "technique": t["id"],
              "name": t["name"], "matrix": t["matrix"],
              "count": len(t["mitigations"]),
              "mitigations": [{"id": m, "name": db.mitigations[m]["name"],
                               "matrix": db.mitigations[m]["matrix"],
                               "description": _snippet(
                                   db.mitigations[m]["description"], 400)}
                              for m in t["mitigations"] if m in db.mitigations]})


@tool("get_mitigation",
      "Detail d'une contre-mesure et de toutes les techniques qu'elle couvre. "
      "Accepte un identifiant Enterprise (M1***), ICS (M0***) ou un nom.",
      {"id": ("string", True, "ex: M1043, M0801 ou Credential Access Protection")},
      aliases=("mitre_mitigation",))
def get_mitigation(id):
    q = _validate(id, MAX_ID_LEN, "id")
    m, mode, cands = _resolve(db.mitigations, q)
    if not m:
        return J({"error": f"Mitigation '{q}' non trouvee",
                  "db_version": _db_version()})
    r = {"db_version": _db_version(), "id": m["id"], "name": m["name"],
         "matrix": m["matrix"],
         "description": _clean_text(m["description"]).strip(),
         "techniques": _capped(sorted(m["techniques"]), lambda t: {
             "id": t, "name": db.techniques[t]["name"],
             "matrix": db.techniques[t]["matrix"]}
             if t in db.techniques else None, cap=50),
         "url": m["url"]}
    if mode == "partiel":
        r["resolution"] = {"mode": "partiel", "candidats": cands}
    return J(r)


@tool("get_groups",
      "Groupes APT. Sans argument : top 50 par nombre de techniques. Avec "
      "technique_id : les groupes connus pour utiliser cette technique.",
      {"technique_id": ("string", False, "ID technique (optionnel)"),
       "matrix": ("string", False, "Restreint aux groupes actifs sur une matrice")},
      aliases=("mitre_groups",))
def get_groups(technique_id="", matrix=""):
    want = _matrix(matrix)
    if technique_id:
        tid = _norm_id(_validate(technique_id, MAX_ID_LEN, "technique_id"))
        t = db.techniques.get(tid)
        if not t:
            return J({"error": f"Technique '{tid}' non trouvee",
                      "db_version": _db_version()})
        ids = [g for g in t["groups"] if g in db.groups
               and (not want or want in db.groups[g]["matrices"])]
        return J({"db_version": _db_version(), "technique": tid,
                  "matrix": t["matrix"],
                  "groups": _capped(ids, lambda g: {
                      "id": g, "name": db.groups[g]["name"],
                      "matrices": db.groups[g]["matrices"],
                      "aliases": db.groups[g]["aliases"][:5]}, cap=30)})
    pool = [g for g in db.groups.values()
            if not want or want in g["matrices"]]
    top = sorted(pool, key=lambda g: (-len(g["techniques"]), g["id"]))[:50]
    return J({"db_version": _db_version(), "matrix_filtre": want or "aucun",
              "count": len(pool),
              "groups": [{"id": g["id"], "name": g["name"],
                          "matrices": g["matrices"],
                          "aliases": g["aliases"][:5],
                          "technique_count": len(g["techniques"])}
                         for g in top]})


@tool("get_group",
      "Detail d'un groupe APT, par identifiant, nom ou alias publie. Les "
      "techniques sont annotees de leur matrice : un groupe hybride en a dans "
      "les deux.",
      {"id": ("string", True, "ex: G0034, Sandworm Team ou ELECTRUM")},
      aliases=("mitre_group",))
def get_group(id):
    q = _validate(id, MAX_ID_LEN, "id")
    g, mode, cands = _resolve(db.groups, q)
    if not g:
        return J({"error": f"Groupe '{q}' non trouve",
                  "db_version": _db_version()})
    r = {"db_version": _db_version(), "id": g["id"], "name": g["name"],
         "matrices": g["matrices"], "aliases": g["aliases"],
         "description": _snippet(g["description"], 400),
         "techniques": _capped(sorted(g["techniques"]), lambda t: {
             "id": t, "name": db.techniques[t]["name"],
             "matrix": db.techniques[t]["matrix"]}
             if t in db.techniques else None, cap=50),
         "software": _capped(sorted(g["software"]), lambda s: {
             "id": s, "name": db.software[s]["name"]}
             if s in db.software else None),
         "url": g["url"]}
    if mode == "partiel":
        r["resolution"] = {"mode": "partiel", "candidats": cands}
    return J(r)


@tool("get_software",
      "Software/malware. Sans argument : top 50. Avec un ID de technique : "
      "les software associes. Avec un ID S**** ou un nom : la fiche detaillee.",
      {"technique_id": ("string", False, "ID technique, ID software ou nom")},
      aliases=("mitre_software",))
def get_software(technique_id=""):
    q = _validate(technique_id, MAX_ID_LEN, "technique_id") if technique_id else ""
    if q:
        t = db.techniques.get(_norm_id(q))
        if t:
            return J({"db_version": _db_version(), "technique": t["id"],
                      "matrix": t["matrix"],
                      "software": _capped(t["software"], lambda s: {
                          "id": s, "name": db.software[s]["name"],
                          "type": db.software[s]["type"],
                          "matrices": db.software[s]["matrices"]}
                          if s in db.software else None, cap=30)})
        sw, mode, cands = _resolve(db.software, q)
        if sw:
            r = {"db_version": _db_version(), "id": sw["id"], "name": sw["name"],
                 "type": sw["type"], "matrices": sw["matrices"],
                 "aliases": sw["aliases"], "platforms": sw["platforms"],
                 "description": _snippet(sw["description"], 400),
                 "techniques": _capped(sorted(sw["techniques"]), lambda t: {
                     "id": t, "name": db.techniques[t]["name"],
                     "matrix": db.techniques[t]["matrix"]}
                     if t in db.techniques else None, cap=50),
                 "url": sw["url"]}
            if mode == "partiel":
                r["resolution"] = {"mode": "partiel", "candidats": cands}
            return J(r)
        return J({"error": f"'{q}' non trouve", "db_version": _db_version()})
    top = sorted(db.software.values(),
                 key=lambda s: (-len(s["techniques"]), s["id"]))[:50]
    return J({"db_version": _db_version(), "count": len(db.software),
              "software": [{"id": s["id"], "name": s["name"], "type": s["type"],
                            "matrices": s["matrices"],
                            "technique_count": len(s["techniques"])}
                           for s in top]})


@tool("get_datasources",
      "Techniques observables a partir d'une source de donnees, d'un "
      "composant ou d'un canal de logs. Requetes valides : Process Creation, "
      "WinEventLog:Security, auditd:SYSCALL, AWS:CloudTrail.",
      {"query": ("string", True, "ex: Process Creation, auditd, WinEventLog"),
       "matrix": ("string", False, "Restreint a Enterprise ou ICS")},
      aliases=("mitre_datasources",))
def get_datasources(query, matrix=""):
    want = _matrix(matrix)
    q = _validate(query, 128, "query").lower()
    if not q:
        return J({"error": "query vide", "db_version": _db_version()})
    matches = {n: tids for n, tids in db.datasources.items() if q in n.lower()}
    techs = {}
    for tids in matches.values():
        for tid in tids:
            if tid in techs or tid not in db.techniques:
                continue
            t = db.techniques[tid]
            if want and t["matrix"] != want:
                continue
            techs[tid] = {"id": tid, "name": t["name"], "matrix": t["matrix"],
                          "tactics": [x["id"] for x in t["tactics"]]}
    ordered = sorted(techs.values(), key=lambda x: x["id"])
    return J({"db_version": _db_version(), "query": query,
              "matrix_filtre": want or "aucun",
              "matched_sources": sorted(matches)[:40],
              "source_count": len(matches),
              "techniques": {"count": len(ordered), "items": ordered[:60],
                             "truncated": len(ordered) > 60}})


@tool("search_techniques",
      "Recherche LEXICALE de techniques candidates (mots entiers racinises, "
      "pas de semantique). METHODE : 1) UNE requete = UN comportement "
      "atomique, en mots-cles ANGLAIS ATT&CK (ex 'lsass credential "
      "dumping'). 2) Les resultats sont des CANDIDATS avec un score "
      "normalise [0..1] - >= 0.6 fort, < 0.3 faible - et des preuves "
      "(matched.name / matched.description). 3) VERIFIER chaque candidat "
      "retenu avec get_technique avant d'affirmer un mapping ; retenir la "
      "technique PARENTE par defaut, la sous-technique seulement si "
      "l'evidence la confirme. 4) Une liste vide ou uniquement des scores "
      "faibles signifie 'pas de mapping' : conclusion valide, ne pas forcer.",
      {"query": ("string", True, "Mots-cles ou identifiant (ex: T1003.001)"),
       "limit": ("integer", False,
                 f"Nombre max de resultats (defaut {SEARCH_DEFAULT_LIMIT}, "
                 f"max {SEARCH_MAX_LIMIT})"),
       "matrix": ("string", False, "Filtre Enterprise ou ICS (aussi IT/OT/SCADA)"),
       "platform": ("string", False, "Filtre plateforme (ex: Windows, Linux)"),
       "tactic": ("string", False,
                  "Filtre tactique (TAxxxx ou shortname ex 'credential-access')")},
      aliases=("mitre_search",))
def search_techniques(query, limit=SEARCH_DEFAULT_LIMIT, matrix="",
                      platform="", tactic=""):
    q = _validate(query, MAX_QUERY_LEN, "query")
    notes = []
    if not q:
        return J({"db_version": _db_version(), "query": query,
                  "result_count": 0, "total_matches": 0, "results": [],
                  "note": "requete vide"})
    try:
        n_limit = int(limit)
    except (TypeError, ValueError):
        n_limit = SEARCH_DEFAULT_LIMIT
        notes.append("limit invalide : valeur par defaut appliquee")
    if n_limit < 1 or n_limit > SEARCH_MAX_LIMIT:
        notes.append(f"limit ramene dans l'intervalle 1..{SEARCH_MAX_LIMIT}")
    n_limit = max(1, min(n_limit, SEARCH_MAX_LIMIT))

    fm = _matrix(matrix)
    fp = _validate(platform, 32, "platform").lower() if platform else ""
    ft = _validate(tactic, 32, "tactic").lower() if tactic else ""

    ql = q.lower()
    q_tok = _tokens(ql)
    m = _ID_IN_TEXT_RE.search(ql)
    id_like = _norm_id(m.group(0)) if m else None

    if id_like and id_like in db.redirects:
        r = db.redirects[id_like]
        notes.append(f"'{id_like}' ({r['name']}) est revoquee, remplacee par "
                     f"{r['replaced_by']} : recherche redirigee")
        id_like = r["replaced_by"]

    if not q_tok and not id_like:
        return J({"db_version": _db_version(), "query": q, "result_count": 0,
                  "total_matches": 0, "results": [],
                  "note": "aucun terme significatif dans la requete"})

    def keep(t):
        if fm and t["matrix"] != fm:
            return False
        if fp and not any(fp == p.lower() for p in t["platforms"]):
            return False
        if ft and not any(ft == ta["id"].lower()
                          or ft == db.tactics.get(ta["id"], {}).get("shortname", "")
                          for ta in t["tactics"]):
            return False
        return True

    scored = []
    n = max(len(q_tok), 1)
    for tid, t in db.techniques.items():
        if not keep(t):
            continue
        hit_name = q_tok & t["_tok_name"]
        hit_desc = (q_tok & t["_tok_desc"]) - hit_name
        score = 0.0
        matched = {}
        if id_like:
            if tid == id_like:
                score = 1.0
                matched["id"] = [tid]
            elif tid.startswith(id_like + ".") or id_like.startswith(tid + "."):
                score = max(score, 0.7)
                matched["id"] = [id_like]
        if hit_name or hit_desc:
            # Chaque token de la REQUETE compte une fois : le score mesure la
            # couverture de la requete, pas la longueur de la description.
            base = (1.0 * len(hit_name) + 0.35 * len(hit_desc)) / n
            if ql in t["name"].lower():
                base += 0.15
            score = max(score, min(base, 1.0))
            if hit_name:
                matched["name"] = sorted(hit_name)
            if hit_desc:
                matched["description"] = sorted(hit_desc)
        if score > 0:
            scored.append((round(score, 3), tid, t, matched))

    # A score egal : technique parente avant sous-technique (regle de
    # precision CISA/MITRE), puis identifiant croissant (determinisme).
    scored.sort(key=lambda x: (-x[0], x[2]["is_subtechnique"], x[1]))
    top = scored[:n_limit]
    results = [{"id": tid, "name": t["name"], "matrix": t["matrix"],
                "score": s, "is_subtechnique": t["is_subtechnique"],
                "parent_id": t["parent_id"],
                "tactics": [ta["id"] for ta in t["tactics"]],
                "matched": matched, "matched_in": sorted(matched),
                "snippet": t["_snippet"]}
               for s, tid, t, matched in top]

    if not results:
        notes.append("aucun candidat : l'absence de mapping est une "
                     "conclusion valide")
    elif results[0]["score"] < SCORE_WEAK:
        notes.append("correspondances faibles uniquement : l'absence de "
                     "mapping est une conclusion valide")
    out = {"db_version": _db_version(), "query": q,
           "query_tokens": sorted(q_tok),
           "filtres": {"matrix": fm or "aucun", "platform": platform or "aucun",
                       "tactic": tactic or "aucun"},
           "seuils": {"fort": SCORE_STRONG, "faible": SCORE_WEAK},
           "result_count": len(results), "total_matches": len(scored),
           "results": results}
    if notes:
        out["note"] = " | ".join(notes)
    return J(out)


@tool("mitre_stats",
      "Version du serveur, releases ATT&CK chargees, modele de detection "
      "detecte, fraicheur du cache et statistiques de la base hybride.")
def mitre_stats():
    parents = sum(1 for t in db.techniques.values() if not t["is_subtechnique"])
    age = db.age_days()
    per = {}
    for mx in MATRIX_NAMES:
        techs = [t for t in db.techniques.values() if t["matrix"] == mx]
        per[mx] = {
            "release": db.versions.get(mx, {}).get("release", ""),
            "detection_model": db.versions.get(mx, {}).get("detection_model", ""),
            "tactics": sum(1 for t in db.tactics.values() if t["matrix"] == mx),
            "techniques": len(techs),
            "with_detections": sum(1 for t in techs if t["detections"]),
            "with_data_sources": sum(1 for t in techs if t["data_sources"]),
            "mitigations": sum(1 for m in db.mitigations.values()
                               if m["matrix"] == mx),
            "groups": sum(1 for g in db.groups.values() if mx in g["matrices"]),
            "software": sum(1 for s in db.software.values() if mx in s["matrices"]),
            "tactic_links": db.liens_tactiques(mx),
        }
    return J({"server": SERVER_NAME, "server_version": SERVER_VERSION,
              "source": "attack-stix-data", "db_version": _db_version(),
              "ready": db.ready, "loaded_at": db.loaded_at,
              "cache_age_days": age,
              "stale": bool(age is not None and age > STALE_DAYS),
              "matrices": per,
              "tactics": len(db.tactics), "techniques": len(db.techniques),
              "parents": parents, "subtechniques": len(db.techniques) - parents,
              "groups": len(db.groups), "software": len(db.software),
              "mitigations": len(db.mitigations),
              "data_sources": len(db.datasources),
              "revoked_redirects": len(db.redirects),
              "tools": len(TOOLS), "aliases": len(ALIASES)})


@tool("mitre_update",
      "Re-telecharge les deux matrices. La base en place n'est remplacee "
      "qu'en cas de succes COMPLET : un echec la laisse intacte.")
def mitre_update():
    fresh = MitreDB(autoload=False)
    raws, errors = {}, {}
    for matrix, url, fname in SOURCES:
        ok, msg, raw = fresh._fetch(matrix, url, CACHE_DIR / fname, commit=False)
        if ok:
            raws[fname] = raw
        else:
            errors[matrix] = msg
    if errors:
        return J({"status": "error", "errors": errors,
                  "base_preservee": db.ready, "db_version": _db_version()})
    fresh._finalize()
    problemes = fresh.check()
    if problemes:
        audit("update_rejected", problemes=problemes)
        return J({"status": "error", "errors": {"integrite": problemes},
                  "base_preservee": db.ready, "db_version": _db_version()})
    for fname, raw in raws.items():
        MitreDB._write_cache(CACHE_DIR / fname, raw)
    db.adopt(fresh)
    audit("db_updated", db_version=_db_version())
    return J({"status": "ok", "db_version": _db_version(),
              "tactics": len(db.tactics), "techniques": len(db.techniques),
              "groups": len(db.groups), "software": len(db.software),
              "mitigations": len(db.mitigations),
              "data_sources": len(db.datasources),
              "revoked_redirects": len(db.redirects)})


#  Boucle MCP (stdio JSON-RPC)

def run():
    log.info(f"MCP {SERVER_NAME} v{SERVER_VERSION} : {len(TOOLS)} outils, "
             f"{len(db.techniques)} techniques, "
             f"{len(db.datasources)} sources, {len(db.redirects)} redirections.")
    audit("server_start", pid=os.getpid(), version=SERVER_VERSION,
          db_version=_db_version(), ready=db.ready, tools=len(TOOLS))
    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                log.warning("Message JSON invalide ignore")
                continue
            batch = isinstance(msg, list)
            out = [r for r in (handle(m) for m in (msg if batch else [msg])) if r]
            if out:
                sys.stdout.write(
                    json.dumps(out if batch else out[0], ensure_ascii=False) + "\n")
                sys.stdout.flush()
        except KeyboardInterrupt:
            break
        except Exception as e:
            log.error(e)
    audit("server_stop")
    if _audit:
        _audit.shutdown()


def handle(msg):
    if not isinstance(msg, dict):
        return None
    method = msg.get("method", "")
    mid = msg.get("id")
    params = msg.get("params") or {}
    if mid is None:
        return None

    if method == "initialize":
        v = params.get("protocolVersion")
        return R(mid, {"protocolVersion": v if isinstance(v, str) else "2024-11-05",
                       "capabilities": {"tools": {}},
                       "serverInfo": {"name": SERVER_NAME,
                                      "version": SERVER_VERSION}})
    if method == "tools/list":
        return R(mid, {"tools": [t["schema"] for t in TOOLS.values()]})
    if method == "tools/call":
        asked = params.get("name", "")
        name = ALIASES.get(asked, asked)
        args = params.get("arguments") or {}
        t = TOOLS.get(name)
        if not t:
            return E(mid, -32602, f"Outil inconnu: {asked}")
        if not db.ready and not db.ensure():
            return R(mid, {"content": [{"type": "text", "text": J({
                "error": "Base MITRE indisponible ou incomplete",
                "details": db.check(),
                "db_version": _db_version()})}], "isError": True})
        try:
            res = t["handler"](**args)
            audit("tool_call", tool=name, status="success")
            return R(mid, {"content": [{"type": "text", "text": res}]})
        except TypeError as e:
            audit("tool_call", tool=name, status="bad_args", error=str(e))
            return R(mid, {"content": [{"type": "text", "text": J({
                "error": f"Arguments invalides: {e}",
                "attendus": sorted(t["schema"]["inputSchema"]["properties"]),
                "requis": t["schema"]["inputSchema"]["required"]})}],
                "isError": True})
        except Exception as e:
            audit("tool_call", tool=name, status="error", error=str(e))
            return R(mid, {"content": [{"type": "text",
                                        "text": J({"error": str(e)})}],
                           "isError": True})
    if method in ("resources/list", "prompts/list"):
        return R(mid, {method.split("/")[0]: []})
    if method == "ping":
        return R(mid, {})
    return E(mid, -32601, f"Methode inconnue: {method}")


def R(mid, result):
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def E(mid, code, msg):
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": msg}}


#  Diagnostic : VERIFIE et sort en code 1, utilisable en integration continue

def selftest() -> int:
    echecs = []
    print(f"Serveur : {SERVER_NAME} v{SERVER_VERSION}")
    print("Source  : attack-stix-data")
    print(f"Releases: { {m: v.get('release', '?') for m, v in db.versions.items()} }")
    for mx in MATRIX_NAMES:
        techs = [t for t in db.techniques.values() if t["matrix"] == mx]
        n_tac = sum(1 for t in db.tactics.values() if t["matrix"] == mx)
        n_det = sum(1 for t in techs if t["detections"])
        n_ds = sum(1 for t in techs if t["data_sources"])
        model = db.versions.get(mx, {}).get("detection_model", "?")
        print(f"  {mx:11} {n_tac:3} tactiques, {len(techs):4} techniques, "
              f"{n_det:4} avec strategie, {n_ds:4} avec source "
              f"(modele: {model})")
        if not techs:
            echecs.append(f"{mx} : matrice vide")
            continue
        if not n_tac:
            echecs.append(f"{mx} : aucune tactique")
        if not db.liens_tactiques(mx):
            echecs.append(f"{mx} : aucun lien tactique-technique")
        if n_ds * 4 < len(techs):
            echecs.append(f"{mx} : couverture de detection anormale "
                          f"({n_ds}/{len(techs)})")
    print(f"  Total       {len(db.tactics)} tactiques, {len(db.techniques)} "
          f"techniques, {len(db.groups)} groupes, {len(db.software)} software, "
          f"{len(db.mitigations)} mitigations")
    print(f"  Index       {len(db.datasources)} libelles de sources")
    print(f"  Liens       {db.liens_tactiques()} tactique-technique, "
          f"{sum(len(t['subtechniques']) for t in db.techniques.values())} "
          f"parent-sous-technique")
    print(f"  Revocations {len(db.redirects)} redirections, "
          f"{sum(1 for r in db.redirects.values() if not r.get('alive'))} "
          f"sans remplacant vivant")

    if not db.datasources:
        echecs.append("index des sources de donnees vide")

    # Reciprocites : la classe de regression la plus dangereuse pour ce
    # serveur est celle qui vide une relation sans lever la moindre erreur.
    integrite = 0
    for tid, t in db.techniques.items():
        for ta in t["tactics"]:
            if db.tactics[ta["id"]]["matrix"] != t["matrix"]:
                integrite += 1
            if tid not in db.tactics[ta["id"]]["techniques"]:
                integrite += 1
        for m in t["mitigations"]:
            if tid not in db.mitigations[m]["techniques"]:
                integrite += 1
        for g in t["groups"]:
            if tid not in db.groups[g]["techniques"]:
                integrite += 1
        if t["is_subtechnique"]:
            p = db.techniques.get(t["parent_id"])
            if p is not None and tid not in p["subtechniques"]:
                integrite += 1
    print(f"  Integrite   {integrite} anomalie(s) de reciprocite")
    if integrite:
        echecs.append(f"{integrite} anomalies de reciprocite")

    print(f"Outils ({len(TOOLS)}) : {list(TOOLS.keys())}")
    print(f"Alias  ({len(ALIASES)}) : {list(ALIASES.keys())}")
    if echecs:
        print("ECHEC : " + " | ".join(echecs))
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    if "--help" in sys.argv:
        print(__doc__)
        sys.exit(0)
    if "--test" in sys.argv:
        code = selftest()
        if _audit:
            _audit.shutdown()
        sys.exit(code)
    run()
