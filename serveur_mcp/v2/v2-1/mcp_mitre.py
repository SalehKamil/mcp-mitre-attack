# Version 2.1 du serveur MCP MITRE ATT&CK - hybride Enterprise (IT) + ICS (OT)
# + referentiel interne de techniques (fiches THQxxxx).
"""MCP MITRE ATT&CK - serveur stdio exposant les matrices Enterprise et ICS,
etendues par un referentiel interne de techniques propre a l'organisation.

Moteur de mapping (inchange depuis la v2.0, verifie par --test) :

  - lecture des DEUX modeles de detection ATT&CK (strategies/analytics des
    releases >= 18, champs herites des releases <= 17.1) ;
  - libelles de sources de logs assainis (champ `channel` filtre) ;
  - recherche par mots entiers racinises, score normalise [0..1] + preuves ;
  - redirection des identifiants revoques, resolue transitivement ;
  - numero de release ATT&CK rappele dans chaque reponse (`db_version`) ;
  - garde-fous : cache incomplet refuse et retelecharge, base preservee en cas
    d'echec de mise a jour, `--test` qui sort en code 1, arguments invalides
    documentes, normalisation des identifiants, homonymes de tactiques
    signales, alias `mitre_*`.

Referentiel interne (v2.1) :

  - fichier JSON versionne par l'equipe, servi en LECTURE SEULE : aucun outil
    n'ecrit jamais dans le referentiel, la creation et la validation d'une
    fiche restent des actes humains ;
  - une fiche THQxxxx est une EXTENSION de MITRE, jamais un remplacement :
    elle reste ancree a ATT&CK par `technique_mitre_liee` ;
  - controles au chargement : format d'identifiant, doublons, nom obligatoire,
    statut inconnu retrograde a 'brouillon', lien MITRE inconnu signale et
    lien revoque suivi jusqu'a son remplacant vivant ;
  - `list_internal_techniques` fournit le PROCHAIN IDENTIFIANT LIBRE
    (numerotation continue, jamais reutilisee) ;
  - `search_internal` applique EXACTEMENT la fonction de score de
    `search_techniques` (meme code, pas une copie) : anti-doublon avant toute
    proposition de nouvelle fiche ;
  - `get_technique` signale les fiches rattachees a la technique consultee
    (champ additif `internal_extensions`), y compris celles rattachees a ses
    sous-techniques et celles rattachees a un identifiant revoque ;
  - `internal_reload` relit le fichier a chaud, sans redemarrer le serveur.

Usage:
  python mcp_mitre.py             Demarre le serveur MCP (stdio).
  python mcp_mitre.py --test      Verifie la base et sort en code 1 si KO.
  python mcp_mitre.py --strict    Avec --test : les anomalies du referentiel
                                  interne sont elles aussi bloquantes.
  python mcp_mitre.py --no-audit  Demarre sans journal d'audit.
  python mcp_mitre.py --help      Affiche ce message.

Variables d'environnement:
  MITRE_CACHE      Repertoire du cache local  (defaut: MITRE_DB/ a cote du script).
  MITRE_LOGS       Repertoire du journal      (defaut: Logs/ a cote du script).
  MCP_INTERNAL_DB  Referentiel interne        (defaut: referentiel_interne.json
                   a cote du script). Absent = zero fiche, demarrage normal.
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
import unicodedata
from pathlib import Path
from datetime import datetime

for _s in (sys.stdin, sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

SERVER_NAME = "mcp-mitre-attack"
SERVER_VERSION = "2.1"

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

#  Referentiel interne : fichier JSON versionne par l'equipe, LECTURE SEULE

INTERNAL_DB_PATH = Path(os.getenv("MCP_INTERNAL_DB",
                                  BASE_DIR / "referentiel_interne.json"))
INTERNAL_PREFIX = "THQ"
INTERNAL_ID_RE = re.compile(r"^THQ(\d{4,})$")   # 4 chiffres au moins :
# la numerotation ne doit pas casser au passage de THQ9999 a THQ10000.
INTERNAL_STATUTS = ("brouillon", "valide")
INTERNAL_DEFAULT_STATUT = "brouillon"
INTERNAL_LIST_CAP = 200       # plafond d'affichage de list_internal_techniques
# Champs que le SERVEUR produit : une fiche qui les porterait ecraserait la
# reponse (db_version falsifie, lecture_seule a false, faux 'error'). Ils sont
# retires au chargement, avec un avertissement, jamais silencieusement.
INTERNAL_RESERVED = frozenset((
    "db_version", "lecture_seule", "error", "hint", "note", "anomalies",
    "fiche_count", "result_count", "next_id", "internal_extensions",
    "resolution", "technique_mitre_effective", "lien_revoque", "via",
    "score", "matched",
))
INTERNAL_MAX_NAME = 200
INTERNAL_MAX_DESC = 4000

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

# --strict : avec --test, une fiche interne ecartee devient bloquante en CI.
STRICT_INTERNAL = "--strict" in sys.argv


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
    # Grammaire francaise : le referentiel interne est redige en francais et
    # ces mots diluent le denominateur du score sans rien discriminer.
    "les", "des", "une", "aux", "pour", "dans", "avec", "sur", "par", "sans",
    "est", "sont", "ete", "etre", "qui", "que", "quoi", "dont", "cette", "ces",
    "son", "ses", "leur", "leurs", "plus", "moins", "tout", "tous", "toute",
    "vers", "chez", "lors", "afin", "ainsi", "donc", "mais", "puis",
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


def _fold(text: str) -> str:
    """Retire les diacritiques AVANT la tokenisation. Sans ce pliage, le motif
    [a-z0-9]+ coupe le mot a chaque accent : 'privileges' devient
    {'privil', 'ges'} et ne converge jamais avec 'privileges' non accentue.
    Le referentiel interne etant redige en francais, cette convergence
    conditionne l'anti-doublon de search_internal."""
    return "".join(c for c in unicodedata.normalize("NFD", text or "")
                   if unicodedata.category(c) != "Mn")


def _tokens(text: str) -> set:
    """Tokens significatifs racinises. Les tokens contenant un chiffre
    (4688, t1003, sha256, c2) sont gardes des 2 caracteres et non racinises."""
    out = set()
    for w in _TOKEN_RE.findall(_fold(text).lower()):
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


def _lexical_score(q_tok, ql, n, tok_name, tok_desc, name):
    """Fonction de score commune a search_techniques et search_internal.

    Un SEUL exemplaire du calcul : les deux recherches ne peuvent pas diverger
    au fil des versions, et la promesse « memes regles que la recherche MITRE »
    est vraie par construction plutot que par relecture.

    Chaque token de la REQUETE compte une fois : le score mesure la couverture
    de la requete, pas la longueur de la description. Un mot trouve dans le nom
    vaut 1, dans la description 0.35 ; la phrase complete presente dans le nom
    ajoute 0.15. Resultat borne a [0..1]."""
    hit_name = q_tok & tok_name
    hit_desc = (q_tok & tok_desc) - hit_name
    if not hit_name and not hit_desc:
        return 0.0, {}
    base = (1.0 * len(hit_name) + 0.35 * len(hit_desc)) / max(n, 1)
    if ql and _fold(ql) in _fold(name or "").lower():
        base += 0.15
    matched = {}
    if hit_name:
        matched["name"] = sorted(hit_name)
    if hit_desc:
        matched["description"] = sorted(hit_desc)
    return min(base, 1.0), matched


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
            # _parse peut echouer APRES avoir collecte une partie du bundle
            # (objet STIX malforme) : sans purge, le retelechargement viendrait
            # s'ajouter aux residus d'un cache corrompu.
            log.warning(f"Cache {matrix} illisible ({e}) : retelechargement")
            audit("cache_invalid", matrix=matrix, error=str(e))
            self._purge(matrix)
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
        echoue, pour ne pas laisser de residus avant retelechargement.

        Retirer les OBJETS ne suffit pas : les objets qui survivent les
        CITENT encore. Un groupe hybride garde les identifiants des
        techniques industrielles qu'il utilisait, l'index des sources garde
        des libelles fantomes, une redirection garde son drapeau `alive`
        alors que sa cible vient de partir. Aucune reponse n'est fausse
        (chaque lecture filtre a l'affichage), mais les compteurs de
        mitre_stats et de --test annoncent des objets absents, et le
        re-ancrage du referentiel interne peut resoudre un lien revoque vers
        une technique qui n'est plus la. Toute reference vers un objet parti
        est donc retiree ici, en meme temps que l'objet lui-meme."""
        partis_t = {k for k, v in self.techniques.items()
                    if v.get("matrix") == matrix}
        partis_m = {k for k, v in self.mitigations.items()
                    if v.get("matrix") == matrix}
        for store in (self.tactics, self.techniques, self.mitigations):
            for k in [k for k, v in store.items() if v.get("matrix") == matrix]:
                del store[k]
        # Un groupe ou un software present dans les deux matrices survit a la
        # purge de l'une d'elles : seuls ceux qui n'ont plus aucune matrice
        # disparaissent, et eux seuls doivent etre deferences.
        partis_g, partis_s = set(), set()
        for store, partis in ((self.groups, partis_g), (self.software, partis_s)):
            for k, v in list(store.items()):
                if matrix in v["matrices"]:
                    v["matrices"].remove(matrix)
                if not v["matrices"]:
                    partis.add(k)
                    del store[k]
        for g in self.groups.values():
            g["techniques"] = [t for t in g["techniques"] if t not in partis_t]
            g["software"] = [s for s in g["software"] if s not in partis_s]
        for s in self.software.values():
            s["techniques"] = [t for t in s["techniques"] if t not in partis_t]
        for mi in self.mitigations.values():
            mi["techniques"] = [t for t in mi["techniques"] if t not in partis_t]
        for ta in self.tactics.values():
            ta["techniques"] = [t for t in ta["techniques"] if t not in partis_t]
        for t in self.techniques.values():
            t["mitigations"] = [x for x in t["mitigations"] if x not in partis_m]
            t["groups"] = [x for x in t["groups"] if x not in partis_g]
            t["software"] = [x for x in t["software"] if x not in partis_s]
            t["subtechniques"] = [x for x in t["subtechniques"]
                                  if x not in partis_t]
            t["tactics"] = [x for x in t["tactics"] if x["id"] in self.tactics]
        # L'index des sources pointe vers des identifiants de techniques :
        # sans ce nettoyage il conserve des libelles fantomes, comptes par
        # mitre_stats.data_sources et par get_datasources.source_count.
        for label in list(self.datasources):
            self.datasources[label] -= partis_t
            if not self.datasources[label]:
                del self.datasources[label]
        # Les redirections de la matrice purgee partent avec elle ; celles qui
        # restent voient leur drapeau `alive` recalcule, sinon get_technique
        # annonce un remplacant vivant qui ne l'est plus.
        for old in list(self.redirects):
            r = self.redirects[old]
            if r.get("matrix") == matrix or r["replaced_by"] in partis_t:
                del self.redirects[old]
                continue
            r["alive"] = r["replaced_by"] in self.techniques
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
                    # La matrice d'origine est conservee : sans elle, _purge
                    # ne saurait pas quelles redirections partent avec elle.
                    self.redirects[old_id] = {"replaced_by": new_id,
                                              "name": old_name,
                                              "matrix": matrix}
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


#  Referentiel interne de techniques (fiches THQ) - EXTENSION de MITRE

class InternalDB:
    """Fiches internes lues depuis un fichier JSON versionne par l'equipe.

    Le serveur SERT ce fichier, il ne l'ecrit jamais : aucun outil d'ecriture
    n'est expose, ce qui rend structurellement impossible la pollution du
    referentiel par un modele de langage. La creation et la validation d'une
    fiche passent par l'edition humaine du JSON, puis par un commit.

    Le chargement ne peut pas degrader le referentiel : une fiche invalide est
    ecartee avec son motif, jamais reparee au jugé. Une fiche incomplete ne
    doit pas non plus pouvoir casser un outil de mapping MITRE : c'est pour
    cela que `name` est obligatoire et que toutes les lectures passent par des
    accesseurs surs."""

    def __init__(self):
        self.fiches = {}          # THQ0001 -> fiche normalisee
        self.by_mitre = {}        # T1566.002 -> [THQ0001, ...] (declare + vivant)
        self.meta = {}
        self.path = None
        self.loaded_at = ""
        self.anomalies = []       # [{niveau, fiche, message}]
        # Marque haute MONOTONE : elle ne redescend jamais, y compris apres la
        # suppression d'une fiche, sinon un identifiant deja attribue serait
        # reattribue a un comportement different. Elle est amorcee au demarrage
        # par meta.dernier_id_attribue, qui la fait survivre a un redemarrage.
        self._max_num = 0

    #  Chargement

    def load(self, path):
        """Recharge integralement le referentiel depuis le disque. En cas
        d'echec de lecture, l'etat precedent est conserve : un fichier
        temporairement casse ne vide pas le referentiel en memoire."""
        p = Path(path)
        if not p.exists():
            # Un fichier qui DISPARAIT est traite comme un fichier illisible :
            # l'etat precedent est conserve. Une edition humaine non atomique,
            # un `git checkout` ou un `git stash` passe par un instant sans
            # fichier, et il serait absurde qu'un rechargement a chaud y vide
            # le referentiel alors qu'un JSON tronque, lui, le preserve.
            if self.fiches:
                msg = "fichier introuvable - referentiel precedent conserve"
                log.error(f"Referentiel interne introuvable ({p}) : {msg} "
                          f"({len(self.fiches)} fiche(s))")
                audit("internal_db_missing", path=str(p),
                      fiches_conservees=len(self.fiches))
                return {"status": "error", "path": str(p), "message": msg,
                        "fiche_count": len(self.fiches)}
            # Premier chargement : un depot sans referentiel est legitime.
            self.fiches, self.by_mitre, self.meta = {}, {}, {}
            self.anomalies = []
            self.path = str(p)
            self.loaded_at = datetime.now().isoformat()
            log.warning(f"Referentiel interne absent ({p}) : 0 fiche")
            audit("internal_db_missing", path=str(p))
            return {"status": "absent", "path": str(p), "fiche_count": 0}
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("racine JSON attendue : un objet")
            brut = data.get("techniques")
            if not isinstance(brut, list):
                raise ValueError("cle 'techniques' absente ou non-liste")
        except Exception as e:
            log.error(f"Referentiel interne illisible ({p}) : {e} "
                      f"- referentiel precedent conserve "
                      f"({len(self.fiches)} fiche(s))")
            audit("internal_db_error", path=str(p), error=str(e))
            return {"status": "error", "path": str(p), "message": str(e),
                    "fiche_count": len(self.fiches)}

        fiches, by_mitre, anomalies, max_num = {}, {}, [], 0
        for brute in brut:
            fiche, anos, num = self._normalise(brute, fiches)
            anomalies.extend(anos)
            max_num = max(max_num, num)
            if fiche:
                fiches[fiche["id"]] = fiche

        for fid, f in fiches.items():
            for key in (f["technique_mitre_liee"], f["technique_mitre_effective"]):
                if key:
                    by_mitre.setdefault(key, [])
                    if fid not in by_mitre[key]:
                        by_mitre[key].append(fid)
        for ids in by_mitre.values():
            ids.sort()

        self.fiches, self.by_mitre = fiches, by_mitre
        meta_brut = data.get("meta")
        self.meta = meta_brut if isinstance(meta_brut, dict) else {}
        # meta.dernier_id_attribue conserve la marque haute a travers les
        # redemarrages : une fiche supprimee du fichier ne rend pas son numero
        # disponible. En memoire la marque est monotone de toute facon ; c'est
        # au REDEMARRAGE qu'elle se perd, et un redemarrage du client MCP est
        # un geste quotidien. Son absence est donc signalee : sans la cle, la
        # regle « un identifiant retire n'est jamais reattribue » n'est pas
        # tenue des que la fiche la plus haute quitte le fichier.
        declare = str((meta_brut or {}).get("dernier_id_attribue", "")
                      or "").strip().upper()
        mm = INTERNAL_ID_RE.match(declare)
        if fiches and not mm:
            msg = (f"meta.dernier_id_attribue {declare!r} illisible "
                   f"(format attendu {INTERNAL_PREFIX}0000)" if declare else
                   "meta.dernier_id_attribue absent")
            msg += (" : la marque haute des identifiants ne survivra pas a un "
                    "redemarrage si la fiche la plus haute quitte le fichier")
            anomalies.append({"niveau": "avertissement", "fiche": "meta",
                              "message": msg})
            log.warning(f"Referentiel interne : {msg}")
        self.anomalies = anomalies
        self._max_num = max(self._max_num, max_num,
                            int(mm.group(1)) if mm else 0)
        self.path = str(p)
        self.loaded_at = datetime.now().isoformat()
        rejets = sum(1 for a in anomalies if a["niveau"] == "rejet")
        log.info(f"Referentiel interne : {len(fiches)} fiche(s) chargee(s) "
                 f"depuis {p} ({rejets} ecartee(s), next_id {self.next_id()}).")
        audit("internal_db_loaded", path=str(p), fiches=len(fiches),
              rejets=rejets, avertissements=len(anomalies) - rejets,
              next_id=self.next_id())
        return {"status": "ok", "path": str(p), "fiche_count": len(fiches),
                "rejets": rejets, "next_id": self.next_id()}

    def _normalise(self, brute, deja):
        """Valide et normalise une fiche. Renvoie (fiche|None, anomalies,
        numero vu). Le numero est renvoye meme pour une fiche ecartee : un
        identifiant deja attribue ne doit jamais etre reattribue."""
        anos = []
        ident = str(brute.get("id", "") if isinstance(brute, dict) else "")
        fid = ident.strip().upper()
        m = INTERNAL_ID_RE.match(fid)

        def rejet(msg):
            anos.append({"niveau": "rejet", "fiche": fid or ident or "?",
                         "message": msg})
            log.warning(f"Fiche interne ecartee : {msg}")
            return None, anos, int(m.group(1)) if m else 0

        if not isinstance(brute, dict):
            return rejet("entree non-objet dans 'techniques'")
        if not m:
            return rejet(f"id invalide {ident!r} "
                         f"(format attendu {INTERNAL_PREFIX}0000)")
        num = int(m.group(1))
        if fid in deja:
            return rejet(f"id duplique {fid}")

        name = str(brute.get("name", "") or "").strip()
        if not name:
            # Une fiche sans nom est inutilisable et ferait echouer toute
            # reponse qui la cite, y compris celle d'un outil MITRE.
            return rejet(f"{fid} : champ 'name' absent ou vide")

        usurpes = sorted(k for k in brute
                         if str(k).lower() in INTERNAL_RESERVED)
        if usurpes:
            anos.append({"niveau": "avertissement", "fiche": fid,
                         "message": f"{fid} : champ(s) reserve(s) au serveur "
                                    f"ignore(s) : {', '.join(usurpes)}"})
            log.warning(f"Fiche {fid} : champ(s) reserve(s) ignore(s) : "
                        f"{', '.join(usurpes)}")
        fiche = {k: v for k, v in brute.items()
                 if not str(k).startswith("_")
                 and str(k).lower() not in INTERNAL_RESERVED}
        fiche["id"] = fid
        fiche["name"] = name[:INTERNAL_MAX_NAME]
        desc = str(brute.get("description", "") or "").strip()
        fiche["description"] = desc[:INTERNAL_MAX_DESC]
        if len(name) > INTERNAL_MAX_NAME or len(desc) > INTERNAL_MAX_DESC:
            anos.append({"niveau": "avertissement", "fiche": fid,
                         "message": f"{fid} : nom ou description tronque"})

        statut = str(brute.get("statut", INTERNAL_DEFAULT_STATUT)
                     or "").strip().lower()
        if statut not in INTERNAL_STATUTS:
            anos.append({"niveau": "avertissement", "fiche": fid,
                         "message": f"{fid} : statut {brute.get('statut')!r} "
                                    f"inconnu, retrograde a "
                                    f"'{INTERNAL_DEFAULT_STATUT}'"})
            log.warning(f"Fiche {fid} : statut {brute.get('statut')!r} inconnu, "
                        f"retrograde a '{INTERNAL_DEFAULT_STATUT}'")
            statut = INTERNAL_DEFAULT_STATUT
        fiche["statut"] = statut

        # Ancrage ATT&CK : normalise, puis suivi jusqu'au remplacant vivant si
        # MITRE a revoque la technique depuis la redaction de la fiche.
        declare = _norm_id(str(brute.get("technique_mitre_liee", "") or ""))
        effectif = declare or None
        fiche["technique_mitre_liee"] = declare or None
        fiche["lien_revoque"] = None
        if declare:
            if declare in db.redirects:
                r = db.redirects[declare]
                effectif = r["replaced_by"] if r.get("alive") else None
                fiche["lien_revoque"] = {"declare": declare,
                                         "replaced_by": r["replaced_by"],
                                         "remplacant_vivant": bool(r.get("alive"))}
                msg = (f"{fid} : technique_mitre_liee {declare} est revoquee "
                       f"par MITRE, remplacee par {r['replaced_by']}"
                       + ("" if r.get("alive")
                          else " (remplacant absent de la base)"))
                anos.append({"niveau": "avertissement", "fiche": fid,
                             "message": msg})
                log.warning(msg)
            elif db.techniques and declare not in db.techniques:
                msg = (f"{fid} : technique_mitre_liee {declare} inconnue de la "
                       f"base ATT&CK chargee")
                anos.append({"niveau": "avertissement", "fiche": fid,
                             "message": msg})
                log.warning(msg)
                effectif = None
        else:
            anos.append({"niveau": "avertissement", "fiche": fid,
                         "message": f"{fid} : aucune technique_mitre_liee, "
                                    f"fiche sans ancrage ATT&CK"})
        fiche["technique_mitre_effective"] = effectif

        fiche["_tok_name"] = _tokens(fiche["name"])
        fiche["_tok_desc"] = _tokens(_clean_text(fiche["description"]))
        fiche["_snippet"] = _snippet(fiche["description"])
        return fiche, anos, num

    #  Lectures

    def next_id(self):
        """Prochain identifiant libre. Numerotation CONTINUE : le maximum vu
        plus un, y compris les identifiants de fiches ecartees ou supprimees,
        pour qu'un numero deja attribue ne soit jamais reattribue."""
        return f"{INTERNAL_PREFIX}{self._max_num + 1:04d}"

    @staticmethod
    def public(f):
        """Fiche debarrassee de ses champs d'index (prefixe '_')."""
        return {k: v for k, v in f.items() if not str(k).startswith("_")}

    def resume(self, fid):
        """Resume minimal d'une fiche, sur des donnees toujours presentes."""
        f = self.fiches.get(fid)
        if not f:
            return None
        return {"id": f["id"], "name": f.get("name", ""),
                "statut": f.get("statut", INTERNAL_DEFAULT_STATUT),
                "technique_mitre_liee": f.get("technique_mitre_liee")}

    def extensions_de(self, tid):
        """Fiches qui precisent une technique MITRE : celles qui lui sont
        rattachees directement, puis celles rattachees a ses sous-techniques
        (marquees par `via`). Un analyste qui confirme une technique parente
        voit ainsi la declinaison interne sans requete supplementaire."""
        out = []
        for fid in self.by_mitre.get(tid, []):
            r = self.resume(fid)
            if r:
                out.append(r)
        t = db.techniques.get(tid)
        for sub in (t["subtechniques"] if t else []):
            for fid in self.by_mitre.get(sub, []):
                if any(x["id"] == fid for x in out):
                    continue
                r = self.resume(fid)
                if r:
                    r["via"] = sub
                    out.append(r)
        return out

    def compteurs(self):
        rejets = sum(1 for a in self.anomalies if a["niveau"] == "rejet")
        return {
            "fiche_count": len(self.fiches),
            "next_id": self.next_id(),
            "valides": sum(1 for f in self.fiches.values()
                           if f.get("statut") == "valide"),
            "brouillons": sum(1 for f in self.fiches.values()
                              if f.get("statut") != "valide"),
            "sans_ancrage_mitre": sum(1 for f in self.fiches.values()
                                      if not f.get("technique_mitre_liee")),
            "liens_revoques": sum(1 for f in self.fiches.values()
                                  if f.get("lien_revoque")),
            "fiches_ecartees": rejets,
            "avertissements": len(self.anomalies) - rejets,
            "path": self.path,
            "loaded_at": self.loaded_at,
        }


internal = InternalDB()
internal.load(INTERNAL_DB_PATH)   # apres MITRE : les liens sont verifiables


def _reancrer_interne(raison):
    """Le referentiel interne est resolu CONTRE la base ATT&CK chargee :
    `technique_mitre_effective`, `lien_revoque` et l'index `by_mitre` en
    dependent. Toute base remplacee (mitre_update, rattrapage apres un
    telechargement echoue) doit donc etre suivie d'une relecture, sinon le pont
    `internal_extensions` pointe vers d'anciens identifiants et une fiche
    devient invisible depuis la technique vivante."""
    try:
        internal.load(INTERNAL_DB_PATH)
        audit("internal_reanchor", raison=raison, fiches=len(internal.fiches))
    except Exception as e:
        log.warning(f"Re-ancrage du referentiel interne impossible : {e}")


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
            # Une fiche interne peut encore citer l'ancien identifiant : elle
            # est signalee ici plutot que perdue derriere la redirection.
            return J({"db_version": _db_version(), "redirect": True,
                      "requested": tid, "name": r["name"],
                      "replaced_by": r["replaced_by"],
                      "remplacant_vivant": r.get("alive", False),
                      "internal_extensions": internal.extensions_de(tid),
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
        # Champ ADDITIF : declinaisons internes de cette technique. Les fiches
        # rattachees a une sous-technique portent `via`. Liste vide si le
        # referentiel interne est absent ou ne couvre pas cette technique.
        "internal_extensions": internal.extensions_de(tid),
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
    # Le filtre de matrice s'applique aux LIBELLES autant qu'aux techniques :
    # sinon la reponse annonce sous `matrix_filtre: ICS` des canaux Windows
    # qui n'observent aucune technique industrielle, et un modele les prend
    # pour des sources de logs OT.
    matches = {}
    for n, tids in db.datasources.items():
        if q not in n.lower():
            continue
        vus = {t for t in tids if t in db.techniques
               and (not want or db.techniques[t]["matrix"] == want)}
        if vus:
            matches[n] = vus
    techs = {}
    for tids in matches.values():
        for tid in tids:
            if tid in techs:
                continue
            t = db.techniques[tid]
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
        score = 0.0
        matched = {}
        if id_like:
            if tid == id_like:
                score = 1.0
                matched["id"] = [tid]
            elif tid.startswith(id_like + ".") or id_like.startswith(tid + "."):
                score = max(score, 0.7)
                matched["id"] = [id_like]
        s_lex, matched_lex = _lexical_score(q_tok, ql, n, t["_tok_name"],
                                            t["_tok_desc"], t["name"])
        if s_lex > 0:
            score = max(score, s_lex)
            matched.update(matched_lex)
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
    # MITRE d'abord, interne ensuite : le renvoi vers le referentiel maison
    # n'apparait que lorsque MITRE ne fournit aucun candidat fort.
    if internal.fiches and (not results or results[0]["score"] < SCORE_STRONG):
        notes.append(f"aucun candidat MITRE fort : confronter le comportement "
                     f"au referentiel interne avec search_internal "
                     f"({len(internal.fiches)} fiche(s))")
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


#  Outils du referentiel interne (THQ) - lecture seule

@tool("list_internal_techniques",
      "Referentiel INTERNE (fiches THQ) : liste complete, metadonnees et "
      "PROCHAIN IDENTIFIANT LIBRE. A appeler avant toute proposition de "
      "nouvelle fiche, pour la numerotation et pour la vue d'ensemble "
      "anti-doublon. Le referentiel est en LECTURE SEULE : le serveur ne cree "
      "jamais de fiche, il fournit le prochain identifiant pour que le "
      "brouillon propose soit correctement numerote ; l'ajout reel est un "
      "acte humain (edition du fichier JSON, puis commit).",
      {"statut": ("string", False, "Filtre 'valide' ou 'brouillon' (optionnel)")},
      aliases=("internal_list",))
def list_internal_techniques(statut=""):
    f_statut = _validate(statut, 24, "statut").lower() if statut else ""
    if f_statut and f_statut not in INTERNAL_STATUTS:
        raise ValueError(f"statut '{statut}' inconnu - valeurs acceptees : "
                         f"{', '.join(INTERNAL_STATUTS)}")
    fiches = [f for f in sorted(internal.fiches.values(), key=lambda x: x["id"])
              if not f_statut or f.get("statut") == f_statut]
    items = [internal.resume(f["id"]) for f in fiches[:INTERNAL_LIST_CAP]]
    out = {"db_version": _db_version(),
           "referentiel": {k: v for k, v in internal.meta.items()
                           if isinstance(v, (str, int, float, bool))},
           "lecture_seule": True,
           "statut_filtre": f_statut or "aucun",
           # `fiche_count` designe TOUJOURS la taille du referentiel, comme
           # dans compteurs et dans search_internal ; le nombre de fiches
           # effectivement renvoyees apres filtrage est `result_count`. Sans
           # cette distinction, la meme cle valait deux nombres differents
           # dans la meme reponse des qu'un filtre `statut` etait pose.
           "fiche_count": len(internal.fiches),
           "result_count": len(fiches),
           "next_id": internal.next_id(),
           "fiches": items,
           "truncated": len(fiches) > INTERNAL_LIST_CAP,
           "compteurs": internal.compteurs()}
    if internal.anomalies:
        out["anomalies"] = internal.anomalies[:20]
    if not internal.fiches:
        out["note"] = ("referentiel interne vide : toute proposition part de "
                       f"{internal.next_id()}")
    return J(out)


@tool("get_internal_technique",
      "Detail d'une fiche du referentiel INTERNE. La technique MITRE liee est "
      "resolue (identifiant + nom) pour garder l'ancrage dans le langage "
      "commun ATT&CK ; si MITRE l'a revoquee depuis la redaction de la fiche, "
      "le remplacant vivant est indique.",
      {"id": ("string", True, "ex: THQ0001")},
      aliases=("internal_technique",))
def get_internal_technique(id):
    fid = _validate(id, MAX_ID_LEN, "id").strip().upper()
    f = internal.fiches.get(fid)
    if not f:
        return J({"error": f"Fiche interne '{fid}' non trouvee",
                  "hint": "list_internal_techniques donne la liste complete",
                  "fiche_count": len(internal.fiches),
                  "db_version": _db_version()})
    out = internal.public(f)
    for champ in ("technique_mitre_liee", "technique_mitre_effective"):
        ident = f.get(champ)
        if ident and ident in db.techniques:
            t = db.techniques[ident]
            out[champ] = {"id": ident, "name": t["name"], "matrix": t["matrix"],
                          "tactics": [x["id"] for x in t["tactics"]]}
        elif ident:
            out[champ] = {"id": ident, "name": None,
                          "note": "inconnue de la base ATT&CK chargee"}
    anos = [a for a in internal.anomalies if a["fiche"] == fid]
    if anos:
        out["anomalies"] = anos
    return J({"db_version": _db_version(), "lecture_seule": True, **out})


@tool("search_internal",
      "Recherche LEXICALE dans le referentiel INTERNE, avec exactement la "
      "meme fonction de score que search_techniques (mots entiers racinises, "
      "score normalise [0..1], preuves par tokens). OBLIGATOIRE avant de "
      "proposer une nouvelle fiche THQ : un resultat >= 0.6 signale qu'une "
      "fiche similaire existe deja, ne pas en creer une seconde. Ne remplace "
      "jamais la recherche MITRE : chercher MITRE d'abord, l'interne ensuite.",
      {"query": ("string", True, "Mots-cles du comportement, ou un id THQxxxx"),
       "limit": ("integer", False,
                 f"Nombre max de resultats (defaut {SEARCH_DEFAULT_LIMIT}, "
                 f"max {SEARCH_MAX_LIMIT})")},
      aliases=("internal_search",))
def search_internal(query, limit=SEARCH_DEFAULT_LIMIT):
    q = _validate(query, MAX_QUERY_LEN, "query")
    notes = []
    base_out = {"db_version": _db_version(), "query": query,
                "lecture_seule": True,
                "seuils": {"fort": SCORE_STRONG, "faible": SCORE_WEAK},
                "fiche_count": len(internal.fiches),
                "next_id": internal.next_id()}
    if not q:
        return J({**base_out, "result_count": 0, "total_matches": 0,
                  "results": [], "note": "requete vide"})
    try:
        n_limit = int(limit)
    except (TypeError, ValueError):
        n_limit = SEARCH_DEFAULT_LIMIT
        notes.append("limit invalide : valeur par defaut appliquee")
    if n_limit < 1 or n_limit > SEARCH_MAX_LIMIT:
        notes.append(f"limit ramene dans l'intervalle 1..{SEARCH_MAX_LIMIT}")
    n_limit = max(1, min(n_limit, SEARCH_MAX_LIMIT))

    scored = []
    direct = internal.fiches.get(q.strip().upper())
    if direct:
        scored.append((1.0, direct, {"id": [direct["id"]]}))
    ql = q.lower()
    q_tok = _tokens(ql)
    if not q_tok and not direct:
        return J({**base_out, "result_count": 0, "total_matches": 0,
                  "results": [],
                  "note": "aucun terme significatif dans la requete"})
    n = max(len(q_tok), 1)
    for fid, f in internal.fiches.items():
        if direct is not None and fid == direct["id"]:
            continue
        score, matched = _lexical_score(q_tok, ql, n, f["_tok_name"],
                                        f["_tok_desc"], f["name"])
        if score > 0:
            scored.append((round(score, 3), f, matched))
    scored.sort(key=lambda x: (-x[0], x[1]["id"]))

    results = [{"id": f["id"], "name": f.get("name", ""),
                "statut": f.get("statut", INTERNAL_DEFAULT_STATUT),
                "technique_mitre_liee": f.get("technique_mitre_liee"),
                "score": s, "matched": matched, "matched_in": sorted(matched),
                "snippet": f.get("_snippet", "")}
               for s, f, matched in scored[:n_limit]]

    if not internal.fiches:
        notes.append("referentiel interne vide : une premiere fiche peut etre "
                     f"proposee (statut '{INTERNAL_DEFAULT_STATUT}', id "
                     f"{internal.next_id()})")
    elif not results:
        notes.append("aucune fiche interne similaire : une nouvelle fiche peut "
                     f"etre proposee (statut '{INTERNAL_DEFAULT_STATUT}', id "
                     f"{internal.next_id()}) apres validation humaine")
    elif results[0]["score"] >= SCORE_STRONG:
        notes.append(f"{results[0]['id']} couvre probablement deja ce "
                     f"comportement : ne pas creer de doublon")
    out = {**base_out, "result_count": len(results),
           "total_matches": len(scored), "results": results}
    if notes:
        out["note"] = " | ".join(notes)
    return J(out)


@tool("internal_reload",
      "Relit le referentiel interne depuis le disque, sans redemarrer le "
      "serveur : utile apres qu'un humain a ajoute ou valide une fiche. "
      "STRICTEMENT en lecture : le fichier n'est jamais ecrit. Si le fichier "
      "est illisible, le referentiel en memoire est conserve tel quel.",
      aliases=("internal_refresh",))
def internal_reload():
    avant = len(internal.fiches)
    r = internal.load(INTERNAL_DB_PATH)
    audit("internal_reload", status=r.get("status"),
          avant=avant, apres=len(internal.fiches))
    return J({"db_version": _db_version(), "lecture_seule": True,
              "status": r.get("status"), "path": r.get("path"),
              "message": r.get("message"),
              "fiches_avant": avant, "fiches_apres": len(internal.fiches),
              "compteurs": internal.compteurs(),
              "anomalies": internal.anomalies[:20]})


@tool("mitre_stats",
      "Version du serveur, releases ATT&CK chargees, modele de detection "
      "detecte, fraicheur du cache, statistiques de la base hybride et "
      "compteurs du referentiel interne.")
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
              "internal": internal.compteurs(),
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
    _reancrer_interne("mitre_update")
    audit("db_updated", db_version=_db_version())
    return J({"status": "ok", "db_version": _db_version(),
              "tactics": len(db.tactics), "techniques": len(db.techniques),
              "groups": len(db.groups), "software": len(db.software),
              "mitigations": len(db.mitigations),
              "data_sources": len(db.datasources),
              "revoked_redirects": len(db.redirects)})


#  Boucle MCP (stdio JSON-RPC)

# Outils dont la reponse ne depend pas de la base ATT&CK : ils repondent meme
# si le telechargement a echoue, au lieu de renvoyer « base indisponible ».
TOOLS_SANS_BASE = frozenset((
    "list_internal_techniques", "get_internal_technique", "search_internal",
    "internal_reload", "mitre_stats", "mitre_update",
))


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
        # Les outils du referentiel interne et le diagnostic ne dependent pas
        # de la base MITRE : ils restent utilisables si elle est indisponible.
        if name not in TOOLS_SANS_BASE and not db.ready:
            if not db.ensure():
                return R(mid, {"content": [{"type": "text", "text": J({
                    "error": "Base MITRE indisponible ou incomplete",
                    "details": db.check(),
                    "db_version": _db_version()})}], "isError": True})
            # La base vient d'arriver : les fiches internes ont ete chargees
            # sans pouvoir etre confrontees a ATT&CK, on les re-ancre.
            _reancrer_interne("ensure")
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

    # Symetrique de la reciprocite : une relation qui pointe vers un objet
    # ABSENT de la base. C'est ce que laisse derriere elle une purge de
    # matrice incomplete ; chaque lecture filtre ces references a
    # l'affichage, donc aucune reponse n'est fausse et rien ne les revele
    # sinon ce controle.
    orphelines = 0
    for g in db.groups.values():
        orphelines += sum(1 for x in g["techniques"] if x not in db.techniques)
        orphelines += sum(1 for x in g["software"] if x not in db.software)
    for s in db.software.values():
        orphelines += sum(1 for x in s["techniques"] if x not in db.techniques)
    for mi in db.mitigations.values():
        orphelines += sum(1 for x in mi["techniques"] if x not in db.techniques)
    for ta in db.tactics.values():
        orphelines += sum(1 for x in ta["techniques"] if x not in db.techniques)
    for t in db.techniques.values():
        orphelines += sum(1 for x in t["mitigations"] if x not in db.mitigations)
        orphelines += sum(1 for x in t["groups"] if x not in db.groups)
        orphelines += sum(1 for x in t["software"] if x not in db.software)
        orphelines += sum(1 for x in t["subtechniques"] if x not in db.techniques)
        orphelines += sum(1 for x in t["tactics"] if x["id"] not in db.tactics)
    for tids in db.datasources.values():
        orphelines += sum(1 for x in tids if x not in db.techniques)
    orphelines += sum(1 for r in db.redirects.values()
                      if r.get("alive") and r["replaced_by"] not in db.techniques)

    print(f"  Integrite   {integrite} anomalie(s) de reciprocite, "
          f"{orphelines} reference(s) orpheline(s)")
    if integrite:
        echecs.append(f"{integrite} anomalies de reciprocite")
    if orphelines:
        echecs.append(f"{orphelines} references orphelines")

    # Referentiel interne : verifie comme le reste, mais son absence n'est
    # jamais un echec (un depot sans referentiel est un cas legitime).
    c = internal.compteurs()
    print(f"Interne     {c['fiche_count']} fiche(s) "
          f"({c['valides']} valide(s), {c['brouillons']} brouillon(s)), "
          f"next_id {c['next_id']}")
    print(f"            {c['fiches_ecartees']} ecartee(s), "
          f"{c['avertissements']} avertissement(s), "
          f"{c['sans_ancrage_mitre']} sans ancrage ATT&CK, "
          f"{c['liens_revoques']} lien(s) revoque(s)")
    print(f"            source : {c['path'] or 'aucune'}")
    for a in internal.anomalies[:20]:
        print(f"            [{a['niveau']}] {a['message']}")
    # Reciprocite de l'index : une fiche indexee doit exister, et une fiche
    # ancree sur une technique vivante doit etre retrouvee par get_technique.
    interne_ko = []
    for tid, fids in internal.by_mitre.items():
        for fid in fids:
            if fid not in internal.fiches:
                interne_ko.append(f"index interne casse : {tid} -> {fid}")
    for fid, f in internal.fiches.items():
        eff = f.get("technique_mitre_effective")
        if eff and eff in db.techniques:
            if fid not in [x["id"] for x in internal.extensions_de(eff)]:
                interne_ko.append(f"{fid} absente de internal_extensions de {eff}")
    for m in interne_ko:
        print(f"            [rejet] {m}")

    anos_bloquantes = [a["message"] for a in internal.anomalies
                       if a["niveau"] == "rejet"] + interne_ko
    if interne_ko:
        echecs.extend(interne_ko)
    elif anos_bloquantes and STRICT_INTERNAL:
        echecs.extend(anos_bloquantes)
    elif anos_bloquantes:
        print(f"            ({len(anos_bloquantes)} fiche(s) ecartee(s) : "
              f"relancer avec --strict pour en faire un echec)")

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
