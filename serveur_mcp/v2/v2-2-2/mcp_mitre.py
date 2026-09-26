#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
#
# Lancement : `uv run mcp_mitre.py` (voir --help). uv fournit l'interpreteur :
# aucune installation de Python ni de dependance n'est requise, le serveur
# n'utilise que la bibliotheque standard.
#
# Version 2.2.2 du serveur MCP MITRE ATT&CK - hybride Enterprise (IT) + ICS (OT)
# + referentiel interne de techniques (fiches THQxxxx).
#
# v2.2 = BASE v2.1 INTEGRALE + NOUVEAUTES. Le socle est le fichier v2.1 :
# tous ses garde-fous (referentiel en lecture seule et preserve, marque
# haute des identifiants, check/ready/ensure/purge, champs reserves,
# extensions_de, alias, --test en code 1) sont conserves tels quels.
# Les nouveautes greffees sont marquees « NOUVEAU v2.2 » :
#   - campagnes ATT&CK (get_campaign, techniques_via_campaigns) ;
#   - equipements ICS (get_asset, relation targets) ;
#   - techniques DEPRECIEES signalees comme telles ;
#   - champ `via` sur les chaines de revocation ;
#   - parent_mitigations pour les sous-techniques ;
#   - recherche refondue : Porter, IDF, acronymes, nom du parent,
#     entites et tactiques comme indices, filtres platform/tactic valides ;
#   - journalisation enrichie (run_id, phases MCP, tool_call detaille) ;
#   - transport --http local (sans authentification, boucle locale) ;
#   - messages multi-lignes, enveloppes JSON-RPC validees, negociation
#     de protocolVersion.
#
# v2.2.1 -- correctifs du moteur de mapping, sans ajout de fonctionnalite ni
# changement de signature :
#   1. _tokens : retour au minimum de TROIS caracteres pour un token
#      alphabetique (v2.1). La v2.2 en acceptait deux, et aucun mot anglais
#      de deux lettres n'est dans _STOPWORDS : 'to' indexait 790 techniques
#      sur 794, 'of' 704, 'or' 662. Le denominateur du score etait gonfle
#      jusqu'a 43 % par des mots vides, et « on or of » sortait un candidat
#      a 0.601, au-dessus du seuil fort, sans reserve.
#   2. Tri : la matrice departage AVANT l'identifiant. Tout identifiant ICS
#      commencant par T0, il passait devant n'importe quel T1xxx : 25 des 26
#      noms partages par les deux matrices renvoyaient la technique
#      industrielle en tete a score identique 1.0. Le champ `homonymes`
#      nomme desormais l'ambiguite.
#   3. Requete d'un seul terme plafonnee sous le seuil fort : la couverture
#      atteignait 1.0 mecaniquement ('windows', 'data', 'service').
#   4. Piste issue d'une entite SEULE plafonnee et marquee : 'apt29' donnait
#      exactement 0.9 a quarante techniques indiscernables.
#   5. Assemblage stdio multi-lignes : accolades comptees hors chaines, une
#      requete ne reste plus sans reponse parce qu'une valeur contient '}'.
#   6. list_internal_techniques : instantane unique (course en mode --http).
#   7. search_internal : meme expansion du jargon que search_techniques.
#
# v2.2.2 -- references CTI internes, sans nouvel outil et SANS TOUCHER AU
# MAPPING. Le referentiel interne a desormais deux parties :
#   - `techniques` : fiches THQxxxx, pour les comportements que MITRE ne
#     couvre pas (identifiant personnalise saisi par l'analyste), avec un
#     champ optionnel `references` (rapports CTI internes : titre + lien) ;
#   - `references_mitre` (NOUVEAU) : surcouche des techniques MITRE EXISTANTES.
#     Une entree par identifiant ATT&CK, qui porte les liens des rapports et
#     referentiels internes. La base MITRE telechargee n'est jamais modifiee.
# Le serveur reste en LECTURE SEULE : il propose le bloc JSON a coller,
# l'analyste l'ecrit dans le fichier.
#   - search_internal (parametre optionnel `matrix`) : cherche aussi dans les
#     titres et liens des rapports, confronte la requete a MITRE avec le
#     moteur de search_techniques (appele tel quel, pas copie), et rend une
#     `proposition` : rapport deja reference / rattacher a Txxxx / rattacher a
#     THQxxxx / nouvelle fiche au prochain identifiant libre ;
#   - get_internal_technique accepte un identifiant MITRE (references de
#     cette technique) ;
#   - list_internal_techniques liste aussi la partie `references_mitre` ;
#   - get_technique et search_techniques : cle ADDITIVE `references_internes`,
#     presente SEULEMENT si des rapports internes sont rattaches.
#   - lancement par `uv run mcp_mitre.py` : metadonnees de script PEP 723 en
#     tete de fichier (aucune dependance, Python >= 3.10 fourni par uv).
# INVARIANT DE NON-REGRESSION : le moteur de score, la tokenisation, l'IDF, le
# tri et les descriptions des outils MITRE sont ceux de la v2.2.1, a l'octet.
# Toute cle d'une reponse v2.2.1 garde la meme valeur en v2.2.2 ; sans rapport
# interne rattache, les reponses des outils MITRE sont identiques a l'octet.
# Seule exception assumee : la `note` de search_internal, qui ne propose plus
# une nouvelle fiche quand MITRE couvre deja le comportement.
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

Nouveautes (v2.2) : get_campaign, get_asset, techniques depreciees
signalees, champ `via` des revocations, parent_mitigations, recherche refondue
(Porter, IDF, acronymes, entites), journalisation enrichie, transport --http.

Correctifs (v2.2.1), sans ajout d'outil ni changement de signature : tokens
alphabetiques a trois caracteres minimum, matrice departagee avant
l'identifiant (champ additif `homonymes`), score plafonne sur une requete d'un
seul terme et sur une piste issue d'une entite seule (`matched.pivot`), index
des noms exacts (`matched.name_exact`), assemblage stdio multi-lignes robuste
aux accolades dans les chaines, instantane unique de list_internal_techniques,
tokenisation de search_internal alignee sur search_techniques.

References CTI internes (v2.2.2), sans nouvel outil ni changement du mapping :
partie `references_mitre` du referentiel (rapports internes rattaches a une
technique ATT&CK existante), champ `references` des fiches THQ, recherche par
titre ou lien de rapport et `proposition` de rattachement dans search_internal,
cle additive `references_internes` dans get_technique et search_techniques
(absente quand rien n'est rattache : reponse identique a la v2.2.1).

Format du referentiel interne :

  {"meta": {"dernier_id_attribue": "THQ0001", ...},
   "techniques": [
     {"id": "THQ0001", "name": "...", "description": "...",
      "statut": "brouillon", "technique_mitre_liee": "T0846",
      "references": [{"titre": "CTI-2026-041", "lien": "https://..."}]}],
   "references_mitre": [
     {"technique_mitre": "T0846",
      "references": [{"titre": "CTI-2026-038", "lien": "https://...",
                      "date": "2026-08-31", "commentaire": "..."}]}]}

Usage (uv fournit l'interpreteur, aucune installation de Python requise):
  uv run mcp_mitre.py             Demarre le serveur MCP (stdio).
  uv run mcp_mitre.py --http      Sert le protocole en HTTP local, sans
                                  authentification (clients non-stdio : n8n).
  uv run mcp_mitre.py --test      Verifie la base et sort en code 1 si KO.
  uv run mcp_mitre.py --strict    Avec --test : les anomalies du referentiel
                                  interne sont elles aussi bloquantes.
  uv run mcp_mitre.py --no-audit  Demarre sans journal d'audit.
  uv run mcp_mitre.py --help      Affiche ce message.

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
import math
import uuid
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from datetime import datetime

for _s in (sys.stdin, sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

SERVER_NAME = "mcp-mitre-attack"
SERVER_VERSION = "2.2.2"

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
    # NOUVEAU v2.2.2 -- cles produites par le serveur pour les references.
    "references_internes", "proposition", "rapports", "mitre_candidats",
    "type_entree",
))
INTERNAL_MAX_NAME = 200
INTERNAL_MAX_DESC = 4000

# NOUVEAU v2.2.2 -- references CTI internes (rapports, referentiels maison).
# Une reference = un titre (c'est lui qu'on cherche par son nom) et un lien
# interne ; `date` et `commentaire` sont optionnels. Une reference invalide est
# ecartee SEULE, avec son motif : la fiche ou l'entree qui la porte reste.
INTERNAL_MITRE_SECTION = "references_mitre"
INTERNAL_REF_FIELDS = ("titre", "lien", "date", "commentaire")
INTERNAL_MAX_REFS = 100          # references par fiche ou par entree
INTERNAL_MAX_REF_TITLE = 300
INTERNAL_MAX_REF_LINK = 2000
INTERNAL_MAX_REF_NOTE = 1000
INTERNAL_REF_LIST_CAP = 20       # references montrees par technique
INTERNAL_MITRE_CANDIDATES = 3    # candidats MITRE rendus par search_internal

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

# NOUVEAU v2.2 -- get_datasources : nombre de techniques renvoyees, reglable.
DS_DEFAULT_LIMIT = 60
DS_MAX_LIMIT = 300

# NOUVEAU v2.2 -- poids des indices de recherche : chaque mot de la requete
# compte UNE fois, au meilleur poids obtenu, de sorte que le score reste une
# couverture [0..1].
W_NAME = 1.0                 # mot du nom
W_ALIAS = 1.0                # acronyme defini dans la description (RDP, WMI)
W_PARENT = 0.8               # mot du nom de la technique PARENTE
W_ENTITY = 0.8               # nom/alias d'un groupe, software ou campagne
W_TACTIC = 0.6               # nom d'une tactique de la technique
W_DESC = 0.35                # mot de la description
BONUS_PHRASE = 0.15          # requete entiere presente dans le nom
BONUS_ENTITY = 0.1           # une entite de la requete utilise la technique

# CORRECTIF 2.2.1 -- plafonds de calibration. Le score est une COUVERTURE de
# la requete : avec un seul mot significatif, la couverture atteint 1.0 des
# que ce mot figure dans un nom, et « windows », « data » ou « service »
# renvoyaient trois techniques a 1.0 chacune. De meme, une requete reduite au
# nom d'un groupe ou d'un outil (« apt29 ») attribuait exactement 0.9 - donc
# « candidat fort » - a quarante techniques indiscernables. Ni l'un ni l'autre
# n'est un mapping : ce sont des pistes. Elles restent renvoyees, mais sous le
# seuil fort, et la note dit quoi faire ensuite.
SCORE_SHORT_QUERY_CAP = 0.59   # requete d'un seul mot, nom non identique
SCORE_ENTITY_ONLY_CAP = 0.45   # seule preuve : l'entite utilise la technique
MIN_QUERY_TOKENS = 2           # en deca, la requete est dite trop courte

# CORRECTIF 2.2.1 -- ordre de matrice a score egal. Le dernier critere de
# departage etait l'identifiant : tout identifiant ICS commencant par « T0 »,
# il passait avant n'importe quel « T1xxx » en ordre lexical. Sur les 26 noms
# portes par les DEUX matrices, 25 renvoyaient la technique industrielle en
# tete, a score identique 1.0 et sans aucun signal ('valid accounts' ->
# T0859 avant T1078). Enterprise passe desormais en premier a egalite
# parfaite, et l'ambiguite est nommee dans la reponse.
MATRIX_RANK = {"Enterprise": 0, "ICS": 1}

# NOUVEAU v2.2 -- alias de tactiques (jargon d'analyste).
_TACTIC_ALIASES = {"c2": "command-and-control", "exfil": "exfiltration",
                   "privesc": "privilege-escalation", "recon": "reconnaissance"}

# NOUVEAU v2.2 -- journalisation : RUN_ID identifie une execution du serveur ;
# toutes les lignes d'audit d'une meme session le portent (correlation).
RUN_ID = uuid.uuid4().hex[:12]
AUDIT_ARG_MAX = 512          # troncature des arguments journalises en clair

# NOUVEAU v2.2 -- protocoles MCP acceptes a l'initialisation. La version
# demandee est rendue si elle est connue, sinon la plus recente du serveur.
SUPPORTED_PROTOCOLS = ("2024-11-05", "2025-03-26", "2025-06-18")
DEFAULT_PROTOCOL = "2024-11-05"

# NOUVEAU v2.2 -- acces reseau LOCAL (mode --http). ATTENTION : aucune
# authentification. Ce mode existe pour les clients qui ne parlent pas stdio
# (n8n : SSE / HTTP Streamable). Ecoute limitee par defaut a 127.0.0.1 :
# ne pas l'exposer sur un reseau.
MCP_HTTP_HOST = os.environ.get("MCP_HTTP_HOST", "127.0.0.1")
MCP_HTTP_PORT = int(os.environ.get("MCP_HTTP_PORT", "8733"))
MCP_HTTP_MAX_BODY = 1 * 1024 * 1024          # 1 Mo (aussi le tampon stdio)

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
        # NOUVEAU v2.2 -- les pertes sont comptees, jamais tues.
        self._dropped = 0
        self._dlock = threading.Lock()
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
            with self._dlock:
                self._dropped += 1

    def _drain_dropped(self):
        """NOUVEAU v2.2 -- publie et remet a zero le compteur de pertes."""
        with self._dlock:
            n, self._dropped = self._dropped, 0
        if n:
            return {"ts": datetime.now().isoformat(), "run_id": RUN_ID,
                    "event": "audit_dropped", "count": n,
                    "reason": "file d'audit saturee"}
        return None

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
            lost = self._drain_dropped()
            if lost:
                batch.append(lost)
            self._flush(batch)
        batch = []                       # drain final : rien n'est perdu
        while True:
            try:
                batch.append(self._q.get_nowait())
            except queue.Empty:
                break
        lost = self._drain_dropped()
        if lost:
            batch.append(lost)
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
        _audit.write({"ts": datetime.now().isoformat(), "run_id": RUN_ID,
                      "event": event, **data})


#  NOUVEAU v2.2 -- resumes d'audit : tracabilite sans exposer plus que necessaire

def _client_info(params) -> dict:
    """Identite du client a l'initialisation, quel que soit le fil MCP."""
    params = params if isinstance(params, dict) else {}
    ci = params.get("clientInfo")
    if not isinstance(ci, dict):
        meta = params.get("_meta")
        ci = meta.get("clientInfo") if isinstance(meta, dict) else None
    if not isinstance(ci, dict):
        return {}
    out = {}
    if ci.get("name"):
        out["client"] = str(ci["name"])[:64]
    if ci.get("version"):
        out["client_version"] = str(ci["version"])[:32]
    return out


def _args_summary(args) -> dict:
    """Arguments d'un appel d'outil, en clair, chaque valeur tronquee."""
    if not isinstance(args, dict) or not args:
        return {}
    out = {}
    for k, v in args.items():
        raw = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False,
                                                      default=str)
        out[str(k)[:32]] = raw[:AUDIT_ARG_MAX]
    return out


def _result_summary(payload: str) -> dict:
    """Resume non sensible du resultat : volume et qualite du mapping."""
    out = {"bytes": len(payload or "")}
    try:
        o = json.loads(payload)
    except Exception:
        return out
    if not isinstance(o, dict):
        return out
    for k in ("result_count", "total_matches"):
        if isinstance(o.get(k), int):
            out[k] = o[k]
    res = o.get("results")
    if isinstance(res, list) and res and isinstance(res[0], dict):
        if "score" in res[0]:
            out["top_score"] = res[0]["score"]
        if "id" in res[0]:
            out["top_id"] = res[0]["id"]
    if o.get("note"):
        out["note"] = str(o["note"])[:120]
    return out


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
# NOUVEAU v2.2.2 -- identifiant ATT&CK de technique, forme normalisee.
_MITRE_TECH_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_CITATION_RE = re.compile(r"\(Citation:[^)]*\)")
_MD_LINK_RE = re.compile(r"\[([^\]]*)\]\([^)]*\)")
# NOUVEAU v2.2 -- balises HTML reelles uniquement : les espaces reserves de
# commandes (<PID>, <username>, <DOMAIN>) font partie du sens du texte.
_TAG_RE = re.compile(
    r"</?(?:code|br|b|i|em|strong|pre|p|a|ul|ol|li|span|div|sup|sub|tt|kbd|"
    r"h[1-6]|table|tr|td|th)(?:\s[^>]{0,80})?/?>", re.I)
_COMPOUND_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)+")
# Acronyme defini dans une description : « Remote Desktop Protocol (RDP) ».
_ACRONYM_RE = re.compile(
    r"((?:[A-Z][A-Za-z0-9-]*\s+){1,6}[A-Z][A-Za-z0-9-]*)\s*\(([A-Z][A-Za-z0-9]{1,9})\)")

# NOUVEAU v2.2 -- jargon d'analyste -> vocabulaire ATT&CK, applique a la
# REQUETE seulement : le corpus emploie deja le vocabulaire canonique.
_SYNONYMS = {
    "creds": ["credentials"], "cred": ["credentials"],
    "passwd": ["password"], "pwd": ["password"], "passwords": ["password"],
    "exfil": ["exfiltration"], "exfiltrate": ["exfiltration"],
    "privesc": ["privilege", "escalation"],
    "c2": ["c2"], "cnc": ["c2"], "c&c": ["c2"],
    "beacon": ["beacon", "cobalt", "strike"],
    "http": ["http", "web"], "https": ["https", "http", "web"],
    "ioc": ["indicator"], "iocs": ["indicator"],
    "av": ["antivirus"], "antimalware": ["antivirus"],
    "2fa": ["mfa", "multi", "factor"], "mfa": ["mfa", "multi", "factor"],
    "rce": ["remote", "code", "execution"],
    "lolbin": ["signed", "binary", "proxy", "execution"],
    "lolbins": ["signed", "binary", "proxy", "execution"],
    "lolbas": ["signed", "binary", "proxy", "execution"],
    "ransom": ["ransomware"],
    "ot": ["ot", "operational", "technology"],
    "ics": ["ics", "industrial", "control", "system"],
    "scada": ["scada", "supervisory", "control"],
}


def _porter(w: str) -> str:
    """NOUVEAU v2.2 -- racinisation de Porter (1980), fidele et compacte, sans
    dependance. La v2.1 fusionnait 'lsass' et 'lsa' ; 'base' et 'based'
    n'etaient pas relies. Appliquee a l'identique requete et corpus : seule la
    coherence compte, pas la lisibilite de la racine."""
    if len(w) <= 2:
        return w

    def cons(t, i):
        c = t[i]
        if c in "aeiou":
            return False
        if c == "y":
            return i == 0 or not cons(t, i - 1)
        return True

    def m(t):
        n, i, L = 0, 0, len(t)
        while i < L and cons(t, i):
            i += 1
        while i < L:
            while i < L and not cons(t, i):
                i += 1
            if i >= L:
                break
            n += 1
            while i < L and cons(t, i):
                i += 1
        return n

    def has_vowel(t):
        return any(not cons(t, i) for i in range(len(t)))

    def double_c(t):
        return len(t) >= 2 and t[-1] == t[-2] and cons(t, len(t) - 1)

    def cvc(t):
        L = len(t)
        return (L >= 3 and cons(t, L - 1) and not cons(t, L - 2)
                and cons(t, L - 3) and t[-1] not in "wxy")

    if w.endswith("sses"):
        w = w[:-2]
    elif w.endswith("ies"):
        w = w[:-2]
    elif w.endswith("ss"):
        pass
    elif w.endswith("s"):
        w = w[:-1]
    if w.endswith("eed"):
        if m(w[:-3]) > 0:
            w = w[:-1]
    else:
        stem = None
        if w.endswith("ed") and has_vowel(w[:-2]):
            stem = w[:-2]
        elif w.endswith("ing") and has_vowel(w[:-3]):
            stem = w[:-3]
        if stem is not None:
            w = stem
            if w.endswith(("at", "bl", "iz")):
                w += "e"
            elif double_c(w) and w[-1] not in "lsz":
                w = w[:-1]
            elif m(w) == 1 and cvc(w):
                w += "e"
    if w.endswith("y") and has_vowel(w[:-1]):
        w = w[:-1] + "i"
    for suf, rp in (("ational", "ate"), ("tional", "tion"), ("enci", "ence"),
                    ("anci", "ance"), ("izer", "ize"), ("abli", "able"),
                    ("alli", "al"), ("entli", "ent"), ("eli", "e"),
                    ("ousli", "ous"), ("ization", "ize"), ("ation", "ate"),
                    ("ator", "ate"), ("alism", "al"), ("iveness", "ive"),
                    ("fulness", "ful"), ("ousness", "ous"), ("aliti", "al"),
                    ("iviti", "ive"), ("biliti", "ble"), ("logi", "log")):
        if w.endswith(suf):
            if m(w[: -len(suf)]) > 0:
                w = w[: -len(suf)] + rp
            break
    for suf, rp in (("icate", "ic"), ("ative", ""), ("alize", "al"),
                    ("iciti", "ic"), ("ical", "ic"), ("ful", ""), ("ness", "")):
        if w.endswith(suf):
            if m(w[: -len(suf)]) > 0:
                w = w[: -len(suf)] + rp
            break
    for suf in ("al", "ance", "ence", "er", "ic", "able", "ible", "ant",
                "ement", "ment", "ent", "ion", "ou", "ism", "ate", "iti",
                "ous", "ive", "ize"):
        if w.endswith(suf):
            stem = w[: -len(suf)]
            if suf == "ion" and not stem.endswith(("s", "t")):
                break
            if m(stem) > 1:
                w = stem
            break
    if w.endswith("e"):
        stem = w[:-1]
        mm = m(stem)
        if mm > 1 or (mm == 1 and not cvc(stem)):
            w = stem
    if w.endswith("ll") and m(w) > 1:
        w = w[:-1]
    return w


_stem_cache = {}


def _stem(w: str) -> str:
    """Racine d'un mot (memoisee). Les tokens contenant un chiffre (c2, t1003,
    sha256, 2fa) sont conserves tels quels."""
    r = _stem_cache.get(w)
    if r is None:
        r = w if any(c.isdigit() for c in w) else _porter(w)
        _stem_cache[w] = r
    return r


def _fold(text: str) -> str:
    """Retire les diacritiques AVANT la tokenisation. Sans ce pliage, le motif
    [a-z0-9]+ coupe le mot a chaque accent : 'privileges' devient
    {'privil', 'ges'} et ne converge jamais avec 'privileges' non accentue.
    Le referentiel interne etant redige en francais, cette convergence
    conditionne l'anti-doublon de search_internal."""
    return "".join(c for c in unicodedata.normalize("NFD", text or "")
                   if unicodedata.category(c) != "Mn")


def _tokens(text: str, synonyms: bool = False) -> set:
    """Tokens significatifs racinises, accents plies (v2.1 : le referentiel
    interne est en francais). NOUVEAU v2.2 : les mots composes
    (« side-loading ») donnent aussi leur forme soudee, et le lexique de
    jargon n'est applique qu'a la REQUETE (synonyms=True) — le corpus ATT&CK
    emploie deja le vocabulaire canonique."""
    out = set()
    low = _fold(text or "").lower()
    words = _TOKEN_RE.findall(low)
    for comp in _COMPOUND_RE.findall(low):
        words.append(comp.replace("-", ""))
    for w in words:
        for x in (_SYNONYMS.get(w, (w,)) if synonyms else (w,)):
            if x in _STOPWORDS:
                continue
            # CORRECTIF 2.2.1 -- un token ALPHABETIQUE fait au moins trois
            # caracteres, comme en v2.1 ; seuls les tokens porteurs d'un
            # chiffre (c2, 2fa, t1003, sha256) sont gardes des deux.
            # La v2.2 acceptait deux caracteres pour tout le monde, et aucun
            # mot anglais de deux lettres ne figure dans _STOPWORDS : 'to'
            # entrait dans l'index de 790 techniques sur 794, 'of' de 704,
            # 'or' de 662. Toute requete ecrite en anglais naturel embarquait
            # ainsi un a trois tokens presents partout, qui gonflaient le
            # denominateur du score (jusqu'a 43 % de la requete), abaissaient
            # les bons candidats sous le seuil « fort », et permettaient a une
            # requete de pure grammaire (« on or of ») de sortir un candidat
            # a 0.601 sans la moindre reserve.
            if len(x) < (2 if any(c.isdigit() for c in x) else 3):
                continue
            t = _stem(x)
            if t and t not in _STOPWORDS:
                out.add(t)
    return out


def _acronyms(description: str) -> set:
    """NOUVEAU v2.2 -- acronymes definis dans la description, valides par
    leurs initiales : « Remote Desktop Protocol (RDP) » -> {'rdp'}."""
    out = set()
    for m_ in _ACRONYM_RE.finditer(description or ""):
        phrase, acr = m_.group(1), m_.group(2)
        words = [x for x in re.split(r"[\s-]+", phrase) if x]
        initials = "".join(x[0] for x in words).upper()
        caps = "".join(c for c in phrase if c.isupper())
        a = acr.upper()
        ok = initials.endswith(a)
        if not ok:
            it = iter(caps)
            ok = all(ch in it for ch in a)
        if ok and len(acr) >= 2:
            out.add(acr.lower())
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


def _platform_filter(value) -> str:
    """NOUVEAU v2.2 -- une plateforme inconnue est une ERREUR explicite : la
    v2.1 renvoyait zero resultat en silence, que l'agent lisait comme
    « pas de mapping »."""
    v = _validate(value, 32, "platform").lower()
    if not v:
        return ""
    if v not in {p.lower() for p in db.platforms}:
        raise ValueError(f"platform inconnue {value!r} : attendu une valeur "
                         f"parmi {', '.join(sorted(db.platforms))}")
    return v


def _tactic_filter(value):
    """NOUVEAU v2.2 -- identifiant, shortname ou nom de tactique -> ensemble
    d'identifiants. Une valeur inconnue est une erreur explicite."""
    v = _validate(value, 48, "tactic").lower()
    if not v:
        return set()
    ids = {tid for tid, t in db.tactics.items()
           if v == tid.lower() or v == t["shortname"].lower()
           or v == t["name"].lower()
           or v.replace(" ", "-") == t["shortname"].lower()}
    if not ids:
        known = sorted({t["shortname"] for t in db.tactics.values()})
        raise ValueError(f"tactic inconnue {value!r} : attendu un id TAxxxx, "
                         f"un nom ou un shortname parmi {', '.join(known)}")
    return ids


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


def _query_weights(q_tok, idf=None):
    """NOUVEAU v2.2 -- poids de rarete (IDF) de chaque mot de la requete ; un
    mot inconnu du corpus recoit le poids moyen des mots connus. Sans corpus
    d'IDF (referentiel interne), tous les mots pesent 1.0 : le score retombe
    exactement sur la formule v2.1."""
    idf = idf or {}
    known = [idf[t] for t in q_tok if t in idf]
    default_w = (sum(known) / len(known)) if known else 1.0
    w = {t: idf.get(t, default_w) for t in q_tok}
    return w, (sum(w.values()) or 1.0)


def _lexical_score(w, total_w, ql, buckets, names):
    """Fonction de score commune a search_techniques et search_internal.

    Un SEUL exemplaire du calcul : les deux recherches ne peuvent pas diverger
    au fil des versions, et la promesse « memes regles que la recherche MITRE »
    est vraie par construction plutot que par relecture.

    `buckets` : [(etiquette, poids, tokens deja depuplies)]. Chaque token de
    la REQUETE compte une fois, au meilleur poids obtenu : le score mesure la
    couverture de la requete. La phrase complete presente dans un des `names`
    ajoute BONUS_PHRASE. Resultat borne a [0..1] ; `exact` signale un nom
    strictement egal a la requete (departage)."""
    gain = 0.0
    matched = {}
    for label, poids, toks in buckets:
        if toks:
            gain += poids * sum(w[x] for x in toks)
            matched[label] = sorted(toks)
    if gain <= 0:
        return 0.0, {}, False
    base = gain / total_w
    exact = False
    fql = _fold(ql or "").lower()
    for nm in names:
        fn = _fold(nm or "").lower()
        if fql and fql in fn:
            base += BONUS_PHRASE
            matched["phrase"] = True
            exact = (fql == fn)
            break
    return min(base, 1.0), matched, exact


#  Base de connaissance MITRE ATT&CK (Enterprise + ICS)

class MitreDB:

    def __init__(self, autoload=True):
        self.tactics = {}       # TA0006     -> dict (matrix: chaine)
        self.techniques = {}    # T1003      -> dict (matrix: chaine)
        self.mitigations = {}   # M1027      -> dict (matrix: chaine)
        self.groups = {}        # G0016      -> dict (matrices: liste)
        self.software = {}      # S0002      -> dict (matrices: liste)
        # NOUVEAU v2.2 -- campagnes, equipements ICS, depreciees, index de
        # recherche (rarete des tokens, entites nommees, noms de tactiques).
        self.campaigns = {}     # C0024      -> dict (matrices: liste)
        self.assets = {}        # A0003      -> dict (matrix: chaine, ICS)
        self.deprecated = {}    # Txxxx depreciee sans remplacant -> {name, matrix}
        self.platforms = set()  # plateformes connues (filtre valide)
        self.entities = []      # (tokens, kind, id, nom) groupes/software/campagnes
        self.tactic_index = []  # (tokens, id tactique)
        # CORRECTIF 2.2.1 -- index des noms EXACTS, independant de la
        # tokenisation : une technique doit rester trouvable par son nom meme
        # quand celui-ci ne produit aucun token significatif (T1053.002 « At »).
        self.name_index = {}    # nom plie en minuscules -> [ids de techniques]
        self.idf = {}           # token -> poids de rarete
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
        partis_a = {k for k, v in self.assets.items()
                    if v.get("matrix") == matrix}
        for store in (self.tactics, self.techniques, self.mitigations,
                      self.assets):
            for k in [k for k, v in store.items() if v.get("matrix") == matrix]:
                del store[k]
        # Un groupe ou un software present dans les deux matrices survit a la
        # purge de l'une d'elles : seuls ceux qui n'ont plus aucune matrice
        # disparaissent, et eux seuls doivent etre deferences.
        partis_g, partis_s, partis_c = set(), set(), set()
        for store, partis in ((self.groups, partis_g), (self.software, partis_s),
                              (self.campaigns, partis_c)):
            for k, v in list(store.items()):
                if matrix in v["matrices"]:
                    v["matrices"].remove(matrix)
                if not v["matrices"]:
                    partis.add(k)
                    del store[k]
        for g in self.groups.values():
            g["techniques"] = [t for t in g["techniques"] if t not in partis_t]
            g["software"] = [s for s in g["software"] if s not in partis_s]
            g["campaigns"] = [c for c in g["campaigns"] if c not in partis_c]
        for s in self.software.values():
            s["techniques"] = [t for t in s["techniques"] if t not in partis_t]
        for c in self.campaigns.values():
            c["techniques"] = [t for t in c["techniques"] if t not in partis_t]
            c["software"] = [x for x in c["software"] if x not in partis_s]
            c["groups"] = [x for x in c["groups"] if x not in partis_g]
        for a in self.assets.values():
            a["techniques"] = [t for t in a["techniques"] if t not in partis_t]
        for mi in self.mitigations.values():
            mi["techniques"] = [t for t in mi["techniques"] if t not in partis_t]
        for ta in self.tactics.values():
            ta["techniques"] = [t for t in ta["techniques"] if t not in partis_t]
        for t in self.techniques.values():
            t["mitigations"] = [x for x in t["mitigations"] if x not in partis_m]
            t["groups"] = [x for x in t["groups"] if x not in partis_g]
            t["software"] = [x for x in t["software"] if x not in partis_s]
            t["campaigns"] = [x for x in t["campaigns"] if x not in partis_c]
            t["assets"] = [x for x in t["assets"] if x not in partis_a]
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
        for aid in [k for k, v in self.deprecated.items()
                    if v.get("matrix") == matrix]:
            del self.deprecated[aid]
        # NOUVEAU v2.2 -- les index DERIVES de la recherche citent des
        # groupes, software, campagnes et tactiques : les laisser en place
        # apres une purge, c'est garder des references vers des objets
        # partis, exactement ce que le reste de cette methode s'emploie a
        # eviter. Ils sont reconstruits integralement par _finalize().
        self.idf = {}
        self.entities = []
        self.tactic_index = []
        self.name_index = {}
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
                  "campaigns", "assets", "deprecated", "platforms",
                  "entities", "tactic_index", "idf", "name_index",
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
                    if o.get("revoked"):
                        revoked[o["id"]] = (aid, o.get("name", ""))
                    else:
                        # NOUVEAU v2.2 -- depreciee SANS remplacant : a
                        # signaler comme telle, pas comme une faute de frappe.
                        self.deprecated[aid] = {"name": o.get("name", ""),
                                                "matrix": matrix}
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
                clean = _clean_text(desc)
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
                    "campaigns": [], "assets": [],
                    "url": self._url(o),
                    "_tok_name": _tokens(o.get("name", "")),
                    "_tok_parent": set(),
                    # NOUVEAU v2.2 -- acronymes de la description indexes au
                    # poids du nom (« rdp », « wmi »).
                    "_tok_alias": set(_stem(a) for a in _acronyms(clean)),
                    "_tok_desc": _tokens(clean),
                    "_snippet": _snippet(desc),
                    "_acronyms": sorted(_acronyms(clean)),
                }
                self.platforms.update(o.get("x_mitre_platforms", []))
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
                    "campaigns": [], "url": self._url(o),
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
            elif ot == "campaign" and aid:
                # NOUVEAU v2.2 -- MITRE rattache une part des techniques d'un
                # groupe a ses CAMPAGNES : les ignorer ampute le profil reel.
                c = self.campaigns.setdefault(aid, {
                    "id": aid, "name": o.get("name", ""),
                    "description": o.get("description", ""),
                    "aliases": o.get("aliases", []),
                    "first_seen": (o.get("first_seen") or "")[:10],
                    "last_seen": (o.get("last_seen") or "")[:10],
                    "matrices": [], "techniques": [], "software": [],
                    "groups": [], "url": self._url(o),
                })
                if matrix not in c["matrices"]:
                    c["matrices"].append(matrix)
            elif ot == "x-mitre-asset" and aid:
                # NOUVEAU v2.2 -- equipements ICS (PLC, HMI, RTU...).
                self.assets[aid] = {
                    "id": aid, "name": o.get("name", ""), "matrix": matrix,
                    "description": o.get("description", ""),
                    "platforms": o.get("x_mitre_platforms", []),
                    "sectors": o.get("x_mitre_sectors", []),
                    "techniques": [], "url": self._url(o),
                }
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
                                         "name": self.tactics[ta]["name"],
                                         "shortname": self.tactics[ta]["shortname"]})

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
                elif s_ext in self.campaigns:
                    # NOUVEAU v2.2 -- technique observee dans une campagne.
                    if t_ext not in self.campaigns[s_ext]["techniques"]:
                        self.campaigns[s_ext]["techniques"].append(t_ext)
                    if s_ext not in self.techniques[t_ext]["campaigns"]:
                        self.techniques[t_ext]["campaigns"].append(s_ext)
            elif rt == "uses" and t_ext in self.software:
                if s_ext in self.groups:
                    if t_ext not in self.groups[s_ext]["software"]:
                        self.groups[s_ext]["software"].append(t_ext)
                elif s_ext in self.campaigns:
                    if t_ext not in self.campaigns[s_ext]["software"]:
                        self.campaigns[s_ext]["software"].append(t_ext)
            elif (rt == "attributed-to" and s_ext in self.campaigns
                    and t_ext in self.groups):
                # NOUVEAU v2.2 -- campagne attribuee a un groupe.
                if t_ext not in self.campaigns[s_ext]["groups"]:
                    self.campaigns[s_ext]["groups"].append(t_ext)
                if s_ext not in self.groups[t_ext]["campaigns"]:
                    self.groups[t_ext]["campaigns"].append(s_ext)
            elif (rt == "targets" and s_ext in self.techniques
                    and t_ext in self.assets):
                # NOUVEAU v2.2 -- une technique ICS vise un equipement.
                if t_ext not in self.techniques[s_ext]["assets"]:
                    self.techniques[s_ext]["assets"].append(t_ext)
                if s_ext not in self.assets[t_ext]["techniques"]:
                    self.assets[t_ext]["techniques"].append(s_ext)

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
        # Redirections resolues TRANSITIVEMENT (herite v2.1). NOUVEAU v2.2 :
        # le champ `via` conserve les sauts intermediaires pour la
        # tracabilite (T1073 -> T1574.002 -> T1574.001).
        for old in list(self.redirects):
            cur = self.redirects[old]["replaced_by"]
            seen = {old}
            via = []
            hops = 0
            while cur in self.redirects and cur not in seen and hops < 10:
                seen.add(cur)
                via.append(cur)
                cur = self.redirects[cur]["replaced_by"]
                hops += 1
            self.redirects[old]["replaced_by"] = cur
            self.redirects[old]["alive"] = cur in self.techniques
            if via:
                self.redirects[old]["via"] = via
        for t in self.techniques.values():
            t["subtechniques"].sort()
        for ta in self.tactics.values():
            ta["techniques"].sort()
        # NOUVEAU v2.2 -- nom du parent dans l'index des sous-techniques,
        # comme sur le site ATT&CK (« OS Credential Dumping: LSASS Memory »).
        for tid, t in self.techniques.items():
            p = (self.techniques.get(t["parent_id"])
                 if t["is_subtechnique"] else None)
            t["_tok_parent"] = (set(p["_tok_name"]) - t["_tok_name"]) if p else set()
            t["_tok_desc"] = t["_tok_desc"] - t["_tok_name"] - t["_tok_parent"]
        # NOUVEAU v2.2 -- IDF : rarete de chaque token parmi les techniques.
        df = {}
        for t in self.techniques.values():
            for tok in (t["_tok_name"] | t["_tok_parent"] | t["_tok_alias"]
                        | t["_tok_desc"]):
                df[tok] = df.get(tok, 0) + 1
        n = max(len(self.techniques), 1)
        self.idf = {tok: 1.0 + math.log(n / (1.0 + d)) for tok, d in df.items()}
        # NOUVEAU v2.2 -- entites nommees (groupes, software, campagnes) :
        # nom + alias -> techniques utilisees, indices de mapping.
        self.entities = []
        for kind, coll in (("groups", self.groups), ("software", self.software),
                           ("campaigns", self.campaigns)):
            for eid, e in coll.items():
                if not e["techniques"]:
                    continue
                for nm in {e["name"], *e.get("aliases", [])}:
                    tok = _tokens(nm)
                    if tok:
                        self.entities.append((frozenset(tok), kind, eid, nm))
        # CORRECTIF 2.2.1 -- index des noms exacts (nom court ET nom complet
        # « Parente: Sous-technique »), plie et en minuscules.
        self.name_index = {}
        for tid, t in self.techniques.items():
            p = (self.techniques.get(t["parent_id"])
                 if t["is_subtechnique"] else None)
            noms = {t["name"]}
            if p:
                noms.add(f"{p['name']}: {t['name']}")
            for nm in noms:
                cle = _fold(nm or "").lower().strip()
                if cle:
                    self.name_index.setdefault(cle, [])
                    if tid not in self.name_index[cle]:
                        self.name_index[cle].append(tid)
        # NOUVEAU v2.2 -- noms de tactiques comme indices, plus le jargon.
        self.tactic_index = [(frozenset(_tokens(t["name"])), tid)
                             for tid, t in self.tactics.items()
                             if _tokens(t["name"])]
        for alias, short in _TACTIC_ALIASES.items():
            for tid, t in self.tactics.items():
                if t["shortname"] == short:
                    self.tactic_index.append((frozenset({_stem(alias)}), tid))


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
        # NOUVEAU v2.2.2 -- partie `references_mitre` : rapports internes
        # rattaches a une technique ATT&CK EXISTANTE (la base MITRE n'est
        # jamais modifiee, la surcouche vit ici).
        self.refs_mitre = {}      # T0846 (declare) -> entree normalisee
        self.refs_by_mitre = {}   # T0846 (declare + vivant) -> [T0846, ...]
        self.rapports = []        # index de recherche des references

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
            self.refs_mitre, self.refs_by_mitre, self.rapports = {}, {}, []
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

        # NOUVEAU v2.2.2 -- partie `references_mitre`, OPTIONNELLE : un
        # referentiel v2.2.1 (sans cette cle) se charge a l'identique. Une
        # partie mal formee est ignoree avec un avertissement ; elle ne fait
        # jamais perdre les fiches THQ.
        refs_mitre, refs_by_mitre = {}, {}
        brut_refs = data.get(INTERNAL_MITRE_SECTION)
        if brut_refs is not None and not isinstance(brut_refs, list):
            anomalies.append({"niveau": "avertissement",
                              "fiche": INTERNAL_MITRE_SECTION,
                              "message": f"'{INTERNAL_MITRE_SECTION}' doit etre "
                                         f"une liste : partie ignoree"})
            brut_refs = None
        for brute in brut_refs or []:
            entree, anos = self._normalise_ref_mitre(brute, refs_mitre)
            anomalies.extend(anos)
            if entree:
                refs_mitre[entree["technique_mitre"]] = entree
        for tid, e in refs_mitre.items():
            for key in (e["technique_mitre"], e["technique_mitre_effective"]):
                if key:
                    refs_by_mitre.setdefault(key, [])
                    if tid not in refs_by_mitre[key]:
                        refs_by_mitre[key].append(tid)
        for ids in refs_by_mitre.values():
            ids.sort()

        self.fiches, self.by_mitre = fiches, by_mitre
        self.refs_mitre, self.refs_by_mitre = refs_mitre, refs_by_mitre
        self.rapports = self._index_rapports(fiches, refs_mitre)
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

        # NOUVEAU v2.2.2 -- rapports CTI internes qui documentent la fiche.
        refs, anos_refs = self._refs(brute.get("references"), fid)
        anos.extend(anos_refs)
        fiche["references"] = refs

        fiche["_tok_name"] = _tokens(fiche["name"])
        fiche["_tok_desc"] = _tokens(_clean_text(fiche["description"]))
        fiche["_snippet"] = _snippet(fiche["description"])
        return fiche, anos, num

    # NOUVEAU v2.2.2 -- references CTI internes

    @staticmethod
    def _refs(raw, owner):
        """Valide une liste de references {titre, lien[, date, commentaire]}.
        Renvoie (references valides, anomalies). Une reference invalide est
        ecartee SEULE ; titre et lien sont obligatoires : le titre pour
        retrouver le rapport par son nom, le lien pour l'ouvrir."""
        anos = []

        def avert(msg):
            anos.append({"niveau": "avertissement", "fiche": owner,
                         "message": f"{owner} : {msg}"})
            log.warning(f"Referentiel interne : {owner} : {msg}")

        if raw is None:
            return [], anos
        if not isinstance(raw, list):
            avert("'references' doit etre une liste d'objets "
                  "{titre, lien} : champ ignore")
            return [], anos
        if len(raw) > INTERNAL_MAX_REFS:
            avert(f"{len(raw)} references, seules les {INTERNAL_MAX_REFS} "
                  f"premieres sont chargees")
        out, vus = [], set()
        for i, r in enumerate(raw[:INTERNAL_MAX_REFS], start=1):
            if not isinstance(r, dict):
                avert(f"reference n{i} ecartee : objet {{titre, lien}} attendu")
                continue
            titre = " ".join(str(r.get("titre", "") or "").split())
            lien = str(r.get("lien", "") or "").strip()
            if not titre or not lien:
                avert(f"reference n{i} ecartee : 'titre' et 'lien' sont "
                      f"obligatoires")
                continue
            if any(ord(c) < 32 for c in lien) or " " in lien:
                avert(f"reference n{i} ({titre[:60]}) ecartee : lien invalide")
                continue
            cle = lien.lower()
            if cle in vus:
                avert(f"reference n{i} ({titre[:60]}) ecartee : lien deja "
                      f"cite dans la meme entree")
                continue
            vus.add(cle)
            if (len(titre) > INTERNAL_MAX_REF_TITLE
                    or len(lien) > INTERNAL_MAX_REF_LINK):
                avert(f"reference n{i} : titre ou lien tronque")
            ref = {"titre": titre[:INTERNAL_MAX_REF_TITLE],
                   "lien": lien[:INTERNAL_MAX_REF_LINK]}
            for opt in ("date", "commentaire"):
                v = " ".join(str(r.get(opt, "") or "").split())
                if v:
                    ref[opt] = v[:INTERNAL_MAX_REF_NOTE]
            out.append(ref)
        return out, anos

    def _normalise_ref_mitre(self, brute, deja):
        """Valide une entree de la partie `references_mitre`. Renvoie
        (entree|None, anomalies). La technique citee doit etre un identifiant
        ATT&CK : un comportement que MITRE ne couvre pas se declare en fiche
        THQ dans `techniques`, pas ici."""
        anos = []
        sec = INTERNAL_MITRE_SECTION

        def rejet(ident, msg):
            # Portee prefixee (« references_mitre:T0846 ») : une anomalie de
            # cette partie ne s'affiche jamais sur une fiche THQ homonyme.
            anos.append({"niveau": "rejet",
                         "fiche": f"{sec}:{ident}" if ident != sec else sec,
                         "message": msg})
            log.warning(f"Entree {sec} ecartee : {msg}")
            return None, anos

        if not isinstance(brute, dict):
            return rejet(sec, f"entree non-objet dans '{sec}'")
        declare = _norm_id(str(brute.get("technique_mitre", "") or ""))
        if not declare:
            return rejet(sec, f"entree de '{sec}' sans 'technique_mitre'")
        if INTERNAL_ID_RE.match(declare):
            return rejet(declare, f"{declare} : un identifiant interne se "
                                  f"declare dans 'techniques', pas dans "
                                  f"'{sec}'")
        if not _MITRE_TECH_RE.match(declare):
            return rejet(declare, f"technique_mitre invalide {declare!r} "
                                  f"(format attendu T0000 ou T0000.000)")
        if declare in deja:
            return rejet(declare, f"{declare} : entree dupliquee dans '{sec}' "
                                  f"- regrouper ses references dans une "
                                  f"seule entree")
        refs, anos_refs = self._refs(brute.get("references"), declare)
        for a in anos_refs:
            a["fiche"] = f"{sec}:{declare}"
        anos.extend(anos_refs)
        if not refs:
            return rejet(declare, f"{declare} : aucune reference valide, "
                                  f"entree ignoree")
        effectif, lien_revoque = declare, None
        if declare in db.redirects:
            r = db.redirects[declare]
            effectif = r["replaced_by"] if r.get("alive") else None
            lien_revoque = {"declare": declare,
                            "replaced_by": r["replaced_by"],
                            "remplacant_vivant": bool(r.get("alive"))}
            msg = (f"{declare} ({sec}) est revoquee par MITRE, remplacee par "
                   f"{r['replaced_by']} : references rattachees au remplacant"
                   + ("" if r.get("alive")
                      else " (remplacant absent de la base)"))
            anos.append({"niveau": "avertissement",
                         "fiche": f"{sec}:{declare}", "message": msg})
            log.warning(msg)
        elif declare in db.deprecated:
            msg = (f"{declare} ({sec}) est DEPRECIEE par MITRE sans "
                   f"remplacant : references conservees, a reclasser")
            anos.append({"niveau": "avertissement",
                         "fiche": f"{sec}:{declare}", "message": msg})
            log.warning(msg)
        elif db.techniques and declare not in db.techniques:
            msg = (f"{declare} ({sec}) inconnue de la base ATT&CK chargee : "
                   f"references visibles seulement via "
                   f"get_internal_technique")
            anos.append({"niveau": "avertissement",
                         "fiche": f"{sec}:{declare}", "message": msg})
            log.warning(msg)
            effectif = None
        return {"technique_mitre": declare,
                "technique_mitre_effective": effectif,
                "lien_revoque": lien_revoque,
                "references": refs}, anos

    @staticmethod
    def _index_rapports(fiches, refs_mitre):
        """Index de recherche des references des DEUX parties. Il est
        propre au referentiel interne : il n'entre jamais dans le vocabulaire
        ni dans l'IDF de la recherche MITRE, qui restent ceux de la v2.2.1."""
        out = []

        def add(ref, kind, ident, effectif):
            out.append({
                **ref, "type_cible": kind, "cible": ident,
                "cible_effective": effectif,
                "_titre_f": _fold(ref["titre"]).lower(),
                "_lien_f": ref["lien"].lower(),
                "_tok_titre": _tokens(ref["titre"]),
                "_tok_lien": _tokens(ref["lien"]),
                "_tok_com": _tokens(ref.get("commentaire", "")),
            })

        for tid in sorted(refs_mitre):
            e = refs_mitre[tid]
            for ref in e["references"]:
                add(ref, "mitre", tid, e["technique_mitre_effective"])
        for fid in sorted(fiches):
            f = fiches[fid]
            for ref in f.get("references", []):
                add(ref, "interne", fid, f.get("technique_mitre_effective"))
        return out

    def references_de(self, tid):
        """Rapports internes qui concernent une technique MITRE : ceux de la
        partie `references_mitre` et ceux des fiches THQ ancrees sur elle, puis
        ceux rattaches a ses sous-techniques (marques `via`). Instantane
        unique : un rechargement concurrent ne peut pas melanger deux etats."""
        refs_by, refs_m = self.refs_by_mitre, self.refs_mitre
        by_m, fiches = self.by_mitre, self.fiches
        items = []

        def depuis(cle, via=None):
            for eid in refs_by.get(cle, []):
                e = refs_m.get(eid)
                for ref in (e["references"] if e else []):
                    x = {**ref, "source": eid}
                    if via:
                        x["via"] = via
                    items.append(x)
            for fid in by_m.get(cle, []):
                f = fiches.get(fid)
                for ref in (f.get("references", []) if f else []):
                    x = {**ref, "source": fid}
                    if via:
                        x["via"] = via
                    items.append(x)

        depuis(tid)
        t = db.techniques.get(tid)
        for sub in (t["subtechniques"] if t else []):
            depuis(sub, via=sub)
        return {"count": len(items), "items": items[:INTERNAL_REF_LIST_CAP],
                "truncated": len(items) > INTERNAL_REF_LIST_CAP}

    def chercher_rapports(self, q, q_tok):
        """Recherche par titre ou lien de rapport, avec la fonction de score
        commune (_lexical_score). Titre ou lien strictement egal : 1.0."""
        qf = _fold(q or "").lower().strip()
        ql = q.lower()
        w, total_w = _query_weights(q_tok)
        scored = []
        for rec in self.rapports:
            if qf and (qf == rec["_titre_f"] or qf == rec["_lien_f"]):
                scored.append((1.0, rec, {"exact": ["titre" if qf ==
                                                     rec["_titre_f"]
                                                     else "lien"]}))
                continue
            if not q_tok:
                continue
            hit_t = q_tok & rec["_tok_titre"]
            hit_l = (q_tok & rec["_tok_lien"]) - hit_t
            hit_c = (q_tok & rec["_tok_com"]) - hit_t - hit_l
            score, matched, _ex = _lexical_score(
                w, total_w, ql,
                [("titre", W_NAME, hit_t), ("lien", W_DESC, hit_l),
                 ("commentaire", W_DESC, hit_c)],
                [rec["titre"]])
            if score > 0 and len(q_tok) < MIN_QUERY_TOKENS:
                score = min(score, SCORE_SHORT_QUERY_CAP)
            if score > 0:
                scored.append((round(score, 3), rec, matched))
        scored.sort(key=lambda x: (-x[0], x[1]["cible"], x[1]["titre"]))
        return scored

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
        # NOUVEAU v2.2.2 -- les rejets de la partie references_mitre sont
        # comptes a part : ce ne sont pas des fiches.
        pref = INTERNAL_MITRE_SECTION
        rejets_refs = sum(1 for a in self.anomalies if a["niveau"] == "rejet"
                          and str(a["fiche"]).startswith(pref))
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
            "fiches_ecartees": rejets - rejets_refs,
            "avertissements": len(self.anomalies) - rejets,
            # NOUVEAU v2.2.2
            "references_mitre": len(self.refs_mitre),
            "references_mitre_ecartees": rejets_refs,
            "rapports": len(self.rapports),
            "path": self.path,
            "loaded_at": self.loaded_at,
        }


internal = InternalDB()
internal.load(INTERNAL_DB_PATH)   # apres MITRE : les liens sont verifiables

# NOUVEAU v2.2 -- verrou de bascule (mode --http multi-thread).
_SWAP_LOCK = threading.Lock()


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


def _ajouter_refs(out, tid):
    """NOUVEAU v2.2.2 -- cle ADDITIVE `references_internes`, ajoutee en
    DERNIER et SEULEMENT si des rapports internes sont rattaches : sans
    rattachement, la reponse est identique a l'octet a celle de la v2.2.1, et
    avec rattachement, toutes les autres cles gardent leur valeur et leur
    ordre. Rien ici ne lit ni ne modifie le score."""
    refs = internal.references_de(tid)
    if refs["count"]:
        out["references_internes"] = refs


@tool("get_technique",
      "Detail complet d'une technique Enterprise (T1***) ou ICS (T0***), pour "
      "CONFIRMER un candidat de mapping : description, matrice, tactiques, "
      "plateformes, detections (strategies + analytics + sources de logs), "
      "sous-techniques, groupes, software, campagnes, mitigations (et celles "
      "de la technique PARENTE pour une sous-technique), equipements vises "
      "(ICS). Un identifiant revoque est redirige vers son remplacant vivant "
      "(chaine tracee par `via`) ; un identifiant deprecie est signale comme "
      "tel.",
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
            out = {"db_version": _db_version(), "redirect": True,
                   "requested": tid, "name": r["name"],
                   "replaced_by": r["replaced_by"],
                   "remplacant_vivant": r.get("alive", False),
                   "internal_extensions": internal.extensions_de(tid),
                   "note": f"'{tid}' est revoquee : consulter "
                           f"{r['replaced_by']} via get_technique"}
            if r.get("via"):
                # NOUVEAU v2.2 -- chaine de revocation tracee.
                out["via"] = r["via"]
                out["note"] += (f" (chaine de revocation : "
                                f"{' -> '.join(r['via'])})")
            _ajouter_refs(out, tid)
            return J(out)
        d = db.deprecated.get(tid)
        if d:
            # NOUVEAU v2.2 -- depreciee sans remplacant : dite comme telle.
            return J({"db_version": _db_version(), "deprecated": True,
                      "requested": tid, "name": d["name"],
                      "internal_extensions": internal.extensions_de(tid),
                      "note": f"'{tid}' ({d['name']}) est DEPRECIEE par MITRE "
                              f"sans remplacant : ne plus l'utiliser dans un "
                              f"mapping ; chercher le comportement avec "
                              f"search_techniques"})
        return J({"error": f"Technique '{tid}' non trouvee",
                  "db_version": _db_version()})
    parent = (db.techniques.get(t["parent_id"])
              if t["is_subtechnique"] else None)
    out = {
        "db_version": _db_version(),
        "id": t["id"], "name": t["name"], "matrix": t["matrix"],
        "full_name": (f"{parent['name']}: {t['name']}" if parent else t["name"]),
        "technique_version": t["technique_version"],
        "is_subtechnique": t["is_subtechnique"],
        "parent": ({"id": t["parent_id"], "name": parent["name"]}
                   if parent else None),
        "tactics": t["tactics"], "platforms": t["platforms"],
        "acronyms": t["_acronyms"],
        "description": _clean_text(t["description"]).strip(),
        "detections": t["detections"],
        "legacy_detection": t["legacy_detection"],
        "data_sources": sorted(t["data_sources"]),
        "subtechniques": [{"id": x, "name": db.techniques[x]["name"]}
                          for x in t["subtechniques"] if x in db.techniques],
        "groups": _capped(t["groups"], lambda g: {
            "id": g, "name": db.groups[g]["name"],
            "matrices": db.groups[g]["matrices"]} if g in db.groups else None),
        "software": _capped(t["software"], lambda x: {
            "id": x, "name": db.software[x]["name"],
            "type": db.software[x]["type"]} if x in db.software else None),
        # NOUVEAU v2.2 -- campagnes ou la technique a ete observee.
        "campaigns": _capped(sorted(t["campaigns"]), lambda c: {
            "id": c, "name": db.campaigns[c]["name"],
            "first_seen": db.campaigns[c]["first_seen"],
            "groups": list(db.campaigns[c]["groups"])}
            if c in db.campaigns else None),
        "mitigations": _capped(t["mitigations"], lambda m: {
            "id": m, "name": db.mitigations[m]["name"]}
            if m in db.mitigations else None),
        # Champ ADDITIF : declinaisons internes de cette technique. Les fiches
        # rattachees a une sous-technique portent `via`. Liste vide si le
        # referentiel interne est absent ou ne couvre pas cette technique.
        "internal_extensions": internal.extensions_de(tid),
        "url": t["url"],
    }
    if parent:
        # NOUVEAU v2.2 -- dans ATT&CK, les mesures sont le plus souvent
        # rattachees a la technique PARENTE ; une sous-technique interrogee
        # seule renvoyait une liste courte alors que des mesures valides
        # existent au niveau du parent.
        out["parent_mitigations"] = _capped(parent["mitigations"], lambda m: {
            "id": m, "name": db.mitigations[m]["name"]}
            if m in db.mitigations else None)
    if t["matrix"] == "ICS":
        # NOUVEAU v2.2 -- equipements vises par une technique industrielle.
        out["assets"] = [{"id": a, "name": db.assets[a]["name"]}
                         for a in sorted(t["assets"]) if a in db.assets]
    _ajouter_refs(out, tid)
    return J(out)


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
    out = {"db_version": _db_version(), "technique": t["id"],
           "name": t["name"], "matrix": t["matrix"],
           "count": len(t["mitigations"]),
           "mitigations": [{"id": m, "name": db.mitigations[m]["name"],
                            "matrix": db.mitigations[m]["matrix"],
                            "description": _snippet(
                                db.mitigations[m]["description"], 400)}
                           for m in t["mitigations"] if m in db.mitigations]}
    parent = (db.techniques.get(t["parent_id"])
              if t["is_subtechnique"] else None)
    if parent:
        # NOUVEAU v2.2 -- mesures de la technique PARENTE : c'est la que
        # ATT&CK rattache le plus souvent les mitigations.
        out["parent"] = {"id": parent["id"], "name": parent["name"]}
        out["parent_mitigations"] = [
            {"id": m, "name": db.mitigations[m]["name"],
             "description": _snippet(db.mitigations[m]["description"], 400)}
            for m in parent["mitigations"] if m in db.mitigations]
    return J(out)


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
        # NOUVEAU v2.2 -- groupes relies par une campagne attribuee, avec la
        # campagne comme preuve.
        via_camp = {}
        for c in t["campaigns"]:
            for g in db.campaigns.get(c, {}).get("groups", []):
                if g in t["groups"] or g not in db.groups:
                    continue
                if want and want not in db.groups[g]["matrices"]:
                    continue
                via_camp.setdefault(g, []).append(c)
        return J({"db_version": _db_version(), "technique": tid,
                  "matrix": t["matrix"],
                  "groups": _capped(ids, lambda g: {
                      "id": g, "name": db.groups[g]["name"],
                      "matrices": db.groups[g]["matrices"],
                      "aliases": db.groups[g]["aliases"][:5]}, cap=30),
                  "groups_via_campaigns": _capped(sorted(via_camp), lambda g: {
                      "id": g, "name": db.groups[g]["name"],
                      "campaigns": sorted(via_camp[g])}
                      if g in db.groups else None, cap=30)})
    pool = [g for g in db.groups.values()
            if not want or want in g["matrices"]]
    top = sorted(pool, key=lambda g: (-len(g["techniques"]), g["id"]))[:50]
    return J({"db_version": _db_version(), "matrix_filtre": want or "aucun",
              "count": len(pool),
              "groups": [{"id": g["id"], "name": g["name"],
                          "matrices": g["matrices"],
                          "aliases": g["aliases"][:5],
                          "technique_count": len(g["techniques"]),
                          "campaign_count": len(g["campaigns"])}
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
    # NOUVEAU v2.2 -- techniques observees UNIQUEMENT dans les campagnes
    # attribuees au groupe (APT29 : 53 techniques en plus des 66 directes),
    # et la liste des campagnes elles-memes.
    via = {}
    for c in g["campaigns"]:
        for t in db.campaigns.get(c, {}).get("techniques", []):
            if t not in g["techniques"]:
                via.setdefault(t, []).append(c)
    r["techniques_via_campaigns"] = _capped(sorted(via), lambda t: {
        "id": t, "name": db.techniques[t]["name"],
        "campaigns": sorted(via[t])} if t in db.techniques else None, cap=50)
    r["campaigns"] = [{"id": c, "name": db.campaigns[c]["name"],
                       "first_seen": db.campaigns[c]["first_seen"],
                       "last_seen": db.campaigns[c]["last_seen"]}
                      for c in sorted(g["campaigns"]) if c in db.campaigns]
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


@tool("get_campaign",
      "NOUVEAU v2.2 -- detail d'une campagne ATT&CK (Cxxxx), par identifiant, "
      "nom ou alias : periode, groupes attribues, techniques et software "
      "observes. Utile quand un rapport CTI nomme une operation "
      "('SolarWinds Compromise', 'Operation Dream Job').",
      {"id": ("string", True, "ex: C0024 ou SolarWinds Compromise")},
      aliases=("mitre_campaign",))
def get_campaign(id):
    q = _validate(id, MAX_ID_LEN, "id")
    c, mode, cands = _resolve(db.campaigns, q)
    if not c:
        return J({"error": f"Campagne '{q}' non trouvee",
                  "db_version": _db_version()})
    r = {"db_version": _db_version(),
         "id": c["id"], "name": c["name"], "aliases": c["aliases"],
         "matrices": c["matrices"],
         "first_seen": c["first_seen"], "last_seen": c["last_seen"],
         "description": _snippet(c["description"], 500),
         "groups": [{"id": g, "name": db.groups[g]["name"]}
                    for g in sorted(c["groups"]) if g in db.groups],
         "techniques": _capped(sorted(c["techniques"]), lambda t: {
             "id": t, "name": db.techniques[t]["name"],
             "matrix": db.techniques[t]["matrix"]}
             if t in db.techniques else None, cap=100),
         "software": _capped(sorted(c["software"]), lambda x: {
             "id": x, "name": db.software[x]["name"]}
             if x in db.software else None, cap=50),
         "url": c["url"]}
    if mode == "partiel":
        r["resolution"] = {"mode": "partiel", "candidats": cands}
    return J(r)


@tool("get_asset",
      "NOUVEAU v2.2 -- equipement ICS (Axxxx : PLC, HMI, RTU, historian, "
      "safety controller...) et les techniques ICS qui le visent. Sans "
      "argument : liste des equipements. Point d'entree pour partir d'un "
      "inventaire OT plutot que d'un extrait de journal.",
      {"id": ("string", False, "ex: A0003 ou Programmable Logic Controller")},
      aliases=("mitre_asset",))
def get_asset(id=""):
    if not id:
        return J({"db_version": _db_version(), "assets": [{
            "id": a, "name": x["name"],
            "technique_count": len(x["techniques"])}
            for a, x in sorted(db.assets.items())]})
    q = _validate(id, MAX_ID_LEN, "id")
    a, mode, cands = _resolve(db.assets, q)
    if not a:
        return J({"error": f"Equipement '{q}' non trouve",
                  "db_version": _db_version()})
    r = {"db_version": _db_version(),
         "id": a["id"], "name": a["name"], "matrix": a["matrix"],
         "sectors": a["sectors"], "platforms": a["platforms"],
         "description": _snippet(a["description"], 400),
         "techniques": _capped(sorted(a["techniques"]), lambda t: {
             "id": t, "name": db.techniques[t]["name"]}
             if t in db.techniques else None, cap=100),
         "url": a["url"]}
    if mode == "partiel":
        r["resolution"] = {"mode": "partiel", "candidats": cands}
    return J(r)


@tool("get_datasources",
      "Techniques observables a partir d'une source de donnees, d'un "
      "composant ou d'un canal de logs. Requetes valides : Process Creation, "
      "WinEventLog:Security, auditd:SYSCALL, AWS:CloudTrail. Les listes sont "
      "bornees (drapeau truncated) ; NOUVEAU v2.2 : limite reglable.",
      {"query": ("string", True, "ex: Process Creation, auditd, WinEventLog"),
       "matrix": ("string", False, "Restreint a Enterprise ou ICS"),
       "limit": ("integer", False,
                 f"Nombre max de techniques (defaut {DS_DEFAULT_LIMIT}, "
                 f"max {DS_MAX_LIMIT})")},
      aliases=("mitre_datasources",))
def get_datasources(query, matrix="", limit=DS_DEFAULT_LIMIT):
    try:
        limit = max(1, min(int(limit), DS_MAX_LIMIT))
    except (TypeError, ValueError):
        limit = DS_DEFAULT_LIMIT

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
              "techniques": {"count": len(ordered), "items": ordered[:limit],
                             "truncated": len(ordered) > limit}})


@tool("search_techniques",
      "Recherche LEXICALE de techniques candidates (mots entiers racinises, "
      "pas de semantique). METHODE : 1) UNE requete = UN comportement "
      "atomique, en mots-cles ANGLAIS ATT&CK (ex 'lsass credential "
      "dumping'). Les noms de groupes, software, campagnes et tactiques "
      "presents dans la requete ('mimikatz', 'apt29', 'lateral movement') "
      "servent d'indices. 2) Les resultats sont des CANDIDATS avec un score "
      "normalise [0..1] - >= 0.6 fort, < 0.3 faible - et des preuves "
      "(matched.name / alias / parent_name / tactic / groups / software / "
      "description). 3) VERIFIER chaque candidat retenu avec get_technique "
      "avant d'affirmer un mapping ; retenir la technique PARENTE par "
      "defaut, la sous-technique seulement si l'evidence la confirme. 4) Une "
      "liste vide ou uniquement des scores faibles signifie 'pas de "
      "mapping' : conclusion valide, ne pas forcer. Un filtre invalide "
      "renvoie une erreur, jamais une liste vide. 5) PRECISER matrix : 26 "
      "noms existent a l'identique en Enterprise et en ICS (Valid Accounts, "
      "Screen Capture, Masquerading...) ; sans filtre les deux sont "
      "renvoyees et le champ `homonymes` les signale. 6) Une requete d'UN "
      "SEUL mot, ou reduite au nom d'un groupe ou d'un outil, ne peut pas "
      "depasser le seuil fort : ce sont des pistes, pas des mappings.",
      {"query": ("string", True, "Mots-cles ou identifiant (ex: T1003.001)"),
       "limit": ("integer", False,
                 f"Nombre max de resultats (defaut {SEARCH_DEFAULT_LIMIT}, "
                 f"max {SEARCH_MAX_LIMIT})"),
       "matrix": ("string", False, "Filtre Enterprise ou ICS (aussi IT/OT/SCADA)"),
       "platform": ("string", False, "Filtre plateforme (ex: Windows, Linux)"),
       "tactic": ("string", False,
                  "Filtre tactique : id TAxxxx, shortname (ex "
                  "'credential-access') ou nom (ex 'Credential Access')")},
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
    fp = _platform_filter(platform) if platform else ""
    ft = _tactic_filter(tactic) if tactic else set()

    ql = " ".join(q.lower().split())
    # NOUVEAU v2.2 -- le jargon d'analyste est traduit cote requete.
    q_tok = _tokens(ql, synonyms=True)

    # Identifiants presents dans la requete (un ou plusieurs) ; un identifiant
    # revoque redirige la recherche, un deprecie est signale.
    ids_like = []
    for m_ in _ID_IN_TEXT_RE.finditer(ql):
        tid = _norm_id(m_.group(0))
        if tid in db.redirects:
            r = db.redirects[tid]
            notes.append(f"'{tid}' ({r['name']}) est revoquee, remplacee par "
                         f"{r['replaced_by']} : recherche redirigee")
            tid = r["replaced_by"]
        elif tid in db.deprecated:
            notes.append(f"'{tid}' ({db.deprecated[tid]['name']}) est "
                         f"depreciee par MITRE sans remplacant")
        if tid not in ids_like:
            ids_like.append(tid)

    # CORRECTIF 2.2.1 -- correspondance de NOM EXACT, independante de la
    # tokenisation. Sans elle, une technique dont le nom ne produit aucun
    # token significatif reste introuvable par son propre nom : T1053.002
    # s'appelle « At », deux caracteres, aucun token.
    exact_ids = set(db.name_index.get(_fold(ql).lower().strip(), []))

    if not q_tok and not ids_like and not exact_ids:
        return J({"db_version": _db_version(), "query": q, "result_count": 0,
                  "total_matches": 0, "results": [],
                  "note": "aucun terme significatif dans la requete"})

    # NOUVEAU v2.2 -- ponderation par rarete (IDF) des mots de la requete.
    w, total_w = _query_weights(q_tok, db.idf)

    # NOUVEAU v2.2 -- entites nommees dans la requete (groupe / software /
    # campagne) : leurs mots comptent pour les techniques qu'elles utilisent.
    ent_hits = {}      # id technique -> [(kind, id, nom)]
    ent_tokens = {}    # id technique -> tokens de l'alias reconnu
    ent_found = []
    for tok, kind, eid, nm in db.entities:
        if tok <= q_tok:
            # L'index est reconstruit a chaque _finalize() ; on ne
            # dereference jamais un identifiant sans verifier qu'il est
            # encore la, pour qu'une bascule de base concurrente ne puisse
            # pas transformer une recherche en exception.
            e = getattr(db, kind, {}).get(eid)
            if e is None:
                continue
            ent_found.append((kind, eid, nm))
            for tid in e["techniques"]:
                ent_hits.setdefault(tid, []).append((kind, eid, nm))
                ent_tokens.setdefault(tid, set()).update(tok)
    # NOUVEAU v2.2 -- tactiques nommees dans la requete (nom ou jargon).
    tac_hits = {}
    for tok, ta in db.tactic_index:
        if tok <= q_tok and ta in db.tactics:
            tac_hits.setdefault(ta, set()).update(tok)

    def keep(t):
        if fm and t["matrix"] != fm:
            return False
        if fp and not any(fp == p.lower() for p in t["platforms"]):
            return False
        if ft and not any(ta["id"] in ft for ta in t["tactics"]):
            return False
        return True

    scored = []
    for tid, t in db.techniques.items():
        if not keep(t):
            continue
        score = 0.0
        matched = {}
        nom_exact = tid in exact_ids
        if nom_exact:
            score = 1.0
            matched["name_exact"] = [t["name"]]
        if ids_like:
            if tid in ids_like:
                score = 1.0
                matched["id"] = [tid]
            elif any(tid.startswith(x + ".") or x.startswith(tid + ".")
                     for x in ids_like):
                score = 0.7
                matched["id"] = [x for x in ids_like
                                 if tid.startswith(x + ".")
                                 or x.startswith(tid + ".")]
        # Couches d'indices, chaque token compte UNE fois au meilleur poids.
        hit_name = q_tok & t["_tok_name"]
        hit_alias = (q_tok & t["_tok_alias"]) - hit_name
        hit_parent = (q_tok & t["_tok_parent"]) - hit_name - hit_alias
        seen = hit_name | hit_alias | hit_parent
        hit_entity = ent_tokens.get(tid, set()) - seen
        seen |= hit_entity
        hit_tactic = set()
        for ta in t["tactics"]:
            if ta["id"] in tac_hits:
                hit_tactic |= tac_hits[ta["id"]] - seen
        seen |= hit_tactic
        hit_desc = (q_tok & t["_tok_desc"]) - seen
        parent = (db.techniques.get(t["parent_id"])
                  if t["is_subtechnique"] else None)
        full_name = (f"{parent['name']}: {t['name']}" if parent else t["name"])
        s_lex, matched_lex, exact = _lexical_score(
            w, total_w, ql,
            [("name", W_NAME, hit_name), ("alias", W_ALIAS, hit_alias),
             ("parent_name", W_PARENT, hit_parent),
             ("entity", W_ENTITY, hit_entity),
             ("tactic", W_TACTIC, hit_tactic),
             ("description", W_DESC, hit_desc)],
            [t["name"], full_name])
        # CORRECTIF 2.2.1 -- une technique dont la SEULE preuve est « une
        # entite nommee dans la requete l'utilise » n'est pas un candidat de
        # mapping : c'est un pivot. Elle reste renvoyee, sous le seuil fort,
        # et la note renvoie vers get_group / get_software pour la liste
        # faisant foi. Sans ce plafond, « apt29 » attribuait exactement 0.9 -
        # donc « candidat fort » - a quarante techniques departagees par la
        # seule longueur de leur nom.
        entite_seule = bool(hit_entity) and not (hit_name or hit_alias
                                                 or hit_parent or hit_tactic
                                                 or hit_desc)
        if s_lex > 0:
            if entite_seule:
                s_lex = min(s_lex, SCORE_ENTITY_ONLY_CAP)
            if tid in ent_hits:
                if not entite_seule:
                    s_lex = min(s_lex + BONUS_ENTITY, 1.0)
                for kind, eid, nm in ent_hits[tid]:
                    matched_lex.setdefault(kind, [])
                    if f"{eid} {nm}" not in matched_lex[kind]:
                        matched_lex[kind].append(f"{eid} {nm}")
            matched_lex.pop("entity", None)
            score = max(score, s_lex)
            matched.update(matched_lex)
        if score > 0:
            # CORRECTIF 2.2.1 -- requete trop courte pour conclure. Le score
            # mesure la couverture de la requete : avec un seul mot
            # significatif, un nom qui contient ce mot atteint 1.0
            # mecaniquement. « windows », « data », « service » sortaient
            # ainsi trois techniques a 1.0 chacune. Le plafond ne s'applique
            # ni a un identifiant explicite (branche ids_like, verifiable),
            # ni a un nom STRICTEMENT egal a la requete.
            if (len(q_tok) < MIN_QUERY_TOKENS and not exact and not nom_exact
                    and not matched.get("id")):
                score = min(score, SCORE_SHORT_QUERY_CAP)
            # NOUVEAU v2.2 -- couverture du nom par la requete (departage) ;
            # un acronyme reconnu vaut le nom entier.
            precision = (len(hit_name) / len(t["_tok_name"])
                         if t["_tok_name"] else 0.0)
            if hit_alias:
                precision = 1.0
            if entite_seule and not nom_exact:
                matched["pivot"] = "entite seule : piste, pas un mapping"
            scored.append((round(score, 3), exact or nom_exact, precision,
                           tid, t, full_name, matched))

    # A score egal : nom exactement egal a la requete, puis nom le mieux
    # couvert, puis technique parente avant sous-technique (regle de
    # precision CISA/MITRE), puis MATRICE (Enterprise avant ICS), puis nom le
    # plus court, puis identifiant.
    # CORRECTIF 2.2.1 -- le rang de matrice est intercale ici. Sans lui, le
    # dernier critere etait l'identifiant, et « T0859 » passait devant
    # « T1078 » en ordre lexical : sur les 26 noms partages par les deux
    # matrices, 25 renvoyaient la technique industrielle en tete a score
    # identique. Sous filtre matrix= le critere est neutre (une seule matrice
    # en lice) ; sans filtre, le contexte IT redevient le defaut et
    # l'ambiguite est explicitee dans `homonymes`.
    scored.sort(key=lambda x: (-x[0], not x[1], -x[2],
                               x[4]["is_subtechnique"],
                               MATRIX_RANK.get(x[4]["matrix"], 9),
                               len(x[4]["name"]), x[3]))
    top = scored[:n_limit]
    results = [{"id": tid, "name": t["name"], "full_name": full_name,
                "matrix": t["matrix"],
                "score": sc, "is_subtechnique": t["is_subtechnique"],
                "parent_id": t["parent_id"],
                "tactics": [ta["id"] for ta in t["tactics"]],
                "matched": matched, "matched_in": sorted(matched),
                "snippet": t["_snippet"]}
               for sc, _e, _p, tid, t, full_name, matched in top]

    # CORRECTIF 2.2.1 -- ambiguite de matrice nommee plutot que subie. Deux
    # techniques de matrices differentes portant le MEME nom parmi les
    # candidats renvoyes : l'agent doit le savoir, et savoir quoi faire.
    homonymes = []
    if not fm:
        par_nom = {}
        for r in results:
            par_nom.setdefault(r["name"].lower(), []).append(r)
        for nom, lst in par_nom.items():
            if len({r["matrix"] for r in lst}) > 1:
                homonymes.append({"name": lst[0]["name"],
                                  "techniques": [{"id": r["id"],
                                                  "matrix": r["matrix"]}
                                                 for r in lst]})
        if homonymes:
            notes.append(f"{len(homonymes)} nom(s) present(s) dans LES DEUX "
                         f"matrices (voir `homonymes`) : preciser "
                         f"matrix='Enterprise' pour un contexte IT, "
                         f"matrix='ICS' pour un contexte industriel")

    if not results:
        notes.append("aucun candidat : l'absence de mapping est une "
                     "conclusion valide")
    elif results[0]["score"] < SCORE_WEAK:
        notes.append("correspondances faibles uniquement : l'absence de "
                     "mapping est une conclusion valide")

    # CORRECTIF 2.2.1 -- la requete est trop courte pour trancher : le dire,
    # au lieu de servir un score de couverture trivialement parfait.
    if results and len(q_tok) < MIN_QUERY_TOKENS and not ids_like:
        notes.append(f"requete d'un seul terme : score plafonne a "
                     f"{SCORE_SHORT_QUERY_CAP}, aucun candidat ne peut etre "
                     f"declare fort - reformuler en un comportement atomique "
                     f"(ex 'lsass credential dumping')")
    # CORRECTIF 2.2.1 -- pistes issues d'une entite seule : dire que ce ne
    # sont pas des candidats de mapping et renvoyer vers la source qui fait foi.
    if results and all(r["matched"].get("pivot") for r in results):
        quoi = ", ".join(f"{eid} {nm}" for _k, eid, nm in ent_found[:3])
        notes.append(f"aucune correspondance lexicale : ces techniques sont "
                     f"seulement celles utilisees par {quoi} - liste faisant "
                     f"foi via get_group / get_software / get_campaign, pas "
                     f"un mapping du comportement decrit")
    # CORRECTIF 2.2.1 -- coherence avec la methode annoncee par l'outil : si
    # le candidat de tete est une SOUS-technique et que sa parente est elle
    # aussi candidate, rappeler la regle du niveau parent par defaut.
    if results and results[0]["is_subtechnique"]:
        pid = results[0]["parent_id"]
        if any(r["id"] == pid for r in results[1:]):
            notes.append(f"le candidat de tete est une SOUS-technique ; sa "
                         f"parente {pid} est aussi candidate - retenir {pid} "
                         f"si l'evidence ne distingue pas la sous-technique")

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
    if homonymes:
        out["homonymes"] = homonymes
    if ent_found:
        out["entities"] = [{"kind": k, "id": e, "name": n}
                           for k, e, n in ent_found]
    if tac_hits:
        out["tactics_in_query"] = [{"id": ta, "name": db.tactics[ta]["name"]}
                                   for ta in sorted(tac_hits)]
    if notes:
        out["note"] = " | ".join(notes)
    # NOUVEAU v2.2.2 -- rapports internes des candidats renvoyes. Calcule
    # APRES le classement, a partir de `results` deja fige : ne peut changer
    # ni un score, ni un rang, ni la note. Cle absente si rien n'est rattache.
    refs = {}
    for r in results:
        x = internal.references_de(r["id"])
        if x["count"]:
            refs[r["id"]] = x
    if refs:
        out["references_internes"] = refs
    return J(out)


#  Outils du referentiel interne (THQ) - lecture seule

@tool("list_internal_techniques",
      "Referentiel INTERNE : liste complete des fiches THQ (comportements que "
      "MITRE ne couvre pas), metadonnees, PROCHAIN IDENTIFIANT LIBRE, et "
      "partie `references_mitre` (techniques ATT&CK existantes auxquelles des "
      "rapports CTI internes sont rattaches). Le referentiel est en LECTURE "
      "SEULE : le serveur ne cree jamais de fiche ni de reference, il fournit "
      "l'identifiant et le bloc a coller ; l'ajout reel est un acte humain "
      "(edition du fichier JSON, puis commit).",
      {"statut": ("string", False, "Filtre 'valide' ou 'brouillon' (optionnel)")},
      aliases=("internal_list",))
def list_internal_techniques(statut=""):
    f_statut = _validate(statut, 24, "statut").lower() if statut else ""
    if f_statut and f_statut not in INTERNAL_STATUTS:
        raise ValueError(f"statut '{statut}' inconnu - valeurs acceptees : "
                         f"{', '.join(INTERNAL_STATUTS)}")
    # CORRECTIF 2.2.1 -- un SEUL instantane du referentiel pour toute la
    # reponse. La version precedente listait `internal.fiches.values()` puis
    # re-interrogeait `internal.fiches` par identifiant via resume() : en
    # mode --http (multi-thread), un internal_reload concurrent remplacait le
    # dictionnaire entre les deux et resume() renvoyait None, non filtre.
    # Mesure : 92 reponses sur 601 923 annoncaient `result_count: 12` avec
    # une liste de douze `null`.
    snap = internal.fiches
    fiches = [f for f in sorted(snap.values(), key=lambda x: x["id"])
              if not f_statut or f.get("statut") == f_statut]
    items = [{"id": f["id"], "name": f.get("name", ""),
              "statut": f.get("statut", INTERNAL_DEFAULT_STATUT),
              "technique_mitre_liee": f.get("technique_mitre_liee")}
             for f in fiches[:INTERNAL_LIST_CAP]]
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
           "fiche_count": len(snap),
           "result_count": len(fiches),
           "next_id": internal.next_id(),
           "fiches": items,
           "truncated": len(fiches) > INTERNAL_LIST_CAP,
           "compteurs": internal.compteurs()}
    # NOUVEAU v2.2.2 -- partie `references_mitre` (instantane unique).
    refs_m = internal.refs_mitre
    lst = []
    for tid in sorted(refs_m)[:INTERNAL_LIST_CAP]:
        e = refs_m[tid]
        eff = e["technique_mitre_effective"]
        lst.append({"technique_mitre": tid,
                    "technique_mitre_effective": eff,
                    "name": (db.techniques[eff]["name"]
                             if eff and eff in db.techniques else None),
                    "reference_count": len(e["references"]),
                    "titres": [r["titre"] for r in e["references"][:5]]})
    out["references_mitre"] = lst
    out["references_mitre_count"] = len(refs_m)
    if internal.anomalies:
        out["anomalies"] = internal.anomalies[:20]
    if not snap:
        out["note"] = ("referentiel interne vide : toute proposition part de "
                       f"{internal.next_id()}")
    return J(out)


def _mitre_resume(tid):
    """NOUVEAU v2.2.2 -- identite ATT&CK d'un identifiant, ou None."""
    t = db.techniques.get(tid) if tid else None
    if not t:
        return None
    return {"id": tid, "name": t["name"], "matrix": t["matrix"],
            "tactics": [x["id"] for x in t["tactics"]]}


def _detail_references_mitre(tid):
    """NOUVEAU v2.2.2 -- get_internal_technique sur un identifiant MITRE :
    les rapports internes rattaches a cette technique ATT&CK."""
    if tid in db.redirects and db.redirects[tid].get("alive"):
        vivant = db.redirects[tid]["replaced_by"]
    else:
        vivant = tid
    entrees = [internal.refs_mitre[e]
               for e in sorted(set(internal.refs_by_mitre.get(tid, []))
                               | set(internal.refs_by_mitre.get(vivant, [])))
               if e in internal.refs_mitre]
    refs = internal.references_de(vivant)
    ext = internal.extensions_de(vivant)
    out = {"db_version": _db_version(), "lecture_seule": True,
           "type_entree": INTERNAL_MITRE_SECTION, "requested": tid,
           "technique_mitre": _mitre_resume(vivant),
           "entrees": entrees, "references_internes": refs,
           "internal_extensions": ext}
    if vivant != tid:
        out["note"] = f"'{tid}' est revoquee, remplacee par {vivant}"
    if not entrees and not refs["count"]:
        out["error"] = f"Aucune reference interne rattachee a '{tid}'"
        out["hint"] = ("search_internal avec le nom du comportement ou du "
                       "rapport rend le bloc JSON a coller dans "
                       f"'{INTERNAL_MITRE_SECTION}'")
    portees = {f"{INTERNAL_MITRE_SECTION}:{x}" for x in (tid, vivant)}
    anos = [a for a in internal.anomalies if a["fiche"] in portees]
    if anos:
        out["anomalies"] = anos
    return J(out)


@tool("get_internal_technique",
      "Detail d'une entree du referentiel INTERNE. Avec un id THQxxxx : la "
      "fiche, ses rapports CTI (`references`) et la technique MITRE liee "
      "resolue (remplacant vivant indique si MITRE l'a revoquee). Avec un id "
      "ATT&CK (T1566.002, T0846) : les rapports internes rattaches a cette "
      "technique (partie `references_mitre` et fiches THQ ancrees dessus).",
      {"id": ("string", True, "ex: THQ0001, ou T0846 pour les references "
                              "internes d'une technique MITRE")},
      aliases=("internal_technique",))
def get_internal_technique(id):
    fid = _validate(id, MAX_ID_LEN, "id").strip().upper()
    f = internal.fiches.get(fid)
    if not f and _MITRE_TECH_RE.match(_norm_id(fid)):
        # NOUVEAU v2.2.2 -- identifiant ATT&CK : references internes.
        return _detail_references_mitre(_norm_id(fid))
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
      "Recherche dans le referentiel INTERNE, avec exactement la meme fonction "
      "de score que search_techniques (mots entiers racinises, score normalise "
      "[0..1], preuves par tokens) : fiches THQ (`results`) et rapports CTI "
      "internes par titre ou lien (`rapports`). Confronte aussi la requete a "
      "MITRE avec le moteur de search_techniques (`mitre_candidats`) et rend "
      "une `proposition` : rapport deja reference, rattacher la reference a "
      "la technique MITRE trouvee, rattacher a une fiche THQ existante, "
      "departager des candidats MITRE faibles, ou creer une fiche au "
      "prochain identifiant libre. Le serveur n'ecrit "
      "jamais : la proposition est un bloc JSON a coller par l'analyste. "
      "OBLIGATOIRE avant de proposer une nouvelle fiche THQ. Ne remplace "
      "jamais la recherche MITRE : pour mapper un comportement, "
      "search_techniques d'abord.",
      {"query": ("string", True, "Mots-cles du comportement, nom de "
                                 "technique, titre ou lien de rapport, ou un "
                                 "id THQxxxx / Txxxx"),
       "limit": ("integer", False,
                 f"Nombre max de resultats (defaut {SEARCH_DEFAULT_LIMIT}, "
                 f"max {SEARCH_MAX_LIMIT})"),
       "matrix": ("string", False, "Enterprise, ICS, ou vide : filtre des "
                                   "candidats MITRE de la proposition")},
      aliases=("internal_search",))
def search_internal(query, limit=SEARCH_DEFAULT_LIMIT, matrix=""):
    q = _validate(query, MAX_QUERY_LEN, "query")
    _matrix(matrix)   # NOUVEAU v2.2.2 -- matrice invalide : erreur explicite
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
    # CORRECTIF 2.2.1 -- meme expansion du jargon que search_techniques. La
    # v2.2 appelait _tokens(ql) ici et _tokens(ql, synonyms=True) la-bas : le
    # meme enonce d'analyste franchissait le seuil fort cote MITRE et restait
    # sous le seuil cote interne ('exfil cloud' : 1.0 contre 0.5, 'privesc' :
    # 1.0 contre aucun resultat), ce qui declenchait a tort la note « aucune
    # fiche interne similaire » et invitait a creer un doublon.
    q_tok = _tokens(ql, synonyms=True)
    if not q_tok and not direct:
        return J({**base_out, "result_count": 0, "total_matches": 0,
                  "results": [],
                  "note": "aucun terme significatif dans la requete"})
    # Coeur de score COMMUN a search_techniques (voir _lexical_score) ; sans
    # corpus d'IDF, chaque mot pese 1.0 : formule v2.1 a l'identique.
    w, total_w = _query_weights(q_tok)
    for fid, f in internal.fiches.items():
        if direct is not None and fid == direct["id"]:
            continue
        hit_name = q_tok & f["_tok_name"]
        hit_desc = (q_tok & f["_tok_desc"]) - hit_name
        score, matched, _exact = _lexical_score(
            w, total_w, ql,
            [("name", W_NAME, hit_name), ("description", W_DESC, hit_desc)],
            [f["name"]])
        if score > 0:
            scored.append((round(score, 3), f, matched))
    scored.sort(key=lambda x: (-x[0], x[1]["id"]))

    results = [{"id": f["id"], "name": f.get("name", ""),
                "statut": f.get("statut", INTERNAL_DEFAULT_STATUT),
                "technique_mitre_liee": f.get("technique_mitre_liee"),
                "score": s, "matched": matched, "matched_in": sorted(matched),
                "snippet": f.get("_snippet", "")}
               for s, f, matched in scored[:n_limit]]

    # NOUVEAU v2.2.2 -- rapports CTI internes (titre, lien, commentaire).
    rap_scored = internal.chercher_rapports(q, q_tok)
    rapports = [{"titre": rec["titre"], "lien": rec["lien"],
                 **({"date": rec["date"]} if rec.get("date") else {}),
                 "rattache_a": {"type": rec["type_cible"], "id": rec["cible"],
                                "technique_mitre_effective":
                                    rec["cible_effective"]},
                 "score": sc, "matched": m, "matched_in": sorted(m)}
                for sc, rec, m in rap_scored[:n_limit]]

    # NOUVEAU v2.2.2 -- confrontation a MITRE. Le moteur de search_techniques
    # est APPELE tel quel (pas copie) : memes candidats, memes scores que
    # l'outil de mapping. Rien n'est ecrit en retour dans la recherche MITRE.
    mitre_cands, mitre_ok, homonymes = [], False, None
    if db.ready and db.techniques:
        try:
            st = json.loads(search_techniques(
                q, limit=INTERNAL_MITRE_CANDIDATES, matrix=matrix or ""))
            mitre_ok = True
            homonymes = st.get("homonymes")
            refs_st = st.get("references_internes", {})
            for r in st.get("results", []):
                c = {"id": r["id"], "name": r["name"],
                     "full_name": r["full_name"], "matrix": r["matrix"],
                     "score": r["score"], "tactics": r["tactics"],
                     "matched_in": r["matched_in"]}
                if r["matched"].get("pivot"):
                    c["pivot"] = True
                if r["id"] in refs_st:
                    c["reference_count"] = refs_st[r["id"]]["count"]
                mitre_cands.append(c)
        except Exception as e:
            log.warning(f"search_internal : confrontation MITRE impossible "
                        f"({type(e).__name__})")
    top_m = next((c for c in mitre_cands if not c.get("pivot")), None)
    fort_m = bool(top_m and top_m["score"] >= SCORE_STRONG)
    fort_f = bool(results and results[0]["score"] >= SCORE_STRONG)
    # Un rapport est « deja reference » s'il est designe par son titre ou son
    # lien exact, ou s'il ressemble fortement a la requete ET qu'aucune
    # technique (MITRE ou fiche THQ) ne couvre la requete : une requete
    # comportementale (« lsass credential dumping ») qui ressemble au titre
    # d'un rapport existant reste une recherche de technique.
    fort_r = bool(rapports and (
        "exact" in rapports[0]["matched"]
        or (rapports[0]["score"] >= SCORE_STRONG
            and not fort_m and not fort_f)))
    proposition = _proposition(q, fort_r, rapports, fort_m, top_m, fort_f,
                               results, mitre_ok, mitre_cands, homonymes,
                               matrix)
    ptype = proposition["type"]
    # Notes v2.2.1 conservees mot pour mot ; celles qui invitent a creer une
    # fiche ne sont emises que si la proposition va dans ce sens.
    nouvelle = ptype in ("nouvelle_fiche", "verification_mitre_impossible")
    if not internal.fiches and not internal.refs_mitre and nouvelle:
        notes.append("referentiel interne vide : une premiere fiche peut etre "
                     f"proposee (statut '{INTERNAL_DEFAULT_STATUT}', id "
                     f"{internal.next_id()})")
    elif not internal.fiches and nouvelle:
        notes.append("aucune fiche THQ : une premiere fiche peut etre "
                     f"proposee (statut '{INTERNAL_DEFAULT_STATUT}', id "
                     f"{internal.next_id()})")
    elif not results and nouvelle:
        notes.append("aucune fiche interne similaire : une nouvelle fiche peut "
                     f"etre proposee (statut '{INTERNAL_DEFAULT_STATUT}', id "
                     f"{internal.next_id()}) apres validation humaine")
    elif results and results[0]["score"] >= SCORE_STRONG:
        notes.append(f"{results[0]['id']} couvre probablement deja ce "
                     f"comportement : ne pas creer de doublon")
    # NOUVEAU v2.2.2 -- la note resume la proposition.
    if ptype == "rattacher_a_mitre":
        notes.append(f"MITRE couvre ce comportement ({top_m['id']} "
                     f"{top_m['name']}) : rattacher la reference a cette "
                     f"technique (voir `proposition`), pas de nouvelle fiche")
    elif ptype == "rapport_deja_reference":
        notes.append(proposition["message"])
    elif ptype == "rattacher_a_fiche" and not (
            results and results[0]["score"] >= SCORE_STRONG):
        notes.append(f"rattacher la reference a {results[0]['id']}")
    elif ptype == "a_departager":
        notes.append("candidats MITRE faibles seulement : les verifier avant "
                     "toute nouvelle fiche (voir `proposition`)")
    out = {**base_out, "result_count": len(results),
           "total_matches": len(scored), "results": results}
    if notes:
        out["note"] = " | ".join(notes)
    # Cles ADDITIVES v2.2.2, apres les cles v2.2.1.
    out["rapports"] = rapports
    out["rapport_count"] = len(rap_scored)
    if mitre_ok:
        out["mitre_candidats"] = mitre_cands
        if homonymes:
            out["homonymes"] = homonymes
    out["proposition"] = proposition
    return J(out)


def _modele_ref():
    return {"titre": "<titre du rapport CTI interne>",
            "lien": "<lien interne du rapport>",
            "date": "<AAAA-MM-JJ, optionnel>"}


def _proposition(q, fort_r, rapports, fort_m, top_m, fort_f, results,
                 mitre_ok, mitre_cands, homonymes, matrix):
    """NOUVEAU v2.2.2 -- que faire de la reference, dans cet ordre : rapport
    deja reference > technique MITRE couvrante > fiche THQ couvrante >
    nouvelle fiche. MITRE passe avant l'interne : une fiche THQ ne se cree
    que pour un comportement que MITRE ne couvre pas. Le bloc `a_coller` est
    un modele : l'analyste le complete et l'ecrit lui-meme."""
    if fort_r:
        r = rapports[0]
        return {"type": "rapport_deja_reference",
                "rattache_a": r["rattache_a"],
                "message": f"le rapport '{r['titre']}' est deja reference sur "
                           f"{r['rattache_a']['id']} : rien a ajouter"}
    if fort_m:
        tid = top_m["id"]
        deja = tid in internal.refs_mitre
        p = {"type": "rattacher_a_mitre",
             "technique_mitre": {k: top_m[k] for k in
                                 ("id", "name", "matrix", "tactics", "score")},
             "emplacement": (f"{INTERNAL_MITRE_SECTION} > entree "
                             f"technique_mitre={tid} > references (ajouter a "
                             f"la liste)" if deja else
                             f"{INTERNAL_MITRE_SECTION} (ajouter une entree)"),
             "a_coller": (_modele_ref() if deja else
                          {"technique_mitre": tid,
                           "references": [_modele_ref()]}),
             "a_verifier": f"confirmer {tid} avec get_technique avant "
                           f"d'ecrire : un score est une file de candidats, "
                           f"pas une preuve",
             "puis": "internal_reload"}
        deja_refs = internal.references_de(tid)
        if deja_refs["count"]:
            p["deja_rattaches"] = [r["titre"] for r in deja_refs["items"]]
            p["a_verifier"] += " ; verifier que le rapport n'est pas deja " \
                               "dans `deja_rattaches`"
        if homonymes and not matrix:
            p["attention"] = ("nom present dans les deux matrices : relancer "
                              "avec matrix='Enterprise' ou 'ICS'")
        return p
    if fort_f:
        fid = results[0]["id"]
        return {"type": "rattacher_a_fiche",
                "fiche": {k: results[0][k] for k in
                          ("id", "name", "statut", "technique_mitre_liee",
                           "score")},
                "emplacement": f"techniques > {fid} > references (ajouter a "
                               f"la liste)",
                "a_coller": _modele_ref(),
                "deja_rattaches": [r["titre"] for r in
                                   (internal.fiches.get(fid) or {})
                                   .get("references", [])],
                "puis": "internal_reload"}
    if not mitre_ok:
        return {"type": "verification_mitre_impossible",
                "message": "base MITRE indisponible : impossible de dire si "
                           "le comportement est couvert par ATT&CK, aucune "
                           "fiche ne doit etre proposee avant verification"}
    nid = internal.next_id()
    fiche = {"id": nid, "name": "<nom du comportement>",
             "description": "<description du comportement>",
             "statut": INTERNAL_DEFAULT_STATUT,
             "technique_mitre_liee": "",
             "references": [_modele_ref()]}
    # Tout candidat MITRE non-pivot, meme sous le seuil faible : le seuil
    # classe des scores, il ne prouve pas l'absence de couverture ATT&CK.
    faibles = [{"id": c["id"], "name": c["name"], "score": c["score"]}
               for c in mitre_cands if not c.get("pivot")]
    if faibles:
        # Candidats MITRE faibles : un score lexical faible ne prouve pas
        # l'absence de couverture ATT&CK (la bonne technique sort souvent
        # d'une reformulation). Une fiche THQ ne se cree qu'apres avoir
        # ecarte ces candidats sur leur fiche.
        return {"type": "a_departager",
                "message": "candidats MITRE faibles seulement : les verifier "
                           "avec get_technique (et reformuler la requete) "
                           "AVANT toute nouvelle fiche",
                "candidats_a_verifier": faibles,
                "si_mitre_couvre": {
                    "emplacement": f"{INTERNAL_MITRE_SECTION} (entree de la "
                                   f"technique confirmee)",
                    "a_coller": {"technique_mitre": "<Txxxx confirme>",
                                 "references": [_modele_ref()]}},
                "sinon_nouvelle_fiche": {
                    "id_propose": nid,
                    "emplacement": "techniques (ajouter une fiche), puis "
                                   f"meta.dernier_id_attribue = {nid}",
                    "a_coller": {**fiche, "technique_mitre_liee":
                                 "<technique ATT&CK la plus proche, "
                                 "optionnelle>"}},
                "puis": "internal_reload"}
    return {"type": "nouvelle_fiche", "id_propose": nid,
            "message": "aucune technique MITRE ni fiche interne ne couvre ce "
                       "comportement : l'analyste saisit la fiche au prochain "
                       "identifiant libre",
            "emplacement": "techniques (ajouter une fiche), puis "
                           f"meta.dernier_id_attribue = {nid}",
            "a_coller": fiche,
            "puis": "internal_reload"}


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
            "campaigns": sum(1 for c in db.campaigns.values()
                             if mx in c["matrices"]),
            "assets": sum(1 for a in db.assets.values()
                          if a["matrix"] == mx),
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
              "campaigns": len(db.campaigns), "assets": len(db.assets),
              "deprecated": len(db.deprecated),
              "search_vocabulary": len(db.idf),
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
    # NOUVEAU v2.2 -- bascule sous verrou : le mode --http sert plusieurs
    # requetes en parallele et ne doit jamais voir une base a moitie
    # echangee ni un referentiel vide le temps de sa relecture.
    with _SWAP_LOCK:
        db.adopt(fresh)
        _reancrer_interne("mitre_update")
    audit("db_updated", db_version=_db_version())
    return J({"status": "ok", "db_version": _db_version(),
              "tactics": len(db.tactics), "techniques": len(db.techniques),
              "groups": len(db.groups), "software": len(db.software),
              "campaigns": len(db.campaigns), "assets": len(db.assets),
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


def _emit(r) -> bool:
    """NOUVEAU v2.2 -- ecrit une reponse sur stdout. Un echec d'ecriture est
    journalise : le journal ne certifie jamais une reponse non recue."""
    try:
        sys.stdout.write(json.dumps(r, ensure_ascii=False) + "\n")
        sys.stdout.flush()
        return True
    except Exception as e:
        audit("protocol_error", transport="stdio", status="emit_error",
              req_id=r.get("id") if isinstance(r, dict) else None,
              error=str(e)[:200])
        log.error(f"Ecriture de la reponse impossible : {e}")
        return False


def _incomplet(buf: str) -> bool:
    """CORRECTIF 2.2.1 -- un message multi-lignes est-il encore en cours ?

    La v2.2 comparait `buf.count("{")` a `buf.count("}")` sans tenir compte
    des chaines : un message pretty-printe dont une valeur contient une
    accolade - le cas d'une description d'incident ou d'un extrait de log -
    etait declare complet trop tot, rejete en Parse error, et la requete
    restait SANS REPONSE pour son id. Le meme message sur une seule ligne
    passait. Les accolades sont ici comptees hors chaines, guillemets
    echappes compris.
    """
    profondeur = 0
    dans_chaine = False
    echap = False
    for c in buf:
        if dans_chaine:
            if echap:
                echap = False
            elif c == "\\":
                echap = True
            elif c == '"':
                dans_chaine = False
            continue
        if c == '"':
            dans_chaine = True
        elif c in "{[":
            profondeur += 1
        elif c in "}]":
            profondeur -= 1
    return dans_chaine or profondeur > 0


def _one(msg, transport="stdio"):
    """Traite UN message decode. Aucune requete portant un id ne reste sans
    reponse, quelle que soit l'exception rencontree."""
    try:
        return handle(msg, transport=transport)
    except Exception as e:
        mid = msg.get("id") if isinstance(msg, dict) else None
        audit("protocol_error", transport=transport, status="internal_error",
              req_id=mid, error=str(e)[:200])
        log.error(f"Erreur interne : {e}")
        return E(mid, -32603, "Erreur interne du serveur") if mid is not None else None


def dispatch(msg, transport="stdio"):
    """Routeur commun aux deux transports. Un LOT JSON-RPC (liste de
    messages, herite v2.1) est traite message par message, reponse en liste.
    Un lot vide est une requete invalide."""
    if isinstance(msg, list):
        if not msg:
            audit("protocol_error", transport=transport,
                  status="invalid_request", error_code=-32600)
            return E(None, -32600, "Requete invalide : lot vide")
        audit("batch", transport=transport, count=len(msg))
        out = [r for r in (_one(m, transport) for m in msg) if r]
        return out or None
    return _one(msg, transport)


def _process(msg):
    r = dispatch(msg, transport="stdio")
    if r:
        _emit(r)


def run():
    log.info(f"MCP {SERVER_NAME} v{SERVER_VERSION} : {len(TOOLS)} outils, "
             f"{len(db.techniques)} techniques, "
             f"{len(db.datasources)} sources, {len(db.redirects)} redirections, "
             f"{len(db.campaigns)} campagnes, {len(db.assets)} assets ICS.")
    audit("server_start", pid=os.getpid(), version=SERVER_VERSION,
          transport="stdio", db_version=_db_version(), ready=db.ready,
          tools=len(TOOLS))
    # NOUVEAU v2.2 -- le transport stdio delimite les messages par des sauts
    # de ligne. Chaque ligne est d'abord tentee SEULE ; un message
    # multi-lignes est assemble dans `buf`, borne a 1 Mo, et une ligne valide
    # recue pendant cet assemblage est traitee immediatement (le tampon
    # fautif est jete et journalise). La v2.1 ignorait en silence tout JSON
    # invalide et ne comprenait jamais un message pretty-printe.
    buf = ""
    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
            stripped = line.strip()
            if not stripped:
                continue
            try:
                msg = json.loads(stripped)
            except json.JSONDecodeError:
                msg = None
            if msg is not None:
                if buf:
                    audit("protocol_error", transport="stdio",
                          status="parse_error", bytes=len(buf))
                    buf = ""
                _process(msg)
                continue
            if not buf and not stripped.startswith(("{", "[")):
                audit("protocol_error", transport="stdio",
                      status="parse_error", bytes=len(stripped))
                _emit(E(None, -32700, "Parse error"))
                continue
            buf += line
            if len(buf) > MCP_HTTP_MAX_BODY:
                audit("protocol_error", transport="stdio",
                      status="buffer_overflow", bytes=len(buf))
                buf = ""
                _emit(E(None, -32700, "Parse error: message trop long"))
                continue
            try:
                msg = json.loads(buf.strip())
            except json.JSONDecodeError:
                # CORRECTIF 2.2.1 -- profondeur calculee hors chaines : le
                # tampon n'est jete que lorsque le message est reellement
                # clos et malgre tout invalide.
                if not _incomplet(buf):
                    audit("protocol_error", transport="stdio",
                          status="parse_error", bytes=len(buf))
                    buf = ""
                    _emit(E(None, -32700, "Parse error"))
                continue
            buf = ""
            _process(msg)
        except KeyboardInterrupt:
            break
        except Exception as e:
            log.error(e)
            buf = ""
    audit("server_stop", transport="stdio")
    if _audit:
        _audit.shutdown()


def _check_args(t, args):
    """NOUVEAU v2.2 -- validation des arguments contre le schema de l'outil :
    une erreur d'entree recoit un message net, jamais un TypeError Python."""
    schema = t["schema"]["inputSchema"]
    props, req = schema["properties"], schema["required"]
    missing = [k for k in req if k not in args]
    unknown = [k for k in args if k not in props]
    if missing:
        raise ValueError(f"argument requis manquant : {', '.join(missing)} "
                         f"(attendus : {', '.join(props) or 'aucun'})")
    if unknown:
        raise ValueError(f"argument inconnu : {', '.join(unknown)} "
                         f"(attendus : {', '.join(props) or 'aucun'})")


def handle(msg, transport="stdio"):
    """Routeur de protocole. NOUVEAU v2.2 -- chaque branche laisse une trace
    d'audit : l'integralite des echanges avec le client est reconstituable,
    les trois phases du cycle de vie MCP comprises."""
    if not isinstance(msg, dict):
        audit("protocol_error", transport=transport, status="invalid_request",
              error_code=-32600)
        return E(None, -32600, "Requete invalide : objet JSON-RPC attendu")
    method = msg.get("method", "")
    mid = msg.get("id")
    params = msg.get("params")
    if params is None:
        params = {}
    t0 = time.time()

    # ---- notifications (aucun id, aucune reponse attendue) -----------------
    if mid is None:
        if method:
            audit("notification", transport=transport,
                  method=str(method)[:64], **_client_info(params))
        return None

    if not isinstance(method, str) or not method:
        audit("protocol_error", transport=transport, req_id=mid,
              status="invalid_request", error_code=-32600)
        return E(mid, -32600, "Requete invalide : 'method' manquant")
    if not isinstance(params, dict):
        audit("protocol_error", transport=transport, req_id=mid,
              method=method, status="invalid_params", error_code=-32602)
        return E(mid, -32602, "'params' doit etre un objet")

    if method == "initialize":
        # NOUVEAU v2.2 -- negociation : la version demandee est rendue SI
        # elle est connue, sinon la plus recente du serveur (la v2.1
        # renvoyait en echo n'importe quelle version demandee).
        want = params.get("protocolVersion", "")
        proto = want if want in SUPPORTED_PROTOCOLS else DEFAULT_PROTOCOL
        audit("initialize", transport=transport, req_id=mid,
              protocol_requested=want or None, protocol_negotiated=proto,
              duration_ms=int((time.time() - t0) * 1000),
              db_version=_db_version(), **_client_info(params))
        return R(mid, {"protocolVersion": proto,
                       "capabilities": {"tools": {}},
                       "serverInfo": {"name": SERVER_NAME,
                                      "version": SERVER_VERSION}})

    if method == "tools/list":
        # Tracee : c'est par cet appel que le modele decouvre les outils et
        # LIT LEURS DESCRIPTIONS — vecteur de l'empoisonnement d'outil.
        tools = [t["schema"] for t in TOOLS.values()]
        audit("tools_list", transport=transport, req_id=mid,
              tool_count=len(tools),
              duration_ms=int((time.time() - t0) * 1000))
        return R(mid, {"tools": tools})

    if method == "tools/call":
        asked = params.get("name", "")
        args = params.get("arguments")
        if args is None:
            args = {}
        if not isinstance(asked, str):
            audit("tool_call", transport=transport, req_id=mid,
                  status="invalid_params", error_code=-32602)
            return E(mid, -32602, "'name' doit etre une chaine")
        name = ALIASES.get(asked, asked)
        t = TOOLS.get(name)
        if not t:
            # Un appel a un outil inexistant est la signature d'une
            # HALLUCINATION D'OUTIL — indicateur qu'il faut pouvoir compter.
            audit("tool_call", transport=transport, req_id=mid,
                  tool=asked[:64], status="unknown_tool", error_code=-32602,
                  duration_ms=int((time.time() - t0) * 1000))
            return E(mid, -32602, f"Outil inconnu: {asked[:64]}")
        if not isinstance(args, dict):
            audit("tool_call", transport=transport, req_id=mid, tool=name,
                  status="invalid_params", error_code=-32602)
            return E(mid, -32602, "'arguments' doit etre un objet")
        # Les outils du referentiel interne et le diagnostic ne dependent pas
        # de la base MITRE : ils restent utilisables si elle est indisponible.
        if name not in TOOLS_SANS_BASE and not db.ready:
            if not db.ensure():
                problemes = db.check()
                audit("tool_call", transport=transport, req_id=mid, tool=name,
                      status="db_not_ready", problemes=problemes,
                      duration_ms=int((time.time() - t0) * 1000))
                return R(mid, {"content": [{"type": "text", "text": J({
                    "error": "Base MITRE indisponible ou incomplete",
                    "details": problemes,
                    "db_version": _db_version()})}], "isError": True})
            # La base vient d'arriver : les fiches internes ont ete chargees
            # sans pouvoir etre confrontees a ATT&CK, on les re-ancre.
            with _SWAP_LOCK:
                _reancrer_interne("ensure")
        try:
            _check_args(t, args)
            res = t["handler"](**args)
            audit("tool_call", transport=transport, req_id=mid, tool=name,
                  status="success",
                  duration_ms=int((time.time() - t0) * 1000),
                  db_version=_db_version(), args=_args_summary(args),
                  result=_result_summary(res))
            return R(mid, {"content": [{"type": "text", "text": res}]})
        except ValueError as e:
            audit("tool_call", transport=transport, req_id=mid, tool=name,
                  status="invalid", error=str(e)[:300],
                  duration_ms=int((time.time() - t0) * 1000),
                  db_version=_db_version(), args=_args_summary(args))
            return R(mid, {"content": [{"type": "text", "text": str(e)}],
                           "isError": True})
        except Exception as e:
            audit("tool_call", transport=transport, req_id=mid, tool=name,
                  status="error",
                  error=f"{type(e).__name__}: {str(e)[:300]}",
                  duration_ms=int((time.time() - t0) * 1000),
                  db_version=_db_version(), args=_args_summary(args))
            return R(mid, {"content": [{"type": "text",
                                        "text": f"erreur interne de l'outil "
                                                f"'{name}' "
                                                f"({type(e).__name__})"}],
                           "isError": True})

    if method in ("resources/list", "prompts/list"):
        audit("capability_probe", transport=transport, req_id=mid,
              method=method, result="empty")
        return R(mid, {method.split("/")[0]: []})
    if method == "ping":
        audit("ping", transport=transport, req_id=mid)
        return R(mid, {})
    audit("protocol_error", transport=transport, req_id=mid,
          method=method[:64], status="unknown_method", error_code=-32601,
          duration_ms=int((time.time() - t0) * 1000))
    return E(mid, -32601, f"Methode inconnue: {method[:64]}")


def R(mid, result):
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def E(mid, code, msg):
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": msg}}


# =============================================================================
#  NOUVEAU v2.2 -- MODE HTTP LOCAL (--http), sans authentification
#
#  Ajout strictement additif : le moteur de mapping, les outils et le routeur
#  `dispatch()` sont ceux du mode stdio, appeles ici avec transport="http".
#  Deux formes de dialogue sont servies :
#    - Streamable HTTP : POST /mcp -> reponse JSON (ou trame SSE si le client
#      ne declare accepter que text/event-stream) ; GET /mcp -> flux de
#      notifications maintenu ouvert.
#    - HTTP+SSE (herite) : GET /sse annonce l'URL de depot, puis
#      POST /messages pour chaque message.
#  Le serveur reste SANS ETAT : aucun identifiant de session n'est exige.
# =============================================================================

def _sse_frame(obj) -> bytes:
    """Encapsule un message JSON-RPC dans une trame SSE."""
    return ("event: message\ndata: " +
            json.dumps(obj, ensure_ascii=False) + "\n\n").encode("utf-8")


class MCPHTTPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"mcp-mitre/{SERVER_VERSION}"

    def log_message(self, fmt, *a):
        log.debug("http %s", fmt % a)

    def _send(self, code, body=b"", ctype="application/json", extra=None):
        self.send_response(code)
        if body:
            self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, code, obj, extra=None):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json", extra)

    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/") or "/"
        if path == "/healthz":
            self._json(200, {"status": "ok", "version": SERVER_VERSION,
                             "transport": "http", "run_id": RUN_ID,
                             "ready": db.ready,
                             "db_version": _db_version()})
            return
        if path in ("/mcp", "/sse"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            try:
                if path == "/sse":
                    self.wfile.write(b"event: endpoint\ndata: /messages\n\n")
                    self.wfile.flush()
                while True:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    time.sleep(15)
            except Exception:
                return          # client parti : fin normale du fil
            return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        path = self.path.split("?")[0].rstrip("/") or "/"
        if path not in ("/mcp", "/messages"):
            self._json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0:
            audit("protocol_error", transport="http",
                  status="bad_content_length")
            self._json(400, {"error": "invalid Content-Length"})
            return
        if length > MCP_HTTP_MAX_BODY:
            audit("protocol_error", transport="http", status="body_too_large",
                  bytes=length)
            self._json(413, {"error": "body too large"})
            return
        raw = self.rfile.read(length) if length else b""
        try:
            msg = json.loads(raw.decode("utf-8"))
        except Exception:
            audit("protocol_error", transport="http", status="parse_error",
                  bytes=len(raw))
            self._json(400, {"jsonrpc": "2.0", "id": None,
                             "error": {"code": -32700,
                                       "message": "Parse error"}})
            return
        try:
            resp = dispatch(msg, transport="http")
        except Exception as e:
            mid = msg.get("id") if isinstance(msg, dict) else None
            audit("protocol_error", transport="http", status="internal_error",
                  req_id=mid, error=str(e)[:200])
            log.error(f"Erreur interne (http) : {e}")
            self._json(500, E(mid, -32603, "Erreur interne du serveur"))
            return
        if resp is None:
            self._send(202)      # notification : deja journalisee
            return
        extra = {}
        if isinstance(msg, dict) and msg.get("method") == "initialize":
            # Identifiant de session emis par politesse, jamais exige :
            # le serveur reste sans etat.
            extra["Mcp-Session-Id"] = uuid.uuid4().hex
        accept = (self.headers.get("Accept") or "")
        if "text/event-stream" in accept and "application/json" not in accept:
            self._send(200, _sse_frame(resp), "text/event-stream", extra)
        else:
            self._json(200, resp, extra)


class MCPHTTPServer(ThreadingHTTPServer):
    """NOUVEAU v2.2 -- la file d'ecoute par defaut de socketserver est de 5
    connexions : au-dela, le noyau REINITIALISE les connexions excedentaires
    et le client recoit une coupure, pas une erreur applicative. Mesure : a
    20 clients simultanes, 6 requetes sur 40 etaient perdues. Un agent qui
    parallelise ses appels d'outils atteint ce seuil sans effort."""
    request_queue_size = 128
    daemon_threads = True
    allow_reuse_address = True


def run_http(host=MCP_HTTP_HOST, port=MCP_HTTP_PORT):
    """Sert le protocole sur HTTP local, sans authentification."""
    httpd = MCPHTTPServer((host, port), MCPHTTPHandler)
    audit("server_start", pid=os.getpid(), version=SERVER_VERSION,
          transport="http", host=host, port=port, db_version=_db_version(),
          ready=db.ready)
    log.info(f"HTTP local : http://{host}:{port}/mcp  (aucune authentification)")
    log.info(f"Sonde      : http://{host}:{port}/healthz")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        audit("server_stop", transport="http")
        if _audit:
            _audit.shutdown()
        httpd.server_close()


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
          f"sans remplacant vivant, {len(db.deprecated)} depreciees")
    print(f"  Objets 2.2  {len(db.campaigns)} campagnes, "
          f"{len(db.assets)} assets ICS, "
          f"index de recherche {len(db.idf)} tokens / "
          f"{len(db.entities)} alias d'entites")

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
        orphelines += sum(1 for x in t["campaigns"] if x not in db.campaigns)
        orphelines += sum(1 for x in t["assets"] if x not in db.assets)
        orphelines += sum(1 for x in t["subtechniques"] if x not in db.techniques)
        orphelines += sum(1 for x in t["tactics"] if x["id"] not in db.tactics)
    for c in db.campaigns.values():
        orphelines += sum(1 for x in c["techniques"] if x not in db.techniques)
        orphelines += sum(1 for x in c["groups"] if x not in db.groups)
    for a in db.assets.values():
        orphelines += sum(1 for x in a["techniques"] if x not in db.techniques)
    for tids in db.datasources.values():
        orphelines += sum(1 for x in tids if x not in db.techniques)
    # NOUVEAU v2.2 -- les index derives de la recherche comptent comme le
    # reste : une entree qui cite un objet absent est une orpheline.
    orphelines += sum(1 for _t, kind, eid, _n in db.entities
                      if eid not in getattr(db, kind, {}))
    orphelines += sum(1 for _t, ta in db.tactic_index if ta not in db.tactics)
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
    print(f"            {c['references_mitre']} technique(s) MITRE avec "
          f"references internes ({c['references_mitre_ecartees']} entree(s) "
          f"ecartee(s)), {c['rapports']} reference(s) CTI indexee(s)")
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
    # NOUVEAU v2.2.2 -- meme reciprocite pour la partie references_mitre :
    # une entree indexee existe, et une entree ancree sur une technique
    # vivante est retrouvee par get_technique (references_internes).
    for tid, eids in internal.refs_by_mitre.items():
        for eid in eids:
            if eid not in internal.refs_mitre:
                interne_ko.append(f"index references casse : {tid} -> {eid}")
    for eid, e in internal.refs_mitre.items():
        eff = e.get("technique_mitre_effective")
        if eff and eff in db.techniques:
            sources = {x["source"] for x in
                       internal.references_de(eff)["items"]}
            if eid not in sources and internal.references_de(eff)["count"] \
                    <= INTERNAL_REF_LIST_CAP:
                interne_ko.append(f"{eid} absente de references_internes "
                                  f"de {eff}")
    n_idx = sum(len(e["references"]) for e in internal.refs_mitre.values()) \
        + sum(len(f.get("references", [])) for f in internal.fiches.values())
    if n_idx != len(internal.rapports):
        interne_ko.append(f"index des rapports incoherent ({n_idx} references "
                          f"pour {len(internal.rapports)} entrees d'index)")
    for m in interne_ko:
        print(f"            [rejet] {m}")

    anos_bloquantes = [a["message"] for a in internal.anomalies
                       if a["niveau"] == "rejet"] + interne_ko
    if interne_ko:
        echecs.extend(interne_ko)
    elif anos_bloquantes and STRICT_INTERNAL:
        echecs.extend(anos_bloquantes)
    elif anos_bloquantes:
        print(f"            ({len(anos_bloquantes)} entree(s) ecartee(s) : "
              f"relancer avec --strict pour en faire un echec)")

    collision = sorted(set(ALIASES) & set(TOOLS))
    if collision:
        echecs.append(f"alias qui masque un outil : {', '.join(collision)}")
    print(f"Outils ({len(TOOLS)}) : {list(TOOLS.keys())}")
    print(f"Alias  ({len(ALIASES)}) : {list(ALIASES.keys())}")
    print(f"Transports : stdio (defaut) | http via --http "
          f"[{MCP_HTTP_HOST}:{MCP_HTTP_PORT}, sans authentification]")
    print(f"Audit : run_id={RUN_ID}")
    if echecs:
        print("ECHEC : " + " | ".join(echecs))
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description=f"Serveur MCP MITRE ATT&CK v{SERVER_VERSION} (stdio par defaut ; "
                    "--http pour un acces local sans authentification)",
        epilog="Documentation complete : uv run mcp_mitre.py --doc")
    ap.add_argument("--test", action="store_true",
                    help="verifie la base et sort en code 1 si KO")
    ap.add_argument("--strict", action="store_true",
                    help="avec --test : les anomalies du referentiel interne "
                         "sont elles aussi bloquantes")
    ap.add_argument("--no-audit", action="store_true",
                    help="demarre sans journal d'audit")
    ap.add_argument("--doc", action="store_true",
                    help="affiche la documentation du module et sort")
    ap.add_argument("--http", action="store_true",
                    help="sert le protocole sur HTTP local (sans "
                         "authentification) au lieu de stdio")
    ap.add_argument("--host", default=MCP_HTTP_HOST,
                    help=f"adresse d'ecoute du mode --http "
                         f"(defaut {MCP_HTTP_HOST})")
    ap.add_argument("--port", type=int, default=MCP_HTTP_PORT,
                    help=f"port d'ecoute du mode --http "
                         f"(defaut {MCP_HTTP_PORT})")
    args = ap.parse_args()

    if args.doc:
        print(__doc__)
        sys.exit(0)
    if args.test:
        code = selftest()
        if _audit:
            _audit.shutdown()
        sys.exit(code)
    if args.http:
        run_http(args.host, args.port)
    else:
        run()
