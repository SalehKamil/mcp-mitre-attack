#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""
calculer_metriques.py — Etiquetage et metriques d'une campagne d'evaluation
===========================================================================
Compare les reponses des modeles (resultats_tous_modeles.jsonl, produit par le
workflow n8n) a la verite de terrain (verite_terrain.jsonl, produite par
preparer_dataset.py), selon la methodologie d'evaluation.

ETIQUETAGE, a chaque NIVEAU (tactique, technique, sous-technique)
  VP            l'identifiant attendu est predit
  FP            un identifiant qui existe dans la version figee, mais incorrect
  FN            le bon identifiant n'a pas ete identifie
  HALLUCINATION un identifiant qui n'existe dans aucune version du referentiel
  OBSOLETE      un identifiant revoque dont le remplacant est l'identifiant attendu

CONVENTION DE COMPTAGE (definitions de la methodologie)
  Le FN est defini comme "le LLM ne parvient pas a identifier le bon identifiant
  alors qu'il etait identifiable depuis le log". Cette definition couvre les DEUX
  causes possibles :
    - une prediction incorrecte  -> compte FP (il affirme du faux)
                                    ET FN (il n'a pas trouve le bon identifiant) ;
    - une absence de prediction  -> compte FN seulement.
  La sous-specification est donc le sous-ensemble des FN dus a une abstention :
  elle est comptee a part, en plus du FN, comme diagnostic.
  Les hallucinations sont comptees dans les FP (une invention est une fausse
  affirmation) et restent suivies par un taux dedie.

Cas particuliers du niveau sous-technique :
  - la technique attendue n'a PAS de sous-technique : "aucune" (ou l'abstention)
    est un VP ; affirmer une sous-technique est une sur-specification (FP) ;
  - la technique attendue EN A une : l'abstention est un FN (sous-specification
    N2) ; repondre "aucune" est egalement compte FN, avec un compteur dedie,
    car ce n'est pas l'affirmation d'un identifiant.

PERIMETRE DU NIVEAU SOUS-TECHNIQUE
  Le F1 sous-technique est calcule UNIQUEMENT sur les echantillons dont la
  technique possede une sous-technique (22 sur 42 dans notre corpus). Sans cette
  restriction, un modele muet obtiendrait 0,645 de F1 et 100 % de precision
  grace aux echantillons terminaux. Les echantillons terminaux sont evalues a
  part par le taux de SUR-SPECIFICATION (sous-technique affirmee alors que la
  technique n'en possede pas).

METRIQUES, calculees SEPAREMENT a chaque niveau (jamais de F1 global)
  Precision = VP / (VP + FP)
  Rappel    = VP / (VP + FN)
  F1        = 2 x (Precision x Rappel) / (Precision + Rappel)
Un modele qui s'abstient perd du rappel sans perdre de precision (l'abstention
n'est pas une fausse affirmation) ; un modele qui repond faux perd les deux.
Comme VP + FN vaut le nombre d'echantillons evalues au niveau considere, le
rappel est aussi le taux de reussite du niveau. Le TAUX D'ABSTENTION, rapporte
par niveau, complete la lecture : un modele peut etre precis tout en omettant
de mapper. Les F1 sont egalement recalcules HORS REJETS (format non respecte,
erreurs d'API) afin de separer la competence de mapping de la conformite au
format de sortie.

Chaque F1 est calcule DEUX FOIS :
  F1 strict    les identifiants obsoletes comptent comme des erreurs (metrique principale)
  F1 tolerant  les identifiants obsoletes comptent comme des VP
L'ecart mesure la part des erreurs due a l'obsolescence des connaissances du modele.

PRESENTATION DES RESULTATS
  Le rapport ne contient plus de bloc detaille par modele : tout est en
  tableaux couvrant l'ensemble du panel, dans cet ordre — etiquetage par
  niveau, attributs de diagnostic, ventilation par matrice, synthese, les
  deux classements de qualite, le classement de fiabilite, l'apport du MCP,
  puis l'usage du serveur.
  Une campagne menee AVEC serveur ne fait pas l'objet de tableaux separes :
  elle s'inscrit dans les memes tableaux, sur une ligne supplementaire,
  signalee par la colonne MCP. Les classements restent donc calcules sur
  l'ensemble des lignes, avec et sans serveur, selon les memes criteres.
  Seul le dernier tableau est propre au serveur : il porte les indicateurs
  d'usage, qui n'ont pas d'equivalent sans outils.

ORDRE DES CLASSEMENTS
  Qualite du mapping (bases stricte et tolerante), du plus grave au plus fin :
    1. mauvaise matrice (effectif brut, croissant) — identifiant pris dans
       l'autre matrice : le modele s'est trompe d'univers, la mitigation qui en
       decoule est inapplicable au systeme observe ;
    2. taux d'hallucination (croissant) ;
    3. F1 (decroissant) : technique, puis tactique, puis sous-technique ;
    4. taux d'obsolescence, puis taux d'abstention.
  Fiabilite, vitesse et cout :
    1. stabilite (decroissante) ;
    2. latence mediane p50 (croissante) ;
    3. cout, jetons moyens par execution (croissant).
  (L'indicateur d'efficacite — F1 par millier de jetons — a ete retire le
   26/09/2026 : il melangeait qualite et cout sans rien apporter de plus.)

USAGE
  uv run calculer_metriques.py <resultats.jsonl> --verite verite_terrain.jsonl
  uv run calculer_metriques.py "resultats_*.jsonl" --verite verite_terrain.jsonl --sortie rapport

COPIE DES RESULTATS n8n AU LANCEMENT
  Des son lancement, le script copie TOUT le dossier des resultats de n8n
  (<dossier n8n>/resultats) dans <dossier de sortie>/resultats_evaluation_n8n,
  puis travaille exclusivement sur cette copie : les fichiers de n8n ne sont
  plus jamais lus pendant le calcul. La copie est refaite a chaque lancement
  (instantane a jour). Le dossier n8n est localise sans chemin en dur, sur
  n'importe quel poste Windows (ou Linux/macOS) :
    1. --source-n8n <dossier>, s'il est fourni ;
    2. la variable d'environnement N8N_FILES_DIR ;
    3. le repertoire personnel de l'utilisateur courant (%USERPROFILE%) :
       .n8n-files, n8n-files, .n8nfiles, n8nfiles, .n8n_files, n8n_files ;
    4. en dernier recours, un dossier dont le nom contient « n8n » dans le
       repertoire personnel, Documents, Bureau/Desktop ou OneDrive.

AJOUTS DE LA PHASE 2 (serveur MCP)
  Les metriques ci-dessus sont inchangees : meme etiquetage, memes bases, memes
  classements. Trois indicateurs d'usage du serveur completent la section MCP
  existante, sur la meme trace `appels_mcp` :

  - CONFORMITE DE MATRICE. Le serveur ne connait pas la matrice prescrite par
    l'echantillon : il ne connait que le parametre `matrix` que le modele lui
    transmet. Sans ce parametre, une recherche mixe Enterprise et ICS, et 26
    noms de techniques existent a l'identique dans les deux matrices. Mesure :
    part des recherches portant la bonne matrice, la matrice omise, la matrice
    erronee. C'est le chainon manquant entre le taux d'utilisation du serveur
    et le compteur de mauvaise matrice de la section 2.5 : il dit POURQUOI un
    identifiant hors matrice a survecu a l'ancrage.
  - DEMENTIS DU SERVEUR. Appels dont la reponse est « identifiant introuvable »
    (le modele a soumis un identifiant de memoire, le serveur l'a dementi) et
    garde-fous leves par le serveur : homonymie entre matrices, resultat de
    pivot, requete trop courte, identifiant revoque ou deprecie.
  - AVERTISSEMENT SUIVI D'ERREUR. Homonymie signalee par le serveur PUIS
    identifiant retenu hors de la matrice de l'echantillon. Le serveur a
    prevenu, le modele a conclu quand meme.

  Ces indicateurs ne modifient aucun F1 et n'entrent dans aucun classement :
  ce sont des attributs de diagnostic au sens de la section 2.5, comptes en
  executions.
"""
import argparse, glob, json, math, os, pathlib, re, shutil, statistics, sys, tempfile, urllib.request
from collections import Counter, defaultdict

VERSION_ATTACK_DEFAUT = "19.2"
AUCUNE = "aucune"
NIVEAUX = ("tactique", "technique", "sous_technique")
LIB_NIVEAU = {"tactique": "Tactique", "technique": "Technique",
              "sous_technique": "Sous-technique",
              # CORRECTIF 2026-09 : hallucination sur echantillon terminal
              "sous_technique (terminal)": "Sous-technique (terminal)"}
VP, FP, FN, HALL, OBS = "VP", "FP", "FN", "HALLUCINATION", "OBSOLETE"
# ANCIENNE_VERSION : identifiant absent de la version figee mais vivant dans
# une version historique (ICS v8, PRE-ATT&CK). Compte en FP comme une
# hallucination — introuvable dans le referentiel courant — mais mesure une
# autre faute : un referentiel interne perime, pas une invention.
FANT = "ANCIENNE_VERSION"
BASE_STIX = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
FICHIER_MATRICE = {"enterprise": "enterprise-attack", "ics": "ics-attack"}
HISTORIQUE_SOURCES = (
    ("ics-attack-8.0.json",
     BASE_STIX + "/ics-attack/ics-attack-8.0.json"),
    ("pre-attack.json",
     "https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json"),
)

# Outils MCP dont la sortie porte des identifiants de technique ou de tactique :
# ce sont les "bons outils" pour une tache de mapping (les autres ne sont pas
# faux, ils ne servent pas la tache).
OUTILS_MAPPING = {"search_techniques", "get_technique", "get_tactics", "get_tactic"}

RE_TACTIQUE = re.compile(r"^TA\d{4}$")
RE_TECHNIQUE = re.compile(r"^T\d{4}$")
RE_SOUS_TECHNIQUE = re.compile(r"^T\d{4}\.\d{3}$")


# ---- referentiel MITRE fige ----------------------------------------------
def charger_base(matrice, version, cache_dir):
    nom = "%s-%s.json" % (FICHIER_MATRICE[matrice], version)
    url = "%s/%s/%s" % (BASE_STIX, FICHIER_MATRICE[matrice], nom)
    tmp = tempfile.gettempdir()
    for p in [pathlib.Path(cache_dir) / nom, pathlib.Path(tmp) / nom]:
        if p.exists():
            return json.load(open(p, encoding="utf-8-sig"))
    print("[1] Telechargement du referentiel %s v%s" % (matrice, version))
    req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
    try:
        data = urllib.request.urlopen(req, timeout=300).read()
    except Exception as e:
        sys.exit("[!] Telechargement impossible (%s). Deposer %s dans --cache." % (e, nom))
    for d in (pathlib.Path(cache_dir), pathlib.Path(tmp)):
        try:
            d.mkdir(parents=True, exist_ok=True)
            (d / nom).write_bytes(data)
            break
        except OSError:
            continue
    return json.loads(data)


def charger_historique(cache_dir):
    """Identifiants des versions historiques du referentiel : ICS v8 (avant le
       grand nettoyage de 2021) et PRE-ATT&CK (tactiques TA0012-TA0026,
       fusionnees dans Enterprise en 2020). Telecharges une fois, mis en
       cache ; indisponibles -> classe vide et avertissement, jamais d'arret :
       l'etiquetage retombe alors sur l'ancienne regle (tout en HALLUCINATION).
    """
    ids = set()
    for nom, url in HISTORIQUE_SOURCES:
        data = None
        tmp = tempfile.gettempdir()
        for p in [pathlib.Path(cache_dir) / nom, pathlib.Path(tmp) / nom]:
            if p.exists():
                data = json.load(open(p, encoding="utf-8-sig"))
                break
        if data is None:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
                brut = urllib.request.urlopen(req, timeout=300).read()
                data = json.loads(brut)
                for d in (pathlib.Path(cache_dir), pathlib.Path(tmp)):
                    try:
                        d.mkdir(parents=True, exist_ok=True)
                        (d / nom).write_bytes(brut)
                        break
                    except OSError:
                        continue
            except Exception as e:
                print("    [i] historique %s indisponible (%s) : la classe "
                      "ANCIENNE_VERSION sera incomplete." % (nom, e), file=sys.stderr)
                continue
        for x in data.get("objects", []):
            if x.get("type") not in ("attack-pattern", "x-mitre-tactic"):
                continue
            for r in x.get("external_references", []):
                # les anciens paquets utilisent mitre-ics-attack / mitre-pre-attack
                if str(r.get("source_name", "")).startswith("mitre") and r.get("external_id"):
                    ids.add(r["external_id"])
    return ids


def indexer(bundle):
    """Renvoie (techniques_vivantes, revoques, tactiques_ids)."""
    o = bundle["objects"]
    tactiques = set()
    for x in o:
        if x.get("type") == "x-mitre-tactic":
            for r in x.get("external_references", []):
                if str(r.get("source_name", "")).startswith("mitre") and r.get("external_id"):
                    tactiques.add(r["external_id"])
    stix2attack = {}
    for x in o:
        if x.get("type") == "attack-pattern":
            e = [r for r in x.get("external_references", [])
                 if str(r.get("source_name", "")).startswith("mitre")]
            if e:
                stix2attack[x["id"]] = e[0]["external_id"]
    remplace = {x["source_ref"]: x["target_ref"] for x in o
                if x.get("type") == "relationship"
                and x.get("relationship_type") == "revoked-by"}
    vivantes, revoques, depreciees = set(), {}, set()
    for x in o:
        if x.get("type") != "attack-pattern":
            continue
        e = [r for r in x.get("external_references", [])
             if str(r.get("source_name", "")).startswith("mitre")]
        if not e:
            continue
        aid = e[0]["external_id"]
        if x.get("revoked"):
            cible = remplace.get(x["id"])
            revoques[aid] = stix2attack.get(cible) if cible else None
        elif x.get("x_mitre_deprecated"):
            # depreciee = retiree du referentiel SANS remplacant officiel.
            # Elle existe (methodologie 2.2) : la predire est un FP, pas une
            # hallucination, et ne peut etre creditee OBSOLETE faute de
            # remplacant a verifier.
            depreciees.add(aid)
        else:
            vivantes.add(aid)
    return vivantes, revoques, tactiques, depreciees


class Referentiel(object):
    """Acces aux deux matrices figees a la meme version."""

    def __init__(self, version, cache_dir):
        self.version = version
        self.tech, self.rev, self.tac = {}, {}, {}
        self.dep = {}
        for m in ("enterprise", "ics"):
            v, r, t, dp = indexer(charger_base(m, version, cache_dir))
            self.tech[m], self.rev[m], self.tac[m], self.dep[m] = v, r, t, dp
        self.toutes_tech = self.tech["enterprise"] | self.tech["ics"]
        self.toutes_dep = self.dep["enterprise"] | self.dep["ics"]
        self.tous_rev = dict(self.rev["enterprise"]); self.tous_rev.update(self.rev["ics"])
        self.toutes_tac = self.tac["enterprise"] | self.tac["ics"]
        # identifiants ayant existe dans une version historique et ABSENTS de
        # la version figee sous toutes ses formes (vivant, revoque, deprecie)
        connus = (self.toutes_tech | self.toutes_dep
                  | set(self.tous_rev) | self.toutes_tac)
        self.anciens = charger_historique(cache_dir) - connus

    def autre(self, matrice):
        return "ics" if matrice == "enterprise" else "enterprise"


# ---- chargement des fichiers ---------------------------------------------
def charger_verite(chemin):
    vt = {}
    p = pathlib.Path(chemin)
    if not p.exists():
        sys.exit("[!] Verite de terrain introuvable : %s" % chemin)
    for i, l in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if not l.strip():
            continue
        try:
            r = json.loads(l)
        except json.JSONDecodeError as e:
            print("[!] verite ligne %d illisible (%s)" % (i, e), file=sys.stderr)
            continue
        ech = r.get("echantillon")
        if not ech:
            continue
        def idn(cle):
            v = r.get(cle)
            if isinstance(v, dict):
                return str(v.get("id", "")).strip()
            return str(v or "").strip()
        vt[ech] = {"zone": r.get("zone"), "source": r.get("source"),
                   "matrice": str(r.get("matrice", "enterprise")).lower(),
                   "tactique": idn("tactique_attendue").upper(),
                   "technique": idn("technique_attendue").upper(),
                   "sous_technique": idn("sous_technique_attendue")}
    if not vt:
        sys.exit("[!] Verite de terrain vide : %s" % chemin)
    return vt


def charger_resultats(motifs):
    recs = []
    for motif in motifs:
        for chemin in sorted(glob.glob(motif)) or [motif]:
            p = pathlib.Path(chemin)
            if not p.exists():
                print("[!] introuvable : %s" % chemin, file=sys.stderr)
                continue
            with p.open(encoding="utf-8", errors="replace") as f:
                for i, l in enumerate(f, 1):
                    if not l.strip():
                        continue
                    try:
                        recs.append(json.loads(l))
                    except json.JSONDecodeError as e:
                        print("[!] %s:%d illisible (%s)" % (chemin, i, e), file=sys.stderr)
    if not recs:
        sys.exit("[!] Aucun resultat lu.")
    return recs


def normaliser_prediction(mapping):
    """Extrait un identifiant unique par niveau ; tolere l'ancien format en listes."""
    def val(m, cle_s, cle_p):
        v = m.get(cle_s)
        if v is None and cle_p in m:
            v = m.get(cle_p)
        if isinstance(v, list):
            v = v[0] if len(v) == 1 else (v[0] if v else "")
        s = str(v or "").strip()
        if re.match(r"^(aucune|aucun|none|n/a|null)$", s, re.I):
            return AUCUNE
        return s.upper()
    m = mapping or {}
    return {"tactique": val(m, "tactique", "tactiques"),
            "technique": val(m, "technique", "techniques"),
            "sous_technique": val(m, "sous_technique", "sous_techniques")}


# ---- CORRECTIF 2026-09 : jetons et cache ---------------------------------
# Anthropic : usage.tokens_entree EXCLUT le cache (lu + ecrit).
# OpenAI, DeepSeek, Kimi, Qwen, Gemini : tokens_entree L'INCLUT deja.
# Le harnais le precise dans cache.entree_inclut_cache. Sans ce correctif,
# la colonne Jetons d'une campagne Anthropic cachee ne comptait que l'entree
# hors cache (835 jetons/exec au lieu de ~69 000), et le cout d'une campagne
# OpenAI cachee facturait le cache DEUX fois (plein tarif + tarif cache).
def cache_de(r):
    c = r.get("cache") or {}
    return int(c.get("lecture") or 0), int(c.get("ecriture") or 0), \
        bool(c.get("entree_inclut_cache"))


# Fournisseurs dont le raisonnement est rapporte A COTE de la sortie (et
# facture en plus) : Google renvoie candidatesTokenCount SANS thoughtsTokenCount.
# Chez OpenAI, DeepSeek, Moonshot et Alibaba, reasoning_tokens est deja
# COMPRIS dans les jetons de sortie.
FOURNISSEURS_RAISONNEMENT_A_PART = {"vertex", "google", "gemini"}


def sortie_facturee(r):
    """Jetons de sortie factures, raisonnement compris et compte une fois.
       CORRECTIF 2026-09 : la regle « raisonnement > sortie » devinait le cas
       Google ; elle est gardee en secours, mais le fournisseur decide d'abord."""
    tok = r.get("usage") or {}
    ts = int(tok.get("tokens_sortie") or 0)
    rais = int(tok.get("tokens_raisonnement") or 0)
    four = str((r.get("meta") or {}).get("fournisseur") or "").lower()
    return ts + rais if (four in FOURNISSEURS_RAISONNEMENT_A_PART or rais > ts) else ts


def jetons_consommes(r):
    """Entree + sortie (raisonnement compris) + cache, chacun compte UNE fois."""
    te = int((r.get("usage") or {}).get("tokens_entree") or 0)
    cl, ce, inclut = cache_de(r)
    return te + sortie_facturee(r) + (0 if inclut else cl + ce)


def entree_plein_tarif(r):
    """Jetons d'entree factures au tarif normal, cache deduit s'il y est inclus."""
    te = int((r.get("usage") or {}).get("tokens_entree") or 0)
    cl, ce, inclut = cache_de(r)
    return max(0, te - cl - ce) if inclut else te


def valider_verite(vt, ref):
    """CORRECTIF 2026-09 : la verite de terrain est confrontee au referentiel
       fige AVANT tout etiquetage. Signale : identifiant non vivant ou hors
       matrice, sous-technique attendue non rattachee a la technique, et
       « aucune » attendue alors que la technique possede des sous-techniques
       (le script lit « aucune » comme « la technique n'en a pas » : une
       sous-technique exacte y serait comptee en sur-specification)."""
    alertes = []
    for ech, g in sorted(vt.items()):
        m, t, st = g["matrice"], g["technique"], g["sous_technique"]
        if t not in ref.tech.get(m, set()):
            alertes.append("%s : technique %s non vivante dans la matrice %s" % (ech, t, m))
        if g["tactique"] not in ref.tac.get(m, set()):
            alertes.append("%s : tactique %s absente de la matrice %s" % (ech, g["tactique"], m))
        if st not in ("", AUCUNE):
            if st not in ref.tech.get(m, set()) or st.split(".")[0] != t:
                alertes.append("%s : sous-technique %s invalide pour %s" % (ech, st, t))
        else:
            enfants = sorted(x for x in ref.tech.get(m, set()) if x.startswith(t + "."))
            if enfants:
                alertes.append("%s : « aucune » attendue mais %s possede %s — "
                               "confirmer qu'aucune ne correspond au log"
                               % (ech, t, ", ".join(enfants)))
    if alertes:
        print("    [!] VERITE DE TERRAIN — %d point(s) a verifier :" % len(alertes))
        for x in alertes:
            print("        - " + x)
    return alertes


# ---- etiquetage d'un enregistrement --------------------------------------
def etiqueter(pred, gt, ref):
    """Renvoie {niveau: {etiquette, drapeaux...}} — UNE etiquette par niveau."""
    m = gt["matrice"]
    res = {}

    # --- tactique ---
    p = pred["tactique"]
    d = {"predit": p}
    if not p or p == AUCUNE:
        d["etiquette"] = FN
    elif p == gt["tactique"]:
        d["etiquette"] = VP
    elif not RE_TACTIQUE.match(p) or p not in ref.toutes_tac:
        # ancienne version (methodologie 2.2) : il a existe, donc pas une
        # hallucination -> FP porteur d'un drapeau, comme le deprecie
        if p in ref.anciens:
            d["etiquette"] = FP
            d["ancienne_version"] = True
        else:
            d["etiquette"] = HALL
    else:
        d["etiquette"] = FP
        if p not in ref.tac[m]:
            d["mauvaise_matrice"] = True
        # scission v19 : TA0005 (Stealth) propose la ou TA0112 est attendu
        if p == "TA0005" and gt["tactique"] == "TA0112":
            d["scission_defense_evasion"] = True
    res["tactique"] = d

    # --- technique ---
    p = pred["technique"]
    d = {"predit": p}
    if not p or p == AUCUNE:
        d["etiquette"] = FN
    elif p == gt["technique"]:
        d["etiquette"] = VP
    elif p in ref.tous_rev and ref.tous_rev[p] and \
            str(ref.tous_rev[p]).split(".")[0] == gt["technique"]:
        d["etiquette"] = OBS
        d["remplacant"] = ref.tous_rev[p]
    elif pred["sous_technique"] in ref.tous_rev and ref.tous_rev[pred["sous_technique"]] \
            and str(ref.tous_rev[pred["sous_technique"]]).split(".")[0] == gt["technique"]:
        # CORRECTIF 2026-09 : scission v19. Le modele donne T1070 + T1070.002 ;
        # T1070 est toujours vivant, mais T1070.002 est revoque vers T1685.006.
        # L'identifiant le PLUS PRECIS porte l'intention : c'est une reponse
        # perimee, pas une erreur de raisonnement.
        d["etiquette"] = OBS
        d["remplacant"] = ref.tous_rev[pred["sous_technique"]]
    elif not RE_TECHNIQUE.match(p) or (p not in ref.toutes_tech
                                        and p not in ref.toutes_dep):
        if p in ref.tous_rev:
            d["etiquette"] = FP
        elif p in ref.anciens:
            d["etiquette"] = FP
            d["ancienne_version"] = True
        else:
            d["etiquette"] = HALL
    else:
        d["etiquette"] = FP
        if p in ref.toutes_dep:
            d["identifiant_deprecie"] = True
        if p not in ref.tech[m] and p not in ref.dep[m]:
            d["mauvaise_matrice"] = True
    res["technique"] = d

    # --- sous-technique ---
    p = pred["sous_technique"]
    attendue = gt["sous_technique"]
    a_sous = attendue not in ("", AUCUNE)
    d = {"predit": p, "applicable": a_sous}
    if not a_sous:
        # la technique attendue n'a pas de sous-technique
        if not p or p == AUCUNE:
            d["etiquette"] = VP
        elif p in ref.toutes_tech and RE_SOUS_TECHNIQUE.match(p):
            d["etiquette"] = FP
            d["sur_specification"] = True
        else:
            # methodologie 2.2 : un identifiant qui a existe n'est JAMAIS une
            # hallucination, meme propose la ou aucune sous-technique n'est
            # attendue. Un identifiant revoque (present dans la table des
            # remplacements) ou issu d'une version historique reste un FP
            # sur-specifie, porteur d'un drapeau.
            if p in ref.tous_rev and ref.tous_rev[p] == gt["technique"]:
                # CORRECTIF 2026-09 : T1562.004 revoque -> T1686 (technique
                # sans sous-technique attendue) : reponse perimee, pas une
                # sur-specification.
                d["etiquette"] = OBS
                d["remplacant"] = ref.tous_rev[p]
            elif p in ref.tous_rev:
                d["etiquette"] = FP
                d["identifiant_revoque"] = True
            elif p in ref.anciens:
                d["etiquette"] = FP
                d["ancienne_version"] = True
            else:
                d["etiquette"] = HALL
            d["sur_specification"] = True
    else:
        if p == attendue:
            d["etiquette"] = VP
        elif not p:
            d["etiquette"] = FN
            d["sous_specification"] = True
        elif p == AUCUNE:
            # « aucune » est une AFFIRMATION, pas une abstention : le modele
            # affirme que la technique ne possede pas de sous-technique, ce qui
            # est faux ici. La classer en abstention la dispenserait de toute
            # penalite de precision. Aux niveaux tactique et technique, en
            # revanche, « aucune » n'existe pas dans le schema impose : c'est
            # un refus de repondre, donc bien une abstention.
            d["etiquette"] = FP
            d["sous_technique_niee"] = True
        elif p in ref.tous_rev and ref.tous_rev[p] == attendue:
            d["etiquette"] = OBS
            d["remplacant"] = ref.tous_rev[p]
        elif not RE_SOUS_TECHNIQUE.match(p) or (p not in ref.toutes_tech
                                                 and p not in ref.toutes_dep):
            if p in ref.tous_rev:
                d["etiquette"] = FP
            elif p in ref.anciens:
                d["etiquette"] = FP
                d["ancienne_version"] = True
            else:
                d["etiquette"] = HALL
        else:
            d["etiquette"] = FP
            if p in ref.toutes_dep:
                d["identifiant_deprecie"] = True
            if p not in ref.tech[m] and p not in ref.dep[m]:
                d["mauvaise_matrice"] = True
    res["sous_technique"] = d
    return res


# ---- metriques -----------------------------------------------------------
def f1(precision, rappel):
    if precision + rappel <= 0:
        return 0.0
    return 2.0 * precision * rappel / (precision + rappel)


class Compteur(object):
    def __init__(self):
        self.n = 0
        self.c = defaultdict(int)      # etiquette -> effectif
        self.drapeaux = defaultdict(int)

    def ajouter(self, d):
        self.n += 1
        self.c[d["etiquette"]] += 1
        for k in ("mauvaise_matrice", "sur_specification", "sous_specification",
                  "sous_technique_niee", "scission_defense_evasion",
                  "identifiant_deprecie", "ancienne_version",
                  "identifiant_revoque"):
            if d.get(k):
                self.drapeaux[k] += 1

    def metriques(self, tolerant):
        """Precision = VP/(VP+FP) ; Rappel = VP/(VP+FN).
        Une prediction incorrecte compte FP *et* FN : elle affirme du faux et
        manque la bonne reponse. Une abstention ne compte que FN."""
        vp = self.c[VP] + (self.c[OBS] if tolerant else 0)
        # les identifiants deprecies et d'anciennes versions sont DANS FP
        # (methodologie 2.2) : aucun terme supplementaire ici
        fp = (self.c[FP] + self.c[HALL]
              + (0 if tolerant else self.c[OBS]))
        abstentions = self.c[FN]
        fn = fp + abstentions
        p = vp / (vp + fp) if (vp + fp) else 0.0
        r = vp / (vp + fn) if (vp + fn) else 0.0
        return {"n": self.n, "vp": vp, "fp": fp, "fn": fn,
                "abstentions": abstentions, "affirmations": vp + fp,
                "precision": p, "rappel": r, "f1": f1(p, r)}


def percentile(valeurs, q):
    if not valeurs:
        return 0.0
    v = sorted(valeurs)
    k = (len(v) - 1) * q
    lo, hi = math.floor(k), math.ceil(k)
    if lo == hi:
        return float(v[int(k)])
    return float(v[lo] + (v[hi] - v[lo]) * (k - lo))


# ---- rapport -------------------------------------------------------------
def pct(x):
    return "%5.1f%%" % (100.0 * x)


def rapport_sans_verite(recs, ref, a):
    """Rapport produit quand la verite de terrain n'est pas fournie.

    Trois familles d'indicateurs ne la demandent pas : l'usage du serveur, qui
    se lit dans la trace des appels ; le cout et la latence, qui se lisent dans
    les compteurs du harnais ; la stabilite, qui compare les executions d'un
    meme echantillon entre elles. Tout le reste — etiquetage, F1, classements —
    exige de savoir ce qui etait attendu, et n'est donc pas produit.

    La matrice de l'echantillon, elle, est portee par l'enregistrement
    (meta.matrice) : un identifiant pris hors de cette matrice reste donc
    detectable, en confrontant la prediction au referentiel fige.
    """
    aux = defaultdict(lambda: {"n": 0, "lat": [], "jet": [],
                               "mcp_util": 0, "mcp_appels": 0, "mcp_inconnus": 0,
                               "mcp_erreurs": 0, "tours": 0, "mcp_pertinents": 0,
                               "ancrees": 0, "ancrees_den": 0, "derive_version": 0,
                               "outils": defaultdict(int),
                               "mx_bon": 0, "mx_absent": 0, "mx_mauvais": 0,
                               "mx_exec_conformes": 0, "mx_exec_den": 0,
                               "introuvables": 0, "averti_puis_faux": 0,
                               "hors_matrice": 0, "avert": defaultdict(int)})
    reponses = defaultdict(dict)

    for r in recs:
        meta = r.get("meta") or {}
        cle = (meta.get("modele", "?"),
               meta.get("_condition", bool(meta.get("mcp_actif"))))
        A = aux[cle]
        A["n"] += 1
        A["lat"].append(meta.get("latence_ms") or 0)
        tok = r.get("usage") or {}
        A["jet"].append(jetons_consommes(r))  # CORRECTIF : cache compte une fois
        pred = normaliser_prediction(r.get("mapping"))
        reponses[cle].setdefault(meta.get("log_id"), []).append(
            (pred["tactique"], pred["technique"], pred["sous_technique"]))

        appels = r.get("appels_mcp") or []
        A["tours"] += r.get("tours") or 1
        if appels:
            A["mcp_util"] += 1
        A["mcp_appels"] += len(appels)
        A["mcp_inconnus"] += sum(1 for x in appels if x.get("inconnu"))
        A["mcp_erreurs"] += sum(1 for x in appels
                                if not x.get("ok") and not x.get("inconnu"))
        A["introuvables"] += sum(1 for x in appels if x.get("introuvable"))
        for x in appels:
            A["outils"][x.get("outil") or "?"] += 1
            if x.get("outil") in OUTILS_MAPPING:
                A["mcp_pertinents"] += 1
            for w in (x.get("avert") or []):
                A["avert"][w] += 1

        # ancrage : l'identifiant retenu figure-t-il parmi ceux rendus ?
        if appels and meta.get("statut") == "ok":
            vus = set()
            for x in appels:
                vus.update(x.get("ids_retournes") or [])
                if x.get("outil") == "get_technique":
                    vus.add(str((x.get("arguments") or {}).get("id", "")).upper())
            repondu = (pred["sous_technique"]
                       if pred["sous_technique"] not in ("", AUCUNE)
                       else pred["technique"])
            if repondu:
                A["ancrees_den"] += 1
                if repondu in vus or repondu.split(".")[0] in vus:
                    A["ancrees"] += 1

        # conformite de matrice des recherches
        attendue = str(meta.get("matrice", "")).lower()
        alias = {"enterprise": {"enterprise", "it"},
                 "ics": {"ics", "ot", "scada"}}.get(attendue, {attendue})
        etats = []
        for x in appels:
            if x.get("outil") not in ("search_techniques", "get_datasources"):
                continue
            mx = x.get("matrix")
            if mx is None:
                A["mx_absent"] += 1; etats.append(False)
            elif str(mx).lower() in alias:
                A["mx_bon"] += 1; etats.append(True)
            else:
                A["mx_mauvais"] += 1; etats.append(False)
        if etats:
            A["mx_exec_den"] += 1
            if all(etats):
                A["mx_exec_conformes"] += 1

        # identifiant pris hors de la matrice de l'echantillon : detectable
        # sans verite de terrain, en confrontant la prediction au referentiel.
        hors = False
        for niveau in ("technique", "sous_technique"):
            p = pred[niveau]
            if not p or p == AUCUNE or not RE_TECHNIQUE.match(p.split(".")[0]):
                continue
            if attendue in ref.tech and p not in ref.tech[attendue] \
                    and p not in ref.dep[attendue] and p in ref.toutes_tech:
                hors = True
        if hors:
            A["hors_matrice"] += 1
            if any("homonymes" in (x.get("avert") or []) for x in appels):
                A["averti_puis_faux"] += 1

        dbv = r.get("db_version_mcp")
        if bool(meta.get("mcp_actif")) and dbv and any(
                str(v) != str(a.version_attack) for v in
                (dbv.values() if isinstance(dbv, dict) else [dbv])):
            A["derive_version"] += 1

    # ---- volumetrie, cout, latence ----
    print("\n" + "=" * 100)
    print("VOLUMETRIE, COUT ET LATENCE — tous les modeles")
    print("=" * 100)
    print("%-24s %-4s %6s %9s %9s %9s %10s"
          % ("Modele", "MCP", "Exec.", "p50 ms", "p95 ms", "Jetons", "Jetons tot."))
    for cle in sorted(aux):
        A = aux[cle]
        print("%-24s %-4s %6d %9.0f %9.0f %9.0f %10d"
              % (cle[0][:24], lib_cond(cle[1]), A["n"],
                 percentile(A["lat"], .5), percentile(A["lat"], .95),
                 statistics.mean(A["jet"]) if A["jet"] else 0, sum(A["jet"])))

    # ---- stabilite ----
    print("\n" + "=" * 100)
    print("STABILITE — echantillons dont toutes les executions rendent le meme triplet")
    print("=" * 100)
    print("%-24s %-4s %10s %10s" % ("Modele", "MCP", "Stabilite", "Base"))
    for cle in sorted(aux):
        den = sum(1 for v in reponses[cle].values() if len(v) > 1)
        num = sum(1 for v in reponses[cle].values()
                  if len(v) > 1 and len(set(v)) == 1)
        print("%-24s %-4s %10s %10s"
              % (cle[0][:24], lib_cond(cle[1]),
                 pct(num / den if den else 0), "%d / %d" % (num, den)))

    # ---- usage du serveur ----
    avec = [k for k in sorted(aux) if est_mcp(k[1])]
    if avec:
        print("\n" + "=" * 100)
        print("USAGE DU SERVEUR MCP — campagnes avec serveur uniquement")
        print("=" * 100)
        print("%-22s %6s %6s %6s %7s %7s %6s %6s %7s %7s %6s"
              % ("Modele", "Util.", "App/ex", "Tou/ex", "Pertin.", "Hall.out",
                 "Err", "Dementi", "Ancrees", "Matrice", "AvFaux"))
        for cle in avec:
            A = aux[cle]
            mxt = A["mx_bon"] + A["mx_absent"] + A["mx_mauvais"]
            print("%-22s %6s %6.1f %6.1f %7s %7s %6d %6d %7s %7s %6d"
                  % (cle[0][:22],
                     pct(A["mcp_util"] / A["n"] if A["n"] else 0),
                     A["mcp_appels"] / max(A["n"], 1),
                     A["tours"] / max(A["n"], 1),
                     pct(A["mcp_pertinents"] / A["mcp_appels"] if A["mcp_appels"] else 0),
                     pct(A["mcp_inconnus"] / A["mcp_appels"] if A["mcp_appels"] else 0),
                     A["mcp_erreurs"], A["introuvables"],
                     pct(A["ancrees"] / A["ancrees_den"] if A["ancrees_den"] else 0),
                     pct(A["mx_bon"] / mxt if mxt else 0),
                     A["averti_puis_faux"]))
        print("Util. = executions ayant emis au moins un appel. App/ex, Tou/ex =")
        print("appels et tours par execution. Pertin. = appels vers un outil rendant")
        print("des identifiants. Hall.out = appels vers un outil inexistant. Err =")
        print("arguments refuses. Dementi = identifiant soumis puis declare")
        print("introuvable. Ancrees = l'identifiant retenu a ete rendu par un outil.")
        print("Matrice = recherches portant la bonne matrice. AvFaux = homonymie")
        print("signalee puis identifiant hors matrice retenu.")
        for cle in avec:
            A = aux[cle]
            mxt = A["mx_bon"] + A["mx_absent"] + A["mx_mauvais"]
            print("\n  %s" % cle[0][:60])
            print("    outils appeles          : %s"
                  % ", ".join("%s=%d" % kv for kv in
                              sorted(A["outils"].items(), key=lambda kv: -kv[1])))
            print("    matrice omise / erronee : %d / %d sur %d recherches"
                  % (A["mx_absent"], A["mx_mauvais"], mxt))
            print("    executions 100%% conformes: %s (%d / %d)"
                  % (pct(A["mx_exec_conformes"] / A["mx_exec_den"] if A["mx_exec_den"] else 0),
                     A["mx_exec_conformes"], A["mx_exec_den"]))
            print("    identifiants hors matrice: %d execution(s)" % A["hors_matrice"])
            if A["avert"]:
                print("    garde-fous du serveur   : %s"
                      % ", ".join("%s=%d" % kv for kv in
                                  sorted(A["avert"].items(), key=lambda kv: -kv[1])))
            if A["derive_version"]:
                print("    [!] DERIVE DE VERSION   : %d reponse(s) sur une version != v%s"
                      % (A["derive_version"], a.version_attack))

    print("\n[i] Pour l'etiquetage, les F1 et les classements de qualite,")
    print("    relancer avec --verite <verite_terrain.jsonl>.")
    return 0


# Condition d'evaluation : ce qui etait a disposition du modele. Sert de 2e
# element de la cle de groupement en mode interactif, a la place du booleen
# mcp_actif, pour qu'une meme paire de tableaux porte plusieurs conditions.
LIB_MODE = {1: "sans", 2: "MCP", 3: "MCP+skill", 4: "MCP+skill+cache"}


def condition_enregistrement(r):
    """1 sans MCP, 2 MCP, 3 MCP+skill, 4 MCP+skill+cache. La distinction
       3/4 repose sur le champ racine `cache`, ecrit par le harnais quand le
       cache de prompt etait actif. Les lignes en erreur d'une campagne
       cachee n'ont pas d'usage, donc pas de champ cache : elles retombent
       en 3 — sans consequence, le filtre d'infrastructure les ecarte."""
    m = r.get("meta") or {}
    if not m.get("mcp_actif"):
        return 1
    if not m.get("skill"):
        return 2
    return 4 if r.get("cache") else 3


def compter_condition(chemin, mode):
    """Nombre d'enregistrements de la condition dans un fichier."""
    n = 0
    try:
        with open(chemin, encoding="utf-8") as f:
            for ligne in f:
                ligne = ligne.strip()
                if not ligne:
                    continue
                try:
                    r = json.loads(ligne)
                    # seules les executions ABOUTIES sont comptees : c'est
                    # l'effectif que le rapport retiendra apres filtrage
                    if (r.get("meta") or {}).get("statut") == "ok" \
                            and condition_enregistrement(r) == mode:
                        n += 1
                except (ValueError, TypeError):
                    continue
    except OSError:
        return 0
    return n
# Une evaluation = un tour de menu (une condition, un ou plusieurs
# modeles). Une comparaison en porte DEUX au maximum : au-dela, le tableau
# comparatif cesse d'etre lisible. C'est une decision de presentation, pas
# une limite technique — pour comparer davantage, enchainer les comparaisons
# depuis le menu de fin.
MAX_EVALUATIONS = 2


def entete(titre, definitions, largeur=78):
    """Titre de tableau precede de la definition de ses attributs. Les
       definitions reprennent le vocabulaire de la methodologie (chapitre 1),
       pour que le rapport se lise sans avoir le memoire a cote."""
    print("\n" + "=" * largeur)
    print(titre)
    print("-" * largeur)
    for d in definitions:
        print("  " + d)
    print("=" * largeur)


def lib_cond(x):
    """Rend le 2e element d'une cle de groupe : libelle de condition en mode
       interactif, oui/non en ligne de commande."""
    return x if isinstance(x, str) else ("oui" if x else "non")


def est_mcp(x):
    """Le serveur etait-il a disposition ? Vrai pour toutes les conditions
       sauf « sans »."""
    return (x != "sans") if isinstance(x, str) else bool(x)



# =========================================================================
# EXPORT XLSX — un classeur, une feuille par tableau
# =========================================================================
# Chaque feuille porte sa couleur d'en-tete, ses definitions en tete, et une
# ligne par couple (modele, condition, niveau) : le nom du modele est REPETE
# a chaque ligne — jamais de cellule vide heritee de la ligne du dessus — et
# un filet epais separe les blocs de modeles. Les colonnes derivees
# (precision, rappel, F1, taux) sont des FORMULES qui referencent les comptes
# de la meme ligne : le classeur se recalcule si l'on corrige un compte.

COULEURS_FEUILLES = {
    "Synthese":      "1F4E79",   # bleu fonce
    "Etiquetage":    "375623",   # vert fonce
    "Base stricte":  "7B3F00",   # brun
    "Base tolerante": "8B5E00",  # ocre
    "Attributs":     "5B2C6F",   # violet
    "Par matrice":   "1B5E5E",   # sarcelle
    "Cout":          "7F1D1D",   # bordeaux
    "Usage MCP":     "2E4053",   # ardoise
    "Hallucinations": "922B21",  # rouge
    "Detail": "4A4A4A",          # gris ardoise
}


def _ecrire_feuille(ws, couleur, titre, definitions, entetes, lignes,
                    formats=None, cle_groupe=0):
    """Ecrit un tableau complet. `lignes` : liste de listes (valeurs ou
       chaines de formule commencant par '='). `cle_groupe` : indice, ou
       tuple d'indices, des colonnes dont le changement declenche un filet de
       separation — (0, 1) separe chaque couple (modele, condition), pour que
       les trois lignes de niveaux d'une meme evaluation forment un bloc."""
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter

    gras = Font(name="Arial", size=11, bold=True, color="FFFFFF")
    normal = Font(name="Arial", size=10)
    titre_f = Font(name="Arial", size=13, bold=True, color=couleur)
    note_f = Font(name="Arial", size=9, italic=True, color="555555")
    remplissage = PatternFill("solid", fgColor=couleur)
    fin = Side(style="thin", color="BFBFBF")
    epais = Side(style="medium", color=couleur)

    ws.cell(row=1, column=1, value=titre).font = titre_f
    r = 2
    for d in definitions:
        ws.cell(row=r, column=1, value=d).font = note_f
        r += 1
    r += 1
    ligne_entete = r
    for j, h in enumerate(entetes, 1):
        c = ws.cell(row=r, column=j, value=h)
        c.font = gras
        c.fill = remplissage
        c.alignment = Alignment(horizontal="center", vertical="center",
                                wrap_text=True)
        c.border = Border(bottom=epais)
    r += 1
    idx = ((cle_groupe,) if isinstance(cle_groupe, int)
           else tuple(cle_groupe or ()))

    def _cle(L):
        return tuple(L[i] for i in idx)

    precedent = None
    for L in lignes:
        nouveau = bool(idx) and _cle(L) != precedent
        for j, v in enumerate(L, 1):
            c = ws.cell(row=r, column=j, value=v)
            c.font = normal
            haut = epais if (nouveau and precedent is not None) else fin
            c.border = Border(top=haut, bottom=fin, left=fin, right=fin)
            if formats and formats.get(j - 1):
                c.number_format = formats[j - 1]
            if isinstance(v, str) and not v.startswith("="):
                c.alignment = Alignment(horizontal="left")
            else:
                c.alignment = Alignment(horizontal="right")
        if idx:
            precedent = _cle(L)
        r += 1
    # largeurs : le contenu le plus long de la colonne, borne
    for j, h in enumerate(entetes, 1):
        longueur = max([len(str(h))]
                       + [len(str(L[j - 1])) for L in lignes
                          if not (isinstance(L[j - 1], str)
                                  and L[j - 1].startswith("="))] or [10])
        ws.column_dimensions[get_column_letter(j)].width = min(max(longueur + 3, 10), 46)
    ws.freeze_panes = ws.cell(row=ligne_entete + 1, column=1)
    return ligne_entete


# --- definitions reprises de la methodologie (chapitre 1) ---------------
DEF_ETIQUETTES = [
    "VP : identifiant predit egal a l'attendu.",
    "FP : identifiant predit different de l'attendu — affirmation fausse.",
    "A  : abstention, aucune reponse a ce niveau (compte au rappel seul).",
    "H  : HALLUCINATION, identifiant qui n'existe dans aucune version du",
    "     referentiel (ni vivant, ni revoque, ni deprecie).",
    "F  : ANCIENNE VERSION, identifiant retire de la version figee mais",
    "     vivant dans une version anterieure (ICS v8, PRE-ATT&CK) —",
    "     referentiel interne perime, distinct de l'invention.",
    "O  : OBSOLETE, identifiant revoque dont le remplacant officiel est",
    "     la bonne reponse.",
    "MM : MAUVAISE MATRICE, identifiant pris hors de la matrice de",
    "     l'echantillon — sous-ensemble des FP.",
    "Une prediction fausse compte FP *et* FN : elle affirme du faux et",
    "manque la bonne reponse. Precision = VP/(VP+FP), Rappel = VP/(VP+FN).",
]
DEF_BASES = [
    "Base STRICTE : les identifiants obsoletes comptent comme des erreurs.",
    "Base TOLERANTE : ils sont credites, leur remplacant officiel etant la",
    "bonne reponse. L'ecart entre les deux mesure l'actualite du referentiel",
    "interne du modele, et rien d'autre.",
]
DEF_CONDITION = [
    "Condition : ce dont le modele disposait — sans (memoire seule), MCP",
    "(outils du serveur), MCP+skill (outils et procedure de mapping).",
]

NOM_VERITE = "verite_terrain.jsonl"
# Emplacements de la verite de terrain dans le depot, relatifs a sa racine ;
# le premier qui existe est retenu. Le meme ordre que preparer_dataset.py,
# qui l'ecrit a cet endroit.
CHEMINS_VERITE = (
    "cas_d_usage/workflow_evaluation/dataset",
    "cas_d_usage/workflow_evaluation",
    "dataset",
)


def racine_depot(depart):
    """Racine du depot, sans aucun chemin en dur : on REMONTE depuis `depart`
       jusqu'au premier dossier contenant A LA FOIS .github et cas_d_usage —
       les deux vivent sur la meme racine, c'est le marqueur le plus sur,
       valable quel que soit le disque, le nom du clone ou l'utilisateur.
       Repli : un dossier nomme mitre-attack-framework. Identique a la
       fonction du meme nom dans preparer_dataset.py, pour que les deux
       scripts s'accordent sur la meme racine."""
    depart = pathlib.Path(depart).resolve()
    candidats = [depart] + list(depart.parents)
    for p in candidats:
        if (p / ".github").is_dir() and (p / "cas_d_usage").is_dir():
            return p
    for p in candidats:
        if p.name == "mitre-attack-framework":
            return p
    return None


def trouver_verite(option=None):
    """Localise verite_terrain.jsonl sans chemin en dur. Ordre :
         1. --verite, s'il est fourni ;
         2. la variable d'environnement VERITE_TERRAIN ;
         3. le fichier a cote de l'appelant (dossier courant, dossier du script) ;
         4. la racine du depot, atteinte en remontant depuis le script PUIS
            depuis le dossier courant, aux emplacements connus, puis par
            recherche recursive en dernier recours.
       La verite de terrain ne bouge pas : une fois le depot trouve, elle est
       toujours au meme endroit. Renvoie un chemin ou None."""
    if option:
        p = pathlib.Path(option).expanduser()
        if p.is_dir():
            p = p / NOM_VERITE
        return p if p.exists() else None
    env = os.environ.get("VERITE_TERRAIN")
    if env and pathlib.Path(env).expanduser().exists():
        return pathlib.Path(env).expanduser()
    for d in (pathlib.Path.cwd(), pathlib.Path(__file__).resolve().parent):
        if (d / NOM_VERITE).exists():
            return d / NOM_VERITE
    vus = set()
    for depart in (pathlib.Path(__file__).resolve().parent, pathlib.Path.cwd()):
        depot = racine_depot(depart)
        if depot is None or depot in vus:
            continue
        vus.add(depot)
        for rel in CHEMINS_VERITE:
            c = depot / pathlib.Path(rel) / NOM_VERITE
            if c.exists():
                return c
        # dernier recours : le depot a ete reorganise
        trouves = sorted(depot.rglob(NOM_VERITE))
        if trouves:
            return trouves[0]
    return None


def charger_tarifs(chemin_cli=None):
    """tarifs.json : {"date_tarifs": "...", "devise": "USD", "modeles":
       {nom: {"entree": $/M, "sortie": $/M, "cache_lecture": $/M,
              "cache_ecriture": $/M}}}. entree null = tarif inconnu.
       Renvoie (tarifs, date, chemin) ou (None, None, None)."""
    p = (pathlib.Path(chemin_cli) if chemin_cli
         else pathlib.Path(__file__).resolve().parent / "tarifs.json")
    if not p.is_file():
        return None, None, None
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, OSError) as e:
        print("[!] %s illisible (%s) : colonne argent omise" % (p.name, e))
        return None, None, None
    modeles = {k: v for k, v in (d.get("modeles") or {}).items()
               if isinstance(v, dict) and v.get("entree") is not None}
    return modeles, d.get("date_tarifs", "date inconnue"), p


def cout_execution(L, t):
    """Cout d'une execution en dollars ; tarifs en $ par million.
       CORRECTIF 2026-09 : L["te"] ne contient plus que l'entree HORS cache
       (voir entree_plein_tarif). Un tarif de cache non renseigne (null dans
       tarifs.json) n'est donc plus lu comme « gratuit » : les jetons du cache
       sont alors factures au tarif d'entree normal, ce qui redonne exactement
       le resultat de l'ancien calcul pour ces modeles (borne haute : la
       remise de cache reelle n'est pas appliquee faute de tarif connu)."""
    pe = t.get("entree") or 0
    pcl = t.get("cache_lecture")
    pce = t.get("cache_ecriture")
    return (L.get("te", 0) * pe
            + L.get("ts", 0) * (t.get("sortie") or 0)
            + L.get("cl", 0) * (pcl if pcl is not None else pe)
            + L.get("ce", 0) * (pce if pce is not None else pe)) / 1e6


def titre_rapport(recs, libelles=None):
    """(titre lisible, nom de fichier) pour un jeu d'enregistrements.
       Le titre dit ce que le rapport compare : modeles, puis conditions
       reliees par « vs » quand il y en a plusieurs."""
    LIB_TITRE = {"non": "sans MCP", "sans": "sans MCP",
                 "oui": "MCP", "MCP": "MCP", "MCP+skill": "MCP+skill"}
    ORDRE_COND = {"sans MCP": 0, "MCP": 1, "MCP+skill": 2,
                  "MCP+skill+cache": 3}
    modeles, conds = [], []
    for r in recs:
        m = r.get("meta") or {}
        mo = str(m.get("modele") or "?")
        brut = lib_cond(m.get("_condition", bool(m.get("mcp_actif"))))
        co = LIB_TITRE.get(brut, brut)
        if mo not in modeles:
            modeles.append(mo)
        if co not in conds:
            conds.append(co)
    modeles.sort()
    conds.sort(key=lambda c: (ORDRE_COND.get(c, 9), c))
    if libelles:
        # le menu sait si « tous les modeles » a ete choisi : son libelle prime
        slug = "__".join(libelles)[:120]
    else:
        part_m = "+".join(abreger(m) for m in modeles[:3])                  + ("+%d" % (len(modeles) - 3) if len(modeles) > 3 else "")
        slug = ("%s_%s" % (part_m, "_vs_".join(c.replace("+", "-").replace(" ", "-")
                                               for c in conds)))[:120]
    if len(modeles) <= 3:
        part_m = ", ".join(modeles)
    else:
        part_m = "%d modeles (%s, ...)" % (len(modeles), ", ".join(modeles[:2]))
    titre = "%s : %s" % (part_m, " vs ".join(conds))
    return titre, slug


class _SectionCSV(object):
    """Section d'un CSV a plusieurs tables : ecrit « ### TITRE » a l'entree,
       une ligne vide a la sortie, et rend le meme descripteur de fichier."""
    def __init__(self, f, titre):
        self.f, self.titre = f, titre

    def __enter__(self):
        self.f.write("### %s\n" % self.titre)
        return self.f

    def __exit__(self, *exc):
        self.f.write("\n")
        return False


class _Tee(object):
    """Duplique tout ce qui part a l'ecran vers un tampon, pour sauvegarder le
       rapport texte a l'identique de ce que l'utilisateur a vu."""
    def __init__(self, *flux):
        self.flux = flux

    def write(self, x):
        for f in self.flux:
            f.write(x)

    def flush(self):
        for f in self.flux:
            f.flush()


def racine_n8n():
    """Dossier des fichiers de n8n, sans chemin en dur : N8N_FILES_DIR,
       sinon <repertoire personnel>/.n8n-files — le meme ordre que le harnais."""
    env = os.environ.get("N8N_FILES_DIR")
    return pathlib.Path(env).expanduser() if env else pathlib.Path.home() / ".n8n-files"


# Copie locale des resultats de n8n, dans le dossier de sortie des rapports.
NOM_COPIE_N8N = "resultats_evaluation_n8n"
# Noms usuels du dossier de fichiers de n8n dans le repertoire personnel.
NOMS_DOSSIER_N8N = (".n8n-files", "n8n-files", ".n8nfiles", "n8nfiles",
                    ".n8n_files", "n8n_files")


def _enfants(dossier):
    """Sous-dossiers de `dossier`, sans lever d'erreur (droits, absence)."""
    try:
        return [p for p in pathlib.Path(dossier).iterdir() if p.is_dir()]
    except OSError:
        return []


def _repertoires_personnels():
    """Repertoire(s) personnel(s) de l'utilisateur COURANT, quel qu'il soit :
       jamais de nom d'utilisateur en dur. Sous Windows, Path.home() lit
       %USERPROFILE% ; HOMEDRIVE+HOMEPATH et HOME servent de replis."""
    cands = [pathlib.Path.home()]
    for var in ("USERPROFILE", "HOME"):
        v = os.environ.get(var)
        if v:
            cands.append(pathlib.Path(v))
    hd, hp = os.environ.get("HOMEDRIVE"), os.environ.get("HOMEPATH")
    if hd and hp:
        cands.append(pathlib.Path(hd + hp))
    vus, res = set(), []
    for c in cands:
        k = os.path.normcase(os.path.abspath(str(c)))
        if k not in vus and c.is_dir():
            vus.add(k)
            res.append(c)
    return res


def _dossier_resultats(base):
    """`base` peut etre le dossier de n8n ou deja son sous-dossier resultats.
       Renvoie le dossier qui contient des resultats_*.jsonl, sinon None."""
    base = pathlib.Path(base).expanduser()
    for d in (base / "resultats", base):
        try:
            if d.is_dir() and any(d.glob("resultats_*.jsonl")):
                return d
        except OSError:
            continue
    return None


def trouver_source_n8n(option=None):
    """Localise <dossier n8n>/resultats sans aucun chemin en dur. Ordre :
         1. --source-n8n ;
         2. N8N_FILES_DIR ;
         3. <repertoire personnel>/<nom usuel> (NOMS_DOSSIER_N8N) ;
         4. un dossier dont le nom contient « n8n » dans le repertoire
            personnel, Documents, Bureau/Desktop ou OneDrive.
       Renvoie un chemin ou None."""
    if option:
        d = _dossier_resultats(option)
        if d is None:
            print("[!] --source-n8n : aucun fichier resultats_*.jsonl dans %s"
                  % option)
        return d
    env = os.environ.get("N8N_FILES_DIR")
    if env:
        d = _dossier_resultats(env)
        if d:
            return d
    homes = _repertoires_personnels()
    for h in homes:
        for nom in NOMS_DOSSIER_N8N:
            d = _dossier_resultats(h / nom)
            if d:
                return d
    for h in homes:
        parents = [h]
        for p in _enfants(h):
            n = p.name.lower()
            if n in ("documents", "desktop", "bureau") or n.startswith("onedrive"):
                parents.append(p)
                if n.startswith("onedrive"):
                    parents += [q for q in _enfants(p)
                                if q.name.lower() in ("documents", "desktop", "bureau")]
        for par in parents:
            for p in _enfants(par):
                if "n8n" in p.name.lower():
                    d = _dossier_resultats(p)
                    if d:
                        return d
    return None


def copier_resultats_n8n(source, dossier_rapport):
    """Copie TOUT le dossier `source` (resultats de n8n, sous-dossiers
       compris) dans <dossier_rapport>/resultats_evaluation_n8n et renvoie
       ce chemin. La copie passe par un dossier temporaire : si elle echoue,
       la copie precedente reste intacte et sert de repli."""
    dest = pathlib.Path(dossier_rapport) / NOM_COPIE_N8N
    tmp = dest.with_name(NOM_COPIE_N8N + ".en_cours")

    def repli(motif):
        if _dossier_resultats(dest):
            print("[!] %s\n    -> utilisation de la copie precedente : %s"
                  % (motif, dest.resolve()))
            return dest
        print("[!] %s\n    Indiquer le dossier avec --source-n8n <dossier> ou "
              "la variable N8N_FILES_DIR." % motif)
        return None

    if source is None:
        return repli("dossier des resultats n8n introuvable (recherche : "
                     "N8N_FILES_DIR, puis %s dans le repertoire personnel)"
                     % ", ".join(NOMS_DOSSIER_N8N))
    source = pathlib.Path(source)
    print("[*] source n8n        : %s" % source.resolve())
    ignorer = shutil.ignore_patterns(NOM_COPIE_N8N, NOM_COPIE_N8N + ".en_cours")
    try:
        if tmp.exists():
            shutil.rmtree(tmp)
        try:
            shutil.copytree(str(source), str(tmp), ignore=ignorer)
        except shutil.Error as e:
            # fichiers verrouilles (n8n en train d'ecrire, antivirus...) :
            # le reste est copie, on signale ceux qui manquent
            echecs = e.args[0] if e.args and isinstance(e.args[0], list) else []
            print("[!] %d fichier(s) non copie(s) :" % len(echecs))
            for src, _, err in echecs[:5]:
                print("      %s (%s)" % (src, err))
        # remplacement de l'ancienne copie par la nouvelle
        try:
            if dest.exists():
                shutil.rmtree(dest)
            tmp.rename(dest)
        except OSError:
            # un fichier de l'ancienne copie est ouvert (editeur, Excel) :
            # on ecrase fichier par fichier
            shutil.copytree(str(tmp), str(dest), dirs_exist_ok=True)
            shutil.rmtree(tmp, ignore_errors=True)
    except OSError as e:
        shutil.rmtree(tmp, ignore_errors=True)
        return repli("copie impossible depuis %s : %s" % (source, e))
    fichiers = [p for p in dest.rglob("*") if p.is_file()]
    n_jsonl = len(list(dest.glob("resultats_*.jsonl")))
    taille = sum(p.stat().st_size for p in fichiers)
    print("[*] copie des resultats : %s" % dest.resolve())
    print("    %d fichier(s) copie(s), dont %d resultats_*.jsonl (%.1f Mo)"
          % (len(fichiers), n_jsonl, taille / 1e6))
    return dest


def rediriger_vers_copie(motifs, source, copie):
    """Ligne de commande : un fichier (ou un motif glob) designe DANS le
       dossier n8n est lu dans la copie, jamais a la source."""
    if not source or not copie:
        return motifs
    src = os.path.abspath(str(source))
    src_n = os.path.normcase(src)
    res = []
    for m in motifs:
        absm = os.path.abspath(os.path.expanduser(m))
        if os.path.normcase(absm).startswith(src_n + os.sep):
            nouveau = str(pathlib.Path(copie) / absm[len(src) + 1:])
            print("[i] lu dans la copie : %s" % nouveau)
            res.append(nouveau)
        else:
            res.append(m)
    return res


def demander(question, defaut):
    try:
        r = input("%s [%s] : " % (question, defaut)).strip()
    except EOFError:
        r = ""
    return r or str(defaut)


def oui_non(question, defaut=False):
    r = demander(question + " (o/n)", "o" if defaut else "n").strip().lower()
    return r.startswith("o") or r.startswith("y")


def menu_interactif(premier=True, dossier_defaut=None):
    """Renvoie (mode, motifs de fichiers, chemin de la verite de terrain).
       mode : 1 = sans MCP, 2 = avec MCP, 3 = avec MCP + skill."""
    print("\n" + "=" * 62)
    print("  CALCUL DES METRIQUES — evaluation des modeles LLM"
          if premier else "  EVALUATION SUPPLEMENTAIRE")
    print("=" * 62)
    print("  1. SANS MCP              (le modele repond de memoire)")
    print("  2. AVEC MCP              (les outils du serveur)")
    print("  3. AVEC MCP+SKILL        (outils + procedure, sans cache)")
    print("  4. AVEC MCP+SKILL+CACHE  (idem, cache de prompt actif)")
    mode = 0
    while mode not in (1, 2, 3, 4):
        try:
            mode = int(demander("Choix", "1"))
        except ValueError:
            mode = 0
    defaut_dir = (dossier_defaut or trouver_source_n8n()
                  or (racine_n8n() / "resultats"))
    dossier = pathlib.Path(demander("Dossier des resultats", defaut_dir)).expanduser()
    # Le nom d'un fichier ne dit pas ce qu'il contient — un meme fichier
    # peut porter plusieurs phases. On balaie donc le CONTENU : seuls les
    # fichiers ayant au moins une execution de la condition choisie sont
    # proposes, avec leur effectif.
    tous = sorted(dossier.glob("resultats_*.jsonl"))
    if not tous:
        sys.exit("[!] aucun fichier resultats_*.jsonl dans %s" % dossier)
    print("\n  [i] examen du contenu de %d fichier(s)..." % len(tous))
    retenus = [(p, compter_condition(p, mode)) for p in tous]
    fichiers = [p for p, n in retenus if n]
    if not fichiers:
        sys.exit("[!] aucun des %d fichier(s) de %s ne contient d'execution "
                 "de la condition « %s »."
                 % (len(tous), dossier, LIB_MODE.get(mode, mode)))
    print("  %d fichier(s) contiennent la condition « %s » :"
          % (len(fichiers), LIB_MODE.get(mode, mode)))
    for p, n in retenus:
        if n:
            print("    - %-52s %5d execution(s)" % (p.name, n))
    # La verite de terrain ne bouge jamais : on ne la redemande qu'au premier
    # tour, les evaluations suivantes reutilisent la meme.
    if not premier:
        return mode, [str(p) for p in fichiers], None, dossier
    auto = trouver_verite()
    if auto:
        print("\n  verite de terrain trouvee : %s" % auto)
    verite = demander("Verite de terrain",
                      auto if auto else (pathlib.Path.cwd() / NOM_VERITE))
    return mode, [str(p) for p in fichiers], verite, dossier


# Selection du dernier tour de menu : sert a nommer le fichier de sortie.
DERNIERE_SELECTION = {"tous": True, "modeles": []}


def abreger(nom):
    """Nom de modele utilisable dans un nom de fichier."""
    return re.sub(r"[^A-Za-z0-9.+-]+", "-", str(nom)).strip("-")[:40]


def libelle_evaluation(mode):
    """Libelle d'une evaluation : modeles retenus + condition. « tous les
       modeles » n'a de sens que s'il y en avait plusieurs a choisir."""
    cond = LIB_MODE.get(mode, "?").replace("+", "-")
    if DERNIERE_SELECTION["tous"] and len(DERNIERE_SELECTION["modeles"]) > 1:
        return "tous-les-modeles_%s" % cond
    return "%s_%s" % ("+".join(abreger(m) for m in DERNIERE_SELECTION["modeles"]),
                      cond)


def choisir_modeles(recs):
    """Sous-menu : tous les modeles, ou une selection. La liste est construite
       a partir des enregistrements REELLEMENT retenus par le mode, pas d'une
       liste ecrite en dur : elle reflete donc ce qui est disponible pour la
       condition choisie."""
    presents = defaultdict(int)
    for r in recs:
        presents[str((r.get("meta") or {}).get("modele") or "?")] += 1
    noms = sorted(presents)
    DERNIERE_SELECTION["tous"] = True
    DERNIERE_SELECTION["modeles"] = noms
    if len(noms) <= 1:
        if noms:
            print("    [i] un seul modele disponible : %s (%d execution(s))"
                  % (noms[0], presents[noms[0]]))
        return recs
    print("\n  Modeles disponibles pour cette condition :")
    for i, n in enumerate(noms, 1):
        print("    %2d. %-32s %4d execution(s)" % (i, n, presents[n]))
    print("\n  1. TOUS les modeles")
    print("  2. Une SELECTION")
    choix = 0
    while choix not in (1, 2):
        try:
            choix = int(demander("Choix", "1"))
        except ValueError:
            choix = 0
    if choix == 1:
        return recs
    retenus = None
    while not retenus:
        brut = demander("Numeros separes par une virgule (ex. 1,3,4)", "1")
        idx, mauvais = [], []
        for x in re.split(r"[,;\s]+", brut.strip()):
            if not x:
                continue
            try:
                k = int(x)
            except ValueError:
                mauvais.append(x); continue
            if 1 <= k <= len(noms):
                idx.append(k)
            else:
                mauvais.append(x)
        if mauvais:
            print("    [!] ignore(s), hors de la liste : %s" % ", ".join(mauvais))
        retenus = {noms[k - 1] for k in idx}
        if not retenus:
            print("    [!] aucun modele valide — recommencer.")
    print("    [i] retenu(s) : %s" % ", ".join(sorted(retenus)))
    DERNIERE_SELECTION["tous"] = (len(retenus) == len(noms))
    DERNIERE_SELECTION["modeles"] = sorted(retenus)
    return [r for r in recs
            if str((r.get("meta") or {}).get("modele") or "?") in retenus]


def detail_hallucinations(hallucinations):
    """Ou les modeles ont halluciné : identifiant exact, niveau, echantillon.
       HALLUCINATION = identifiant qui n'existe dans aucune version du
       referentiel — distinct de l'identifiant d'une ancienne version (F) et
       de l'identifiant pris dans l'autre matrice (MM), qui existent tous deux."""
    if not hallucinations:
        print("\n[ok] Aucune hallucination : tous les identifiants predits")
        print("     existent dans le referentiel.")
        return
    entete("DETAIL DES HALLUCINATIONS — identifiants inexistants",
           ["Un identifiant est compte ici s'il n'existe dans AUCUNE version du",
            "referentiel : ni vivant, ni revoque, ni deprecie, ni dans une",
            "version anterieure. Ce n'est donc ni un identifiant perime (F),",
            "ni un identifiant pris dans l'autre matrice (MM) : c'est une",
            "invention, que l'analyste ne trouvera nulle part.",
            "Exec. : nombre d'executions ou la meme invention est apparue."])
    par_cle = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    for h in hallucinations:
        par_cle[(h["modele"], h["condition"])][h["predit"]][h["echantillon"]].append(h)
    total = 0
    for cle in sorted(par_cle, key=lambda c: (c[0], str(c[1]))):
        mo, co = cle
        n_mod = sum(len(v) for ids in par_cle[cle].values() for v in ids.values())
        total += n_mod
        print("\n  %s  [condition %s] — %d occurrence(s)" % (mo, lib_cond(co), n_mod))
        print("    %-12s %-15s %-15s %-8s %s"
              % ("Identifiant", "Niveau", "Matrice", "Exec.", "Echantillons (attendu)"))
        for ident in sorted(par_cle[cle]):
            ech_map = par_cle[cle][ident]
            occ = sum(len(v) for v in ech_map.values())
            niveaux = sorted({h["niveau"] for v in ech_map.values() for h in v})
            matrices = sorted({h["matrice"] for v in ech_map.values() for h in v})
            details = ", ".join(
                "%s x%d (attendu %s)" % (e, len(ech_map[e]),
                                         ech_map[e][0]["attendu"] or "-")
                for e in sorted(ech_map))
            print("    %-12s %-15s %-15s %-8d %s"
                  % (ident, "/".join(LIB_NIVEAU[n] for n in niveaux),
                     "/".join(matrices), occ, details))
    print("\n  TOTAL : %d hallucination(s) sur l'ensemble du rapport." % total)


def menu_details(hallucinations):
    """Menu de fin : le script ne quitte pas tant que l'utilisateur veut des
       details. Une seule vue pour l'instant ; la structure est prete a en
       recevoir d'autres."""
    while True:
        print("\n" + "=" * 62)
        print("  DETAILS")
        print("=" * 62)
        print("  1. Hallucinations — identifiants inexistants, par echantillon")
        print("  0. Terminer")
        choix = demander("Choix", "0").strip()
        if choix in ("0", "", "q", "n"):
            return
        if choix == "1":
            detail_hallucinations(hallucinations)
        else:
            print("    [!] choix inconnu.")


def etiqueter_condition(recs, mode):
    """Marque chaque enregistrement avec la CONDITION d'evaluation du tour.
       C'est ce libelle qui devient le 2e element de la cle de groupement, a
       la place du booleen mcp_actif : plusieurs conditions cohabitent alors
       dans une meme paire de tableaux."""
    for r in recs:
        (r.setdefault("meta", {}))["_condition"] = LIB_MODE.get(mode, "?")
    return recs


def filtrer_mode(recs, mode):
    """Ne garde que les enregistrements de la CONDITION choisie : les fichiers
       peuvent melanger les phases (le meme JSONL porte du sans-MCP et du
       avec-MCP quand les campagnes ont partage un fichier)."""
    garde = [r for r in recs if condition_enregistrement(r) == mode]
    if not garde:
        sys.exit("[!] aucun enregistrement ne correspond au mode choisi "
                 "(verifier les fichiers et la condition).")
    ecarte = len(recs) - len(garde)
    if ecarte:
        print("    [i] %d ligne(s) d'une autre condition ecartee(s) par le mode" % ecarte)
    return garde


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("resultats", nargs="*",
                    help="fichier(s) JSONL de resultats (glob accepte) ; "
                         "SANS argument, un menu interactif est propose")
    ap.add_argument("--tarifs", default=None,
                    help="fichier de tarifs en $ par million de jetons ; "
                         "defaut : tarifs.json a cote du script, s'il existe")
    ap.add_argument("--csv", action="store_true",
                    help="sans effet, conserve pour compatibilite : les trois "
                         "CSV detailles sont desormais toujours produits")
    ap.add_argument("--sans-classement", action="store_true",
                    help="produire les tables (etiquetage, bases stricte et "
                         "tolerante par niveau, cout) SANS les classements — "
                         "le meme affichage que le mode interactif")
    ap.add_argument("--details-hallucinations", action="store_true",
                    help="imprimer le detail des hallucinations (identifiants "
                         "inexistants et leurs echantillons) ; en mode "
                         "interactif, un menu le propose a la fin")
    ap.add_argument("--sans-verite", action="store_true",
                    help="ne pas chercher la verite de terrain : seules les "
                         "metriques qui n'en dependent pas sont produites")
    ap.add_argument("--verite", default=None,
                    help="verite_terrain.jsonl ; PAR DEFAUT il est localise "
                         "tout seul (dossier courant, puis racine du depot). "
                         "Sans lui, seules les metriques "
                         "qui ne dependent pas de la verite de terrain sont "
                         "produites (usage du serveur, cout, latence, stabilite)")
    ap.add_argument("--version-attack", default=VERSION_ATTACK_DEFAUT,
                    help="version figee du referentiel (defaut %s)" % VERSION_ATTACK_DEFAUT)
    ap.add_argument("--cache", default=tempfile.gettempdir(), help="cache du referentiel STIX")
    ap.add_argument("--sortie", default=None,
                    help="dossier de sortie des rapports (texte, xlsx, csv). "
                         "Defaut : rapports/ a cote de ce script. Les "
                         "resultats n8n y sont copies dans "
                         "resultats_evaluation_n8n/ au lancement.")
    ap.add_argument("--source-n8n", default=None,
                    help="dossier des resultats de n8n a copier ; PAR DEFAUT "
                         "il est localise tout seul (N8N_FILES_DIR, puis "
                         "<repertoire personnel>/.n8n-files/resultats)")
    ap.add_argument("--attendu", type=int, default=42, help="taille attendue du corpus")
    a = ap.parse_args()

    if a.sortie is None:
        # un sous-dossier rapports/ A COTE DU SCRIPT : previsible quel que
        # soit l'endroit d'ou la commande est lancee, et les sorties ne se
        # melangent pas au code ni a la verite de terrain
        a.sortie = str(pathlib.Path(__file__).resolve().parent / "rapports")

    def preparer_sortie():
        """Dossier de sortie utilisable, avec replis silencieux sur ./rapports
           puis sur le dossier courant si l'emplacement vise est en lecture
           seule. Resolu une fois, annonce une fois."""
        if getattr(a, "_sortie_resolue", None) is not None:
            return a._sortie_resolue
        for cand in (a.sortie, "."):
            try:
                p = pathlib.Path(cand)
                p.mkdir(parents=True, exist_ok=True)
                probe = p / ".ecriture_test"
                probe.write_text("", encoding="utf-8")
                probe.unlink()
                if str(p) != str(a.sortie):
                    print("[i] %r inaccessible en ecriture : sortie dans %s"
                          % (str(a.sortie), p.resolve()))
                a._sortie_resolue = p
                print("[*] dossier de sortie : %s" % p.resolve())
                return p
            except OSError:
                continue
        a._sortie_resolue = pathlib.Path(".")
        return a._sortie_resolue

    # ---- 1. copie des resultats n8n, des le lancement ----
    # Tout le dossier <n8n>/resultats est copie dans
    # <sortie>/resultats_evaluation_n8n ; le calcul ne lit ensuite QUE cette
    # copie (menu comme ligne de commande).
    a.source_n8n_resolue = trouver_source_n8n(a.source_n8n)
    a.dossier_copie = copier_resultats_n8n(a.source_n8n_resolue,
                                           preparer_sortie())
    a.resultats = rediriger_vers_copie(a.resultats, a.source_n8n_resolue,
                                       a.dossier_copie)

    # ---- mode interactif : aucun fichier sur la ligne de commande ----
    a.mode_menu = 0
    a.dossier_menu = None
    if not a.resultats:
        a.mode_menu, a.resultats, verite_choisie, a.dossier_menu = \
            menu_interactif(dossier_defaut=a.dossier_copie)
        if a.verite is None:
            a.verite = verite_choisie

    # La verite de terrain ne bouge jamais : on la localise au lieu de la
    # demander. --verite reste prioritaire, --sans-verite desactive tout.
    if a.sans_verite:
        chemin_vt = None
    else:
        chemin_vt = trouver_verite(a.verite)
        if a.verite and chemin_vt is None:
            sys.exit("[!] Verite de terrain introuvable : %s" % a.verite)
        if chemin_vt is None:
            print("[i] verite de terrain introuvable — cherchee dans le dossier "
                  "courant,\n    puis a la racine du depot (marqueurs .github + "
                  "cas_d_usage)\n    aux emplacements : "
                  + ", ".join(CHEMINS_VERITE)
                  + "\n    L'indiquer avec --verite, ou poser VERITE_TERRAIN.")
    vt = charger_verite(str(chemin_vt)) if chemin_vt else None
    recs = charger_resultats(a.resultats)
    if not a.mode_menu:
        # CORRECTIF 2026-09 : en ligne de commande, le groupement se faisait sur
        # le booleen mcp_actif. MCP, MCP+skill et MCP+skill+cache d'un meme
        # modele tombaient dans le meme groupe et le dedoublonnage en ECRASAIT
        # silencieusement deux sur trois (252 lignes perdues pour Opus).
        for r in recs:
            (r.setdefault("meta", {}))["_condition"] = \
                LIB_MODE.get(condition_enregistrement(r), "?")
    if a.mode_menu:
        # Chaque tour ajoute une CONDITION aux memes tableaux : une seule paire
        # base stricte / base tolerante porte l'ensemble, une ligne par couple
        # (modele, condition). C'est ce qui rend la comparaison lisible sans
        # empiler des tableaux separes.
        recs = etiqueter_condition(filtrer_mode(recs, a.mode_menu), a.mode_menu)
        recs = choisir_modeles(recs)
        def fusionner(cumul, lot):
            """Ajoute au cumul les executions qu'il ne contient pas deja."""
            avant = {(r["meta"].get("modele"), r["meta"].get("_condition"),
                      r["meta"].get("log_id"), r["meta"].get("numero_run"))
                     for r in cumul}
            neufs = [r for r in lot
                     if (r["meta"].get("modele"), r["meta"].get("_condition"),
                         r["meta"].get("log_id"), r["meta"].get("numero_run"))
                     not in avant]
            if len(neufs) != len(lot):
                print("    [i] %d execution(s) deja presente(s) dans une "
                      "evaluation precedente, ignoree(s)" % (len(lot) - len(neufs)))
            cumul.extend(neufs)
            return bool(neufs)

        def recapituler(recs):
            conds = sorted({(r["meta"].get("modele"), r["meta"].get("_condition"))
                            for r in recs}, key=lambda t: (t[0], str(t[1])))
            print("\n[*] %d couple(s) modele x condition dans le rapport :"
                  % len(conds))
            for mo, co in conds:
                print("      %-32s %s" % (mo, co))

        cumul = list(recs)
        a.n_evaluations = 1
        a.libelles_eval = [libelle_evaluation(a.mode_menu)]

        def ajouter_evaluation(cumul):
            """Un tour de menu de plus, fusionne dans le cumul. Renvoie True si
               quelque chose a ete ajoute."""
            mode2, fichiers2, _, a.dossier_menu = menu_interactif(
                premier=False, dossier_defaut=a.dossier_menu)
            lot = charger_resultats(fichiers2)
            lot = etiqueter_condition(filtrer_mode(lot, mode2), mode2)
            lot = choisir_modeles(lot)
            ajoute = fusionner(cumul, lot)
            a.n_evaluations += 1
            a.libelles_eval.append(libelle_evaluation(mode2))
            return ajoute

        def nouvelle_comparaison():
            """Repart de zero : un nouveau tour de menu remplace le cumul, puis
               la boucle d'ajout reprend dans la limite du plafond."""
            mode2, fichiers2, _, a.dossier_menu = menu_interactif(
                premier=False, dossier_defaut=a.dossier_menu)
            lot = charger_resultats(fichiers2)
            lot = etiqueter_condition(filtrer_mode(lot, mode2), mode2)
            lot = choisir_modeles(lot)
            neuf = list(lot)
            a.n_evaluations = 1
            a.libelles_eval = [libelle_evaluation(mode2)]
            while a.n_evaluations < MAX_EVALUATIONS and \
                    oui_non("\nAjouter une autre evaluation ? (%d/%d)"
                            % (a.n_evaluations, MAX_EVALUATIONS)):
                ajouter_evaluation(neuf)
            recapituler(neuf)
            return neuf

        a.ajouter_evaluation = ajouter_evaluation
        a.nouvelle_comparaison = nouvelle_comparaison
        while a.n_evaluations < MAX_EVALUATIONS and \
                oui_non("\nAjouter une autre evaluation ? (%d/%d)"
                        % (a.n_evaluations, MAX_EVALUATIONS)):
            ajouter_evaluation(cumul)
        recs = cumul
        recapituler(recs)
    ref = Referentiel(a.version_attack, a.cache)
    if chemin_vt:
        print("[*] verite de terrain : %s" % chemin_vt)
    print("[*] referentiel fige v%s | verite de terrain : %s | reponses : %d"
          % (a.version_attack,
             ("%d echantillons" % len(vt)) if vt else "ABSENTE",
             len(recs)))
    if vt:
        valider_verite(vt, ref)
    if vt and len(vt) != a.attendu:
        print("    [i] corpus de %d echantillons (attendu %d)" % (len(vt), a.attendu))
    if not vt:
        print("    [i] sans --verite : ni etiquetage, ni F1, ni classement de qualite.")
        print("        Sont produits l'usage du serveur, le cout, la latence et la")
        print("        stabilite, qui ne dependent pas de la verite de terrain.")

    # --- provenance : quel harnais a produit quoi -------------------------
    # Le discriminant des campagnes est meta.mcp_actif, PAS version_pipeline.
    # `mcp_actif` decrit la CONDITION d'evaluation — le serveur etait-il a
    # disposition — et c'est ce qui doit grouper les resultats : une execution
    # ou le serveur etait disponible mais inutilise reste une execution de
    # phase 2, et c'est precisement ce que le taux d'ancrage doit reveler.
    # `version_pipeline` est une etiquette de TRACABILITE : elle dit quel code
    # de harnais a ecrit la ligne. Elle est rapportee ici, croisee avec la
    # condition, pour qu'un melange accidentel se voie tout de suite.
    prov = defaultdict(int)
    for r in recs:
        m = r.get("meta") or {}
        prov[(str(m.get("version_pipeline") or "?"), bool(m.get("mcp_actif")))] += 1
    print("    [i] provenance : " + " | ".join(
        "%s %s (%d ligne(s))" % (v, "avec MCP" if x else "sans MCP", n)
        for (v, x), n in sorted(prov.items())))
    # Une etiquette de pipeline denote une campagne AVEC serveur si elle
    # mentionne le serveur ou le skill, qui en depend (6.0-skill).
    incoherentes = [(v, x, n) for (v, x), n in prov.items()
                    if (("mcp" in v.lower()) or ("skill" in v.lower())) != x]
    if incoherentes:
        print("    [!] etiquette de pipeline et drapeau mcp_actif en desaccord : "
              + ", ".join("%s / mcp_actif=%s (%d)" % (v, x, n)
                          for v, x, n in incoherentes))
        print("        le groupement suit mcp_actif ; verifier le harnais.")


    if not vt:
        return rapport_sans_verite(recs, ref, a)

    def rapport(recs):
        """Analyse complete : etiquetage, tableaux, CSV. Isolee en fonction
           pour pouvoir etre REJOUEE apres l'ajout d'une evaluation, sans
           relancer le script. Renvoie la liste des hallucinations, seule
           donnee dont le menu de details a besoin."""
        # --- filtrage prealable (methodologie, sections 2.2 et 2.5) ---
        # 1. les iterations abandonnees pour cause d'infrastructure ne mesurent pas
        #    le modele : quota epuise, requete annulee, delai depasse, coupure reseau.
        #    Les compter en faux negatifs attribuerait au modele une panne de la
        #    plomberie. Le drapeau est pose par le harnais.
        # 2. le fichier de resultats est ecrit en mode ajout : un lancement
        #    abandonne peut laisser des lignes en double. On garde la derniere
        #    occurrence de chaque couple (echantillon, execution).
        uniques, doublons = {}, 0
        for r in recs:
            m = r.get("meta") or {}
            cle_ex = (m.get("modele"),
                      m.get("_condition", bool(m.get("mcp_actif"))),
                      m.get("log_id"), m.get("numero_run"))
            if cle_ex in uniques:
                doublons += 1
                # une ligne ABOUTIE ne doit jamais etre ecrasee par une relance en
                # erreur ecrite apres elle (fichier en mode ajout, reprises)
                if (uniques[cle_ex].get("meta") or {}).get("statut") == "ok" \
                        and (r.get("meta") or {}).get("statut") != "ok":
                    continue
            uniques[cle_ex] = r
        if doublons:
            print("    [!] %d ligne(s) en double ignoree(s) (meme modele, echantillon et execution)"
                  % doublons)
            recs = list(uniques.values())
        # Reponses inexploitables IMPUTABLES AU MODELE (methodologie 2.2 :
        # « format non respecte, JSON invalide, reponse vide ») + le budget de
        # tours d'outils epuise et la troncature, qui sont le fait du modele.
        # Elles deviennent des abstentions aux trois niveaux, JAMAIS des
        # exclusions — meme si un harnais a pose le drapeau : le script fait
        # autorite sur la regle, le drapeau ne couvre que l'infrastructure.
        IMPUTABLES_MODELE = ("format_non_respecte", "json_invalide",
                             "troncature_budget", "reponse_vide",
                             "mcp_tours_epuises")

        def est_infra(r):
            m = r.get("meta") or {}
            if str(m.get("statut", "")) in IMPUTABLES_MODELE:
                return False
            if m.get("exclure_des_metriques") or m.get("erreur_infrastructure"):
                return True
            # les fichiers reels ne portent pas toujours le drapeau : tout
            # statut erreur_* est un echec d'appel (quota, annulation, delai,
            # reseau), jamais une reponse du modele. Les reponses
            # inexploitables imputables au modele ont leurs propres statuts
            # (format_non_respecte, json_invalide, troncature_budget) et
            # deviennent des abstentions, conformement a la methodologie.
            return str(m.get("statut", "")).startswith("erreur_")
        ecartees = [r for r in recs if est_infra(r)]
        if ecartees:
            par_mod = defaultdict(int)
            for r in ecartees:
                par_mod[(r.get("meta") or {}).get("modele", "?")] += 1
            print("    [i] %d iteration(s) ABANDONNEE(S) — jamais abouties, erreur d'infrastructure, "
                  "effectif par modele :" % len(ecartees))
            for mo in sorted(par_mod):
                print("          %-32s %d" % (mo, par_mod[mo]))
            infra_set = set(map(id, ecartees))
            recs = [r for r in recs if id(r) not in infra_set]

        # --- etiquetage ---
        lignes, inconnus = [], set()
        for r in recs:
            meta = r.get("meta", {})
            ech = meta.get("log_id")
            if ech not in vt:
                inconnus.add(ech)
                continue
            gt = vt[ech]
            statut = meta.get("statut", "ok")
            if statut == "ok":
                pred = normaliser_prediction(r.get("mapping"))
            else:
                pred = {k: "" for k in NIVEAUX}     # reponse rejetee : abstention aux 3 niveaux
            et = etiqueter(pred, gt, ref)
            tok = r.get("usage") or {}
            appels = r.get("appels_mcp") or []
            lignes.append({
                "appels": appels, "tours": r.get("tours") or 1,
                "db_version_mcp": r.get("db_version_mcp"),
                "echantillon": ech, "modele": meta.get("modele", "?"),
                "run": meta.get("numero_run", 1), "mcp": bool(meta.get("mcp_actif")),
                # condition d'evaluation : libelle en mode interactif (plusieurs
                # conditions dans les memes tableaux), booleen sinon
                "condition": meta.get("_condition", bool(meta.get("mcp_actif"))),
                "zone": gt["zone"], "matrice": gt["matrice"], "statut": statut,
                "latence_ms": meta.get("latence_ms") or 0,
                # jetons factures = entree + sortie, raisonnement compris. Certains
                # fournisseurs (Gemini via Vertex) rapportent le raisonnement A PART
                # de la sortie ; s'il depasse la sortie, il n'y est pas inclus et
                # doit etre ajoute. Chez les autres, il en est un sous-ensemble.
                "jetons": jetons_consommes(r),  # CORRECTIF : cache compte une fois
                "pred": pred, "gt": gt, "et": et,
                # croisement serveur / modele : "oui" / "non" par niveau,
                # rempli plus bas pour les campagnes avec serveur
                "mcp_rendu": {n: "" for n in NIVEAUX},
                # composantes facturables, aux tarifs propres a chacune :
                # la sortie inclut le raisonnement rapporte A PART (meme
                # regle que la colonne jetons) ; le cache vient du champ
                # racine, ecrit par le harnais quand le cache etait actif
                "te": entree_plein_tarif(r),  # CORRECTIF : cache deduit si inclus
                "ts": sortie_facturee(r),  # CORRECTIF : regle par fournisseur
                "cl": int((r.get("cache") or {}).get("lecture") or 0),
                "ce": int((r.get("cache") or {}).get("ecriture") or 0),
            })
        if inconnus:
            print("    [!] %d echantillon(s) absent(s) de la verite de terrain, ignore(s) : %s"
                  % (len(inconnus), ", ".join(sorted(str(x) for x in inconnus))[:120]))
        if not lignes:
            sys.exit("[!] Aucune reponse exploitable.")

        # --- agregation par (modele, mcp) et par (modele, mcp, matrice) ---
        hallucinations = []
        mauvaises_matrices = []
        hors_bilan = defaultdict(list)
        groupes = defaultdict(lambda: {n: Compteur() for n in NIVEAUX})
        groupes_m = defaultdict(lambda: {n: Compteur() for n in NIVEAUX})
        par_run = defaultdict(lambda: {n: Compteur() for n in NIVEAUX})
        aux = defaultdict(lambda: {"n": 0, "format": 0, "erreurs_api": 0, "lat": [], "jet": [], "fact": [],
                                   "n1": 0, "n2_num": 0, "n2_den": 0,
                                   "sur_spec": 0, "term_den": 0,
                                   "mcp_util": 0, "mcp_appels": 0, "mcp_inconnus": 0,
                                   "mcp_erreurs": 0, "tours": 0, "mcp_pertinents": 0,
                                   "ancrees": 0, "ancrees_den": 0, "derive_version": 0,
                                   "outils": defaultdict(int),
                                   # croisement serveur / modele, AUX TROIS NIVEAUX :
                                   # ce que le serveur a fourni contre ce que le
                                   # modele a retenu. Un sous-dictionnaire par niveau.
                                   "cr": {n: {"n": 0, "rendu_retenu": 0,
                                              "rendu_autre": 0, "absent_juste": 0,
                                              "absent_faux": 0} for n in NIVEAUX},
                                   "cand_tot": 0, "cand_den": 0,
                                   # phase 2 : conformite de matrice et dementis
                                   "mx_bon": 0, "mx_absent": 0, "mx_mauvais": 0,
                                   "mx_exec_conformes": 0, "mx_exec_den": 0,
                                   "introuvables": 0, "averti_puis_faux": 0,
                                   "avert": defaultdict(int)})
        reponses = defaultdict(dict)

        groupes_ok = defaultdict(lambda: {n: Compteur() for n in NIVEAUX})
        for L in lignes:
            for n in NIVEAUX:
                # MEME regle d'applicabilite que les tableaux : le niveau
                # sous-technique n'est compte que pour les echantillons qui en
                # possedent une. Sans ce filtre, le detail montrerait des cas
                # absents de la colonne H, ce qui rendrait les deux inconciliables.
                if n == "sous_technique" and not L["et"][n]["applicable"]:
                    # CORRECTIF 2026-09 : une sous-technique INVENTEE sur un
                    # echantillon terminal (ex. T1016.003) sortait de tous les
                    # comptes d'hallucination : elle n'apparaissait qu'en
                    # sur-specification. Elle est desormais listee, marquee
                    # « terminal », sans entrer dans le F1 sous-technique.
                    if L["et"][n]["etiquette"] == HALL:
                        hallucinations.append({
                            "modele": L["modele"], "condition": L["condition"],
                            "echantillon": L["echantillon"], "run": L["run"],
                            "niveau": "sous_technique (terminal)",
                            "predit": L["et"][n]["predit"] + "*",
                            "attendu": L["gt"][n], "matrice": L["matrice"]})
                    continue
                if L["et"][n]["etiquette"] == HALL:
                    hallucinations.append({
                        "modele": L["modele"], "condition": L["condition"],
                        "echantillon": L["echantillon"], "run": L["run"],
                        "niveau": n, "predit": L["et"][n]["predit"],
                        "attendu": L["gt"][n], "matrice": L["matrice"]})
                if L["et"][n].get("mauvaise_matrice"):
                    mauvaises_matrices.append({
                        "modele": L["modele"], "condition": L["condition"],
                        "predit": L["et"][n]["predit"],
                        "attendu": L["gt"][n], "echantillon": L["echantillon"]})
            cle = (L["modele"], L["condition"])
            exploitable = (L["statut"] == "ok")
            for n in NIVEAUX:
                # le F1 sous-technique ne porte que sur les echantillons qui en ont une
                if n == "sous_technique" and not L["et"][n]["applicable"]:
                    hors_bilan[(L["modele"], L["condition"], n)].append(
                        "%s#%s" % (L["echantillon"], L["run"]))
                    continue
                groupes[cle][n].ajouter(L["et"][n])
                groupes_m[(L["modele"], L["condition"], L["matrice"])][n].ajouter(L["et"][n])
                par_run[(L["modele"], L["condition"], L["run"])][n].ajouter(L["et"][n])
                if exploitable:
                    groupes_ok[cle][n].ajouter(L["et"][n])
            A = aux[cle]
            A["n"] += 1
            # echantillons terminaux (pas de sous-technique) : taux de sur-specification
            if not L["et"]["sous_technique"]["applicable"]:
                A["term_den"] += 1
                if L["et"]["sous_technique"].get("sur_specification"):
                    A["sur_spec"] += 1
            if L["statut"] == "format_non_respecte":
                A["format"] += 1
            elif L["statut"] != "ok":
                A["erreurs_api"] += 1
            A["lat"].append(L["latence_ms"]); A["jet"].append(L["jetons"])
            A["fact"].append({k: L[k] for k in ("te", "ts", "cl", "ce")})
            if L["appels"]:
                A["mcp_util"] += 1
            A["mcp_appels"] += len(L["appels"])
            A["mcp_inconnus"] += sum(1 for x in L["appels"] if x.get("inconnu"))
            A["mcp_erreurs"] += sum(1 for x in L["appels"] if not x.get("ok") and not x.get("inconnu"))
            A["tours"] += L["tours"]
            for x in L["appels"]:
                A["outils"][x.get("outil") or "?"] += 1
                if x.get("outil") in OUTILS_MAPPING:
                    A["mcp_pertinents"] += 1
            # reponse ancree : l'identifiant repondu a ete VU dans un resultat d'outil
            # (ou consulte explicitement via get_technique)
            if L["mcp"] and L["statut"] == "ok":
                vus = set()
                for x in L["appels"]:
                    vus.update(x.get("ids_retournes") or [])
                    if x.get("outil") in ("get_technique", "get_tactic"):
                        vus.add(str((x.get("arguments") or {}).get("id", "")).upper())
                repondu = L["pred"]["sous_technique"] if L["pred"]["sous_technique"] not in ("", AUCUNE) \
                          else L["pred"]["technique"]
                if repondu:
                    A["ancrees_den"] += 1
                    if repondu in vus or repondu.split(".")[0] in vus:
                        A["ancrees"] += 1
                # ---- croisement serveur / modele, AUX TROIS NIVEAUX ----------
                # Deux verifications par execution et par niveau :
                #   1. la bonne reponse figure-t-elle parmi les identifiants que
                #      les outils ont rendus ? -> le serveur l'a FOURNIE ;
                #   2. la reponse finale du modele est-elle la bonne ?
                #      -> le modele l'a RETENUE.
                # "Fournie" garde la definition des reponses ancrees : tout
                # identifiant apparu dans un resultat d'outil, ou consulte
                # explicitement par get_technique / get_tactic. Le niveau
                # sous-technique ne compte que les echantillons qui en ont une.
                A["cand_tot"] += len(vus); A["cand_den"] += 1
                for n in NIVEAUX:
                    if n == "sous_technique" and not L["et"][n]["applicable"]:
                        continue
                    att_n = L["gt"][n]
                    fournie = bool(att_n) and att_n in vus
                    juste = (L["pred"][n] == att_n)
                    L["mcp_rendu"][n] = "oui" if fournie else "non"
                    C = A["cr"][n]
                    C["n"] += 1
                    if juste:
                        C["rendu_retenu" if fournie else "absent_juste"] += 1
                    else:
                        C["rendu_autre" if fournie else "absent_faux"] += 1
            # --- conformite de matrice des recherches (phase 2) ---
            # `matrix` est la valeur transmise au serveur, relevee par le harnais ;
            # None signifie que le modele a omis le parametre. Les alias IT/OT/SCADA
            # sont acceptes par le serveur, donc comptes comme conformes.
            if L["mcp"]:
                attendue = L["matrice"]
                alias = {"enterprise": {"enterprise", "it"},
                         "ics": {"ics", "ot", "scada"}}.get(attendue, {attendue})
                etats = []
                for x in L["appels"]:
                    if x.get("outil") not in ("search_techniques", "get_datasources"):
                        continue
                    mx = x.get("matrix")
                    if mx is None:
                        A["mx_absent"] += 1; etats.append(False)
                    elif str(mx).lower() in alias:
                        A["mx_bon"] += 1; etats.append(True)
                    else:
                        A["mx_mauvais"] += 1; etats.append(False)
                if etats:
                    A["mx_exec_den"] += 1
                    if all(etats):
                        A["mx_exec_conformes"] += 1
                A["introuvables"] += sum(1 for x in L["appels"] if x.get("introuvable"))
                for x in L["appels"]:
                    for w in (x.get("avert") or []):
                        A["avert"][w] += 1
                # le serveur a signale une homonymie ET un identifiant hors matrice
                # a ete retenu : l'avertissement a ete lu sans etre suivi.
                averti = any("homonymes" in (x.get("avert") or []) for x in L["appels"])
                hors = any(L["et"][n].get("mauvaise_matrice") for n in NIVEAUX)
                if averti and hors:
                    A["averti_puis_faux"] += 1
            dbv = L.get("db_version_mcp")
            if L["mcp"] and dbv and any(str(v) != str(a.version_attack) for v in
                                         (dbv.values() if isinstance(dbv, dict) else [dbv])):
                A["derive_version"] += 1
            # sous-specification
            # N1 : le modele s'arrete a la tactique (aucune technique proposee)
            if L["et"]["technique"]["etiquette"] == FN and L["et"]["tactique"]["etiquette"] != FN:
                A["n1"] += 1
            if L["et"]["sous_technique"]["applicable"]:
                A["n2_den"] += 1
                if L["et"]["technique"]["etiquette"] == VP and \
                        L["et"]["sous_technique"].get("sous_specification"):
                    A["n2_num"] += 1
            reponses[cle].setdefault(L["echantillon"], []).append(
                (L["pred"]["tactique"], L["pred"]["technique"], L["pred"]["sous_technique"]))

        # --- 1. etiquetage, tous les modeles ---------------------------------
        # Remplace les blocs par modele : une ligne par (modele, MCP, niveau).
        # Les lignes MCP ne font PAS l'objet d'un tableau separe, elles
        # s'inscrivent dans les memes tableaux, signalees par la colonne MCP.
        def stabilite(cle):
            """Part des echantillons dont les executions repetees rendent le MEME
               triplet. Ne depend d'aucune base de calcul ni de la verite de
               terrain : c'est une mesure de reproductibilite, pas de justesse.
               Une valeur par couple (modele, condition), donc affichee une seule
               fois par bloc."""
            v = reponses[cle]
            den = sum(1 for x in v.values() if len(x) > 1)
            num = sum(1 for x in v.values() if len(x) > 1 and len(set(x)) == 1)
            return (num / den) if den else 0.0

        def bloc_par_niveau(titre, definitions, tolerant):
            """Un bloc de trois lignes par couple (modele, condition) : une par
               niveau. Les taux propres au couple — stabilite — ne sont ecrits que
               sur la premiere ligne du bloc."""
            entete(titre, definitions)
            print("%-24s %-15s %-15s %8s %7s %6s %7s %7s %8s %7s"
                  % ("Modele", "Condition", "Niveau", "MauvMat", "Halluc",
                     "Fant", "Obsol", "Abst.", "F1", "Stab."))
            for cle in sorted(groupes):
                modele, cond = cle
                for i, n in enumerate(NIVEAUX):
                    c = groupes[cle][n]
                    m = c.metriques(tolerant)
                    aff = m["affirmations"]
                    print("%-24s %-15s %-15s %8d %7s %6s %7s %7s %8.3f %7s"
                          % (modele[:24] if i == 0 else "",
                             lib_cond(cond) if i == 0 else "",
                             LIB_NIVEAU[n],
                             c.drapeaux["mauvaise_matrice"],
                             pct(c.c[HALL] / aff if aff else 0),
                             pct((c.drapeaux["ancienne_version"]
                                  + c.drapeaux["identifiant_deprecie"]) / aff
                                 if aff else 0),
                             pct(c.c[OBS] / aff if aff else 0),
                             pct(m["abstentions"] / m["n"] if m["n"] else 0),
                             m["f1"],
                             pct(stabilite(cle)) if i == 0 else ""))

        entete("ETIQUETAGE — une etiquette par niveau et par execution",
               DEF_ETIQUETTES
               + ["Integrite N : controle du script, pas une metrique. Chaque",
                  "     prediction porte une etiquette et une seule, donc les colonnes",
                  "     VP + FP + H + O + A doivent additionner exactement N",
                  "     (F est un sous-compte de FP, affiche pour lecture,",
                  "     jamais additionne).",
                  "     « oui » = l'egalite tombe juste.",
                  "     Sinon la cellule donne le TOTAL A ATTEINDRE, l'ecart entre",
                  "     parentheses, et les executions fautives quand elles sont",
                  "     identifiables (echantillon#execution). Les F1 de la ligne",
                  "     sont alors a rejeter tant que l'ecart n'est pas explique.",
                  "Sous-technique : uniquement les echantillons qui en possedent une."],
               100)
        print("%-24s %-15s %-15s %5s %5s %5s %5s %5s %5s %5s %5s  %s"
              % ("Modele", "Condition", "Niveau", "N", "VP", "FP", "H", "F", "O",
                 "A", "MM", "Integrite N"))
        for cle in sorted(groupes):
            modele, mcp = cle
            for n in NIVEAUX:
                c = groupes[cle][n]
                n_vp, n_fp = c.c[VP], c.c[FP]
                n_h, n_o, n_a = c.c[HALL], c.c[OBS], c.c[FN]
                # F affiche = etiquette ANCIENNE_VERSION (hors version figee mais
                # historique) + FP portant le drapeau identifiant_deprecie (present
                # dans la version figee comme depreciee, sans remplacant)
                n_f = (c.drapeaux["ancienne_version"]
                       + c.drapeaux["identifiant_deprecie"])
                ecart = c.n - (n_vp + n_fp + n_h + n_o + n_a)
                if ecart == 0:
                    integrite = "oui"
                else:
                    integrite = "%d attendu (%+d)" % (c.n, -ecart)
                    fautives = hors_bilan.get((modele, mcp, n), [])
                    if fautives:
                        integrite += " — " + ", ".join(fautives[:4])
                        if len(fautives) > 4:
                            integrite += " (+%d)" % (len(fautives) - 4)
                print("%-24s %-15s %-15s %5d %5d %5d %5d %5d %5d %5d %5d  %s"
                      % (modele[:24], lib_cond(mcp), LIB_NIVEAU[n],
                         c.n, n_vp, n_fp, n_h, n_f, n_o, n_a,
                         c.drapeaux["mauvaise_matrice"], integrite))
        print("F additionne les identifiants DEPRECIES de la version figee (retires")
        print("sans remplacant, ex. T0808) et ceux d'une version historique absents")
        print("de la figee (ex. TA0024) ; les deprecies restent des FP dans N.")

        # --- 2. attributs de diagnostic, tous les modeles ---------------------
        entete("ATTRIBUTS DE DIAGNOSTIC",
               ["MM : identifiants hors de la matrice de l'echantillon, 3 niveaux.",
                "s-t nie : repond « aucune » alors qu'une sous-technique existe —",
                "          une affirmation fausse, pas une abstention.",
                "scis19 : TA0005 propose la ou TA0112 est attendu (scission v19).",
                "format : reponses rejetees imputables au modele (format non",
                "         respecte, JSON invalide, reponse vide, troncature).",
                "Sur-sp. : sur-specification — sous-technique proposee la ou la",
                "          verite de terrain n'en attend aucune.",
                "N1, N2 : sous-specification — technique sans sous-technique la ou",
                "         elle est attendue. Le format impose les trois champs :",
                "         une valeur nulle est une propriete du protocole."], 100)
        print("%-24s %-15s %5s %8s %7s %7s %8s %6s %6s"
              % ("Modele", "Condition", "MM", "s-t nie", "scis19", "format",
                 "Sur-sp.", "N1", "N2"))
        for cle in sorted(groupes):
            modele, mcp = cle
            A = aux[cle]
            print("%-24s %-15s %5d %8d %7d %7d %8s %6s %6s"
                  % (modele[:24], lib_cond(mcp),
                     sum(groupes[cle][n].drapeaux["mauvaise_matrice"] for n in NIVEAUX),
                     groupes[cle]["sous_technique"].drapeaux["sous_technique_niee"],
                     groupes[cle]["tactique"].drapeaux["scission_defense_evasion"],
                     A["format"] + A["erreurs_api"],
                     pct(A["sur_spec"] / A["term_den"] if A["term_den"] else 0),
                     pct(A["n1"] / A["n"] if A["n"] else 0),
                     pct(A["n2_num"] / A["n2_den"] if A["n2_den"] else 0)))


        # --- 3. ventilation par matrice --------------------------------------
        entete("VENTILATION PAR MATRICE — F1 stricts",
               DEF_CONDITION
               + ["Les memes executions, reparties selon la matrice prescrite par",
                  "l'echantillon : enterprise (zone TI) ou ics (zone TO).",
                  "n s-t : executions portant sur un echantillon a sous-technique attendue.",
                  "ICS : F1 sous-technique non rapporte (2 echantillons seulement) ;",
                  "      ces executions restent comptees dans le F1 sous-technique global."], 100)
        print("%-24s %-15s %-12s %5s %8s %8s %8s %6s"
              % ("Modele", "Condition", "Matrice", "n", "F1 tact", "F1 tech", "F1 s-t", "n s-t"))
        for (mo, mc, ma) in sorted(groupes_m):
            v = [groupes_m[(mo, mc, ma)][n].metriques(False) for n in NIVEAUX]
            # CORRECTIF 2026-09 : le F1 sous-technique ICS n'est plus rapporte
            # (2 echantillons) ; il reste compte dans le F1 sous-technique global.
            if ma == "ics":
                fst, nst = "%8s" % "-", "%6s" % "-"
            else:
                fst, nst = "%8.3f" % v[2]["f1"], "%6d" % v[2]["n"]
            print("%-24s %-15s %-12s %5d %8.3f %8.3f %8s %6s"
                  % (mo[:24], lib_cond(mc), ma, v[0]["n"],
                     v[0]["f1"], v[1]["f1"], fst, nst))

        # --- tableau de synthese ---
        bloc_par_niveau("QUALITE DU MAPPING — BASE STRICTE",
                        DEF_BASES + DEF_CONDITION
               + ["Une ligne par NIVEAU : les trois se lisent l'un sous l'autre.",
                  "MauvMat : effectif des identifiants hors matrice a ce niveau.",
                  "Halluc / Fant / Obsol : part des affirmations de ce niveau.",
                  "Abst. : part des reponses sans identifiant a ce niveau.",
                  "F1 : moyenne harmonique de la precision et du rappel.",
                  "Stab. : part des echantillons dont les executions repetees",
                  "        rendent le meme triplet — une valeur par modele et",
                  "        condition, ecrite sur la premiere ligne du bloc."], False)
        rejets_par_cle = {c: aux[c]["format"] + aux[c]["erreurs_api"]
                          for c in groupes}
        if any(rejets_par_cle.values()):
            print("\nF1 techniques HORS REJETS (methodologie 2.2 : les reponses")
            print("inexploitables imputables au modele sont des abstentions ; les")
            print("F1 sont aussi recalcules en les excluant du denominateur) :")
            for c in sorted(groupes):
                if not rejets_par_cle[c]:
                    continue
                ms = groupes_ok[c]["technique"].metriques(False)
                mt = groupes_ok[c]["technique"].metriques(True)
                print("  %-24s %-15s %d rejet(s) | F1 tech S %.3f | T %.3f"
                      % (c[0][:24], lib_cond(c[1]), rejets_par_cle[c],
                         ms["f1"], mt["f1"]))

        bloc_par_niveau("QUALITE DU MAPPING — BASE TOLERANTE",
                        DEF_BASES + DEF_CONDITION
               + ["Une ligne par NIVEAU : les trois se lisent l'un sous l'autre.",
                  "MauvMat : effectif des identifiants hors matrice a ce niveau.",
                  "Halluc / Fant / Obsol : part des affirmations de ce niveau.",
                  "Abst. : part des reponses sans identifiant a ce niveau.",
                  "F1 : moyenne harmonique de la precision et du rappel.",
                  "Stab. : part des echantillons dont les executions repetees",
                  "        rendent le meme triplet — une valeur par modele et",
                  "        condition, ecrite sur la premiere ligne du bloc."], True)

        # --- classement des modeles, sur chacune des deux bases ---
        # Tri lexicographique, sans grandeur composite, par gravite decroissante de
        # la faute :
        #   1. MAUVAISE MATRICE croissante — faute la plus grave : le modele repond
        #      dans l'autre univers (Enterprise pour un journal ICS, ou l'inverse),
        #      ce qui rend la mitigation proposee inapplicable ;
        #   2. taux d'hallucination croissant — le modele fabrique un identifiant ;
        #   3. F1 decroissant : technique (niveau de reference, les mitigations
        #      MITRE s'y rattachent), puis tactique, puis sous-technique ;
        #   4. taux d'obsolescence croissant ;
        #   5. taux d'abstention croissant.
        # Aucun autre critere n'intervient.
        # Meme ordre applique aux deux bases, de sorte que la seule difference entre
        # les deux tableaux soit le traitement des identifiants obsoletes.
        # Pour classer d'abord sur le F1 tactique, remplacer ORDRE_F1 par
        # ("tactique", "technique", "sous_technique").
        ORDRE_F1 = ("technique", "tactique", "sous_technique")
        def classement(tolerant):
            libelle = "tolerante" if tolerant else "stricte"
            P = {}
            for cle in groupes:
                ms = [groupes[cle][n].metriques(tolerant) for n in NIVEAUX]
                aff = sum(x["affirmations"] for x in ms)
                tot = sum(x["n"] for x in ms)
                P[cle] = {"f1": [x["f1"] for x in ms],
                          "mm": sum(groupes[cle][n].drapeaux["mauvaise_matrice"]
                                    for n in NIVEAUX),
                          "hall": sum(groupes[cle][n].c[HALL] for n in NIVEAUX) / aff
                                  if aff else 0.0,
                          "fant_aff": sum(groupes[cle][n].drapeaux["ancienne_version"]
                                          + groupes[cle][n].drapeaux["identifiant_deprecie"]
                                          for n in NIVEAUX) / aff if aff else 0.0,
                          "obs": sum(groupes[cle][n].c[OBS] for n in NIVEAUX) / aff
                                 if aff else 0.0,
                          "abst": sum(x["abstentions"] for x in ms) / tot if tot else 0.0}
            # Tri lexicographique par gravite : la mauvaise matrice prime — un
            # identifiant pris dans l'autre matrice ne designe pas seulement une
            # mauvaise technique, il designe un mauvais univers, et la mitigation
            # qui en decoule est inapplicable au systeme observe. Vient ensuite le
            # taux d'hallucination, car un modele qui fabrique des identifiants est
            # ecarte d'un usage operationnel quel que soit son F1. Les F1 ne
            # departagent que les modeles qui ont passe ces deux filtres ;
            # obsolescence et abstention servent de departage final.
            iF1 = [NIVEAUX.index(n) for n in ORDRE_F1]
            ordre = sorted(groupes, key=lambda c: (P[c]["mm"], P[c]["hall"],
                                                    -P[c]["f1"][iF1[0]],
                                                    -P[c]["f1"][iF1[1]],
                                                    -P[c]["f1"][iF1[2]],
                                                    P[c]["obs"], P[c]["abst"]))
            print("\n" + "=" * 78)
            print("CLASSEMENT — QUALITE DU MAPPING, base %s" % libelle)
            print("criteres, du plus grave au plus fin : 1. mauvaise matrice la plus")
            print("basse — 2. hallucination la plus basse (les identifiants perimes,")
            print("deprecies ou d'anciennes versions, sont des FP : colonne Fant,")
            print("informative) — 3. F1 les plus eleves")
            print("(%s) — 4. obsolescence — 5. abstention"
                  % ", ".join(LIB_NIVEAU[n].lower() for n in ORDRE_F1))
            print("=" * 78)
            print("%-4s %-24s %-4s %8s %8s %6s %8s %8s %8s %7s %7s"
                  % ("Rang", "Modele", "MCP", "MauvMat", "Halluc", "Fant",
                     "F1 " + ORDRE_F1[0][:4], "F1 " + ORDRE_F1[1][:4],
                     "F1 " + ORDRE_F1[2][:4], "Obsol", "Abst."))
            for i, cle in enumerate(ordre, 1):
                modele, mcp = cle
                p = P[cle]
                print("%-4d %-24s %-4s %8d %8s %6s %8.3f %8.3f %8.3f %7s %7s"
                      % (i, modele[:24], lib_cond(mcp),
                         p["mm"], pct(p["hall"]), pct(p["fant_aff"]),
                         p["f1"][iF1[0]], p["f1"][iF1[1]], p["f1"][iF1[2]],
                         pct(p["obs"]), pct(p["abst"])))
            print("MauvMat = nombre d'identifiants predits hors de la matrice de")
            print("l'echantillon, les trois niveaux confondus (effectif brut).")

        def tables_sans_classement():
            """En mode interactif les deux bases sont deja imprimees plus haut par
               bloc_par_niveau ; rien a ajouter ici."""
            return

        def diagnostic_mcp():
            """Les deux questions du mode interactif, par modele :
               1. appelle-t-il les outils MCP a chaque execution ?
               2. retient-il ce que le serveur rend, ou prefere-t-il ses propres
                  identifiants ?"""
            entete("DIAGNOSTIC MCP — les deux questions, par modele",
                   ["Utilise : part des executions ayant emis au moins un appel",
                    "          d'outil (100 % par construction si le premier appel",
                    "          est impose par le harnais).",
                    "Appels/ex : nombre moyen d'appels d'outil par execution.",
                    "Rep. ancrees : la TECHNIQUE retenue a ete rendue par un outil",
                    "          du serveur — le mapping s'appuie sur le referentiel.",
                    "Prefere memoire : la technique retenue ne figure dans aucune",
                    "          reponse du serveur — le modele a repondu de memoire",
                    "          alors que les outils etaient a sa disposition."])
            print("%-24s %10s %10s %12s %14s"
                  % ("Modele", "Utilise", "Appels/ex", "Rep. ancrees",
                     "Prefere memoire"))
            par_modele = defaultdict(lambda: {"ex": 0, "avec": 0, "appels": 0,
                                              "ancrees": 0, "propres": 0, "ok": 0})
            for L in lignes:
                if not L["mcp"]:
                    continue
                A = par_modele[L["modele"]]
                A["ex"] += 1
                if L["appels"]:
                    A["avec"] += 1
                    A["appels"] += len(L["appels"])
                if L["statut"] != "ok":
                    continue
                A["ok"] += 1
                rendus = set()
                for ap2 in L["appels"]:
                    for i2 in (ap2.get("ids_retournes") or []):
                        rendus.add(str(i2).upper())
                # niveau de reference : la TECHNIQUE (les mitigations MITRE s'y
                # rattachent) ; la tactique passe souvent par la connaissance
                # generale sans appel dedie, l'exiger fausserait la question.
                tech = L["pred"]["technique"]
                if tech and tech != AUCUNE:
                    if tech in rendus:
                        A["ancrees"] += 1
                    else:
                        A["propres"] += 1
            for mo in sorted(par_modele):
                A = par_modele[mo]
                print("%-24s %10s %10.1f %12s %14s"
                      % (mo[:24], pct(A["avec"] / A["ex"] if A["ex"] else 0),
                         A["appels"] / A["ex"] if A["ex"] else 0,
                         pct(A["ancrees"] / A["ok"] if A["ok"] else 0),
                         pct(A["propres"] / A["ok"] if A["ok"] else 0)))


        def diagnostic_skill():
            empreintes = defaultdict(lambda: defaultdict(int))
            charges = defaultdict(lambda: [0, 0])
            for r in recs:
                m = r.get("meta") or {}
                sk = m.get("skill")
                if not sk:
                    continue
                mo = m.get("modele", "?")
                empreintes[mo][(sk.get("empreinte"), sk.get("mode"))] += 1
                charges[mo][1] += 1
                if sk.get("integre_au_prompt") or sk.get("charge_via_outil"):
                    charges[mo][0] += 1
            if not empreintes:
                return
            entete("SKILL — version et chargement, par modele",
                   ["empreinte : signature FNV-1a du fichier SKILL.md effectivement",
                    "          servi — rattache la campagne a une version exacte.",
                    "mode : integral (corps ajoute au prompt systeme) ou sur_demande",
                    "          (charge seulement si le modele appelle l'outil).",
                    "procedure chargee : part des executions ayant reellement vu la",
                    "          procedure."])
            for mo in sorted(empreintes):
                for (emp, mode_s), n in sorted(empreintes[mo].items()):
                    print("  %-24s empreinte %s | mode %s | %d execution(s)"
                          % (mo[:24], emp, mode_s, n))
                c, t = charges[mo]
                print("  %-24s procedure chargee : %s" % ("", pct(c / t if t else 0)))
            if len({e for mo in empreintes for (e, _) in empreintes[mo]}) > 1:
                print("  [!] PLUSIEURS EMPREINTES : les executions n'ont pas toutes vu")
                print("      la meme version du skill — campagnes a ne pas melanger.")

        if a.mode_menu:
            tables_sans_classement()
            if a.mode_menu in (2, 3, 4):
                diagnostic_mcp()
            if a.mode_menu in (3, 4):
                diagnostic_skill()
        elif a.sans_classement:
            pass          # tables par niveau deja imprimees, sans rang
        else:
            classement(False)
            classement(True)

        # --- apport du MCP : modeles evalues dans les deux conditions ---
        # La comparaison entre conditions est laissee au lecteur : les blocs par
        # niveau ci-dessus portent toutes les conditions, une ligne par niveau.

        # --- couverture ---
        couverts = set(L["echantillon"] for L in lignes)
        manquants = sorted(set(vt) - couverts)
        # --- classement fiabilite, vitesse et cout ---
        # Tri lexicographique, dans l'ordre demande :
        #   1. STABILITE decroissante — un modele qui ne rend pas deux fois la meme
        #      reponse n'est pas exploitable, quelle que soit sa vitesse ;
        #   2. LATENCE MEDIANE (p50) croissante — le temps de traitement courant ;
        #   3. COUT croissant — jetons moyens par execution.
        #   (Efficacite retiree le 26/09/2026.)
        # La sur-specification ne sert plus que de departage ultime.
        F = {}
        for cle in groupes:
            A = aux[cle]
            moy = statistics.mean(A["jet"]) if A["jet"] else 0.0
            F[cle] = {"jet": moy,
                      "p50": percentile(A["lat"], .5),
                      "p95": percentile(A["lat"], .95)}
        # tri par cout croissant : c'est l'objet du tableau
        sans_rang = a.mode_menu or a.sans_classement
        tarifs, date_tarifs, chemin_tarifs = charger_tarifs(a.tarifs)
        sans_tarif = set()

        def cout_campagne(cle):
            if not tarifs:
                return None
            t = tarifs.get(cle[0]) or tarifs.get(cle[0].split("/")[-1])
            if not t:
                sans_tarif.add(cle[0])
                return None
            return sum(cout_execution(L, t) for L in aux[cle]["fact"])
        ordre_f = sorted(F) if sans_rang else sorted(F, key=lambda c: (F[c]["jet"],
                                                                         F[c]["p50"]))
        entete("COUT — jetons, temps et argent",
               ["Jetons : moyenne par execution, cache compris et compte une fois.",
                "         Avec cache de prompt, la consommation reelle vaut",
                "         entree + cache lu + cache ecrit ; le cout en dollars se",
                "         calcule sur cette somme, pas sur la seule entree.",
                "p50 / p95 : latence mediane et 95e centile de l'appel reussi, en",
                "         millisecondes (interpolation NumPy). Le temps est un cout",
                "         d'exploitation ; le p95 est le pire cas ordinaire."]
               + (["Argent : cout de la campagne — entree, sortie et cache",
                   "         factures chacun a son tarif, sur les seules",
                   "         executions retenues. Tarifs du %s (%s) ;"
                   % (date_tarifs, chemin_tarifs.name),
                   "         « - » = tarif non renseigne pour ce modele."]
                  if tarifs else
                  ["(Pas de tarifs.json a cote du script : deposez-y les",
                   " tarifs en $/M jetons pour obtenir la colonne Argent.)"])
               + ([] if sans_rang else ["Tri : jetons croissants."]))
        print("%-4s %-24s %-15s %10s %9s %9s %10s"
              % ("Rang", "Modele", "Condition", "Jetons", "p50 ms", "p95 ms",
                 "Argent"))
        for i, cle in enumerate(ordre_f, 1):
            modele, mcp = cle
            f = F[cle]
            c = cout_campagne(cle)
            print("%-4s %-24s %-15s %10.0f %9.0f %9.0f %10s"
                  % ("-" if sans_rang else str(i), modele[:24], lib_cond(mcp),
                     f["jet"], f["p50"], f["p95"],
                     "-" if c is None else ("%.2f $" % c)))

        # --- dernier tableau : usage du serveur MCP ---------------------------
        # Ces indicateurs n'existent que pour les campagnes avec serveur ; ils ne
        # modifient aucun F1 et n'entrent dans aucun classement.
        avec_mcp = [k for k in sorted(groupes) if est_mcp(k[1])]
        if avec_mcp:
            print("\n" + "=" * 100)
            print("USAGE DU SERVEUR MCP — campagnes avec serveur uniquement")
            print("=" * 100)
            print("%-22s %6s %6s %6s %7s %7s %6s %6s %7s %7s %6s"
                  % ("Modele", "Util.", "App/ex", "Tou/ex", "Pertin.", "Hall.out",
                     "Err", "Dementi", "Ancrees", "Matrice", "AvFaux"))
            for cle in avec_mcp:
                A = aux[cle]
                mxt = A["mx_bon"] + A["mx_absent"] + A["mx_mauvais"]
                print("%-22s %6s %6.1f %6.1f %7s %7s %6d %6d %7s %7s %6d"
                      % (cle[0][:22],
                         pct(A["mcp_util"] / A["n"] if A["n"] else 0),
                         A["mcp_appels"] / max(A["n"], 1),
                         A["tours"] / max(A["n"], 1),
                         pct(A["mcp_pertinents"] / A["mcp_appels"] if A["mcp_appels"] else 0),
                         pct(A["mcp_inconnus"] / A["mcp_appels"] if A["mcp_appels"] else 0),
                         A["mcp_erreurs"], A["introuvables"],
                         pct(A["ancrees"] / A["ancrees_den"] if A["ancrees_den"] else 0),
                         pct(A["mx_bon"] / mxt if mxt else 0),
                         A["averti_puis_faux"]))
            print("Util. = executions ayant emis au moins un appel (100 % si le premier")
            print("appel est impose). App/ex, Tou/ex = appels et tours par execution.")
            print("Pertin. = appels vers un outil rendant des identifiants. Hall.out =")
            print("appels vers un outil inexistant. Err = arguments refuses. Dementi =")
            print("identifiant soumis puis declare introuvable. Ancrees = l'identifiant")
            print("retenu a ete rendu par un outil. Matrice = recherches portant la bonne")
            print("matrice. AvFaux = homonymie signalee puis identifiant hors matrice retenu.")

            for cle in avec_mcp:
                A = aux[cle]
                if A["outils"]:
                    rep = ", ".join("%s=%d" % kv for kv in
                                    sorted(A["outils"].items(), key=lambda kv: -kv[1]))
                    print("  %s — outils appeles : %s" % (cle[0][:22], rep))
                if A["avert"]:
                    print("  %s — garde-fous du serveur : %s"
                          % (cle[0][:22], ", ".join("%s=%d" % kv for kv in
                                                    sorted(A["avert"].items(),
                                                           key=lambda kv: -kv[1]))))
                if A["derive_version"]:
                    print("  [!] %s — DERIVE DE VERSION : %d reponse(s) sur une version != v%s"
                          % (cle[0][:22], A["derive_version"], a.version_attack))
                print("  %s — executions 100%% conformes en matrice : %s (%d / %d)"
                      % (cle[0][:22],
                         pct(A["mx_exec_conformes"] / A["mx_exec_den"] if A["mx_exec_den"] else 0),
                         A["mx_exec_conformes"], A["mx_exec_den"]))
                # le croisement a son propre tableau, plus bas

        # --- SERVEUR CONTRE MODELE : fournie, puis retenue ? ------------------
        # Deux lignes comparables, aux trois niveaux, en pourcentage des
        # executions. La ligne du serveur est le plafond de la condition : le
        # modele ne peut pas faire mieux que ce que les outils lui ont fourni.
        if avec_mcp:
            print("\n" + "=" * 100)
            print("SERVEUR CONTRE MODELE — la bonne reponse a-t-elle ete fournie,")
            print("                        puis retenue ?")
            print("-" * 100)
            print("  Le serveur ne rend pas une reponse mais une LISTE de candidats ;")
            print("  c'est le modele qui choisit. Les deux lignes ne mesurent donc pas")
            print("  la meme chose, et aucune precision n'est calculee pour le serveur.")
            print("  Serveur MCP : part des executions ou la bonne reponse figure parmi")
            print("       les identifiants rendus par les outils — le plafond atteignable.")
            print("  Modele : part des executions ou la reponse finale est la bonne —")
            print("       c'est le VP du tableau d'etiquetage, en pourcentage.")
            print("  Perte de selection : l'ecart entre les deux lignes, en points. La")
            print("       bonne reponse etait disponible et n'a pas ete retenue.")
            print("  Jamais fournie, faux : le serveur ne l'a pas rendue et le modele")
            print("       s'est trompe — marge de la recherche, pas de la selection.")
            print("  Cand./ex : identifiants distincts rendus par execution, en moyenne.")
            print("=" * 100)
            for cle in avec_mcp:
                A = aux[cle]; C = A["cr"]
                if not any(C[n]["n"] for n in NIVEAUX):
                    continue
                print("\n%s — %s" % (cle[0][:40], lib_cond(cle[1])))
                print("  %-24s %13s %13s %15s"
                      % ("", "Tactique", "Technique", "Sous-technique"))

                def _ligne(titre, cases):
                    print("  %-24s %13s %13s %15s"
                          % (titre, cases[0], cases[1], cases[2]))

                def _pcts(f):
                    out = []
                    for n in NIVEAUX:
                        d = C[n]
                        out.append("-" if not d["n"] else pct(f(d) / d["n"]))
                    return out

                _ligne("Serveur MCP (fournie)",
                       _pcts(lambda d: d["rendu_retenu"] + d["rendu_autre"]))
                _ligne("Modele (retenue)",
                       _pcts(lambda d: d["rendu_retenu"] + d["absent_juste"]))
                ecarts = []
                for n in NIVEAUX:
                    d = C[n]
                    ecarts.append("-" if not d["n"]
                                  else "%.1f pts" % (100.0 * d["rendu_autre"] / d["n"]))
                _ligne("Perte de selection", ecarts)
                _ligne("Jamais fournie, faux", _pcts(lambda d: d["absent_faux"]))
                _ligne("Executions comptees",
                       ["-" if not C[n]["n"] else "n = %d" % C[n]["n"] for n in NIVEAUX])
                if A["cand_den"]:
                    print("  Cand./ex : %.1f identifiants distincts par execution"
                          % (A["cand_tot"] / A["cand_den"]))
                for n in NIVEAUX:
                    if C[n]["absent_juste"]:
                        print("  [i] %s : %d execution(s) justes sans que le serveur ait"
                              " fourni l'identifiant." % (n, C[n]["absent_juste"]))

        if manquants:
            print("\n[!] %d echantillon(s) sans aucune reponse : %s"
                  % (len(manquants), ", ".join(manquants)))

        if tarifs and sans_tarif:
            print("    [i] tarif non renseigne dans %s pour : %s"
                  % (chemin_tarifs.name, ", ".join(sorted(sans_tarif))))

        # --- identifiants fautifs : hallucinations et hors matrice -------
        if hallucinations or mauvaises_matrices:
            def _resume(liste):
                par = defaultdict(Counter)
                for x in liste:
                    par[(x["modele"], x["condition"])][x["predit"]] += 1
                return par
            R_h, R_m = _resume(hallucinations), _resume(mauvaises_matrices)

            def _texte(cnt):
                # le modele figure des qu'UNE des deux colonnes est fautive ;
                # l'autre porte alors la marque explicite « aucune »
                if not cnt:
                    return ["aucune"]
                morceaux = ["%s x%d" % (i, n) if n > 1 else i
                            for i, n in sorted(cnt.items())]
                lignes_t, cour = [], ""
                for m in morceaux:
                    if cour and len(cour) + len(m) + 2 > 34:
                        lignes_t.append(cour + ",")
                        cour = m
                    else:
                        cour = (cour + ", " + m) if cour else m
                lignes_t.append(cour)
                return lignes_t

            entete("IDENTIFIANTS FAUTIFS — hallucinations et hors matrice",
                   DEF_CONDITION
                   + ["Hallucination : l'identifiant n'existe dans aucune version",
                      "          du referentiel — le modele l'a fabrique.",
                      "Hors matrice : l'identifiant existe, mais dans l'autre",
                      "          matrice que celle prescrite par l'echantillon.",
                      "Seuls les modeles concernes figurent ; xN = occurrences",
                      "          sur l'ensemble des executions de l'evaluation.",
                      "* : sous-technique inventee sur un echantillon terminal,",
                      "          hors F1 sous-technique et hors colonne H des",
                      "          tableaux d'etiquetage (comptee en sur-specification)."])
            print("%-24s %-15s %-36s %s"
                  % ("Modele", "Condition", "Hallucinations", "Hors matrice"))
            for cle in sorted(set(R_h) | set(R_m)):
                col_h = _texte(R_h.get(cle, {}))
                col_m = _texte(R_m.get(cle, {}))
                for i in range(max(len(col_h), len(col_m))):
                    print("%-24s %-15s %-36s %s"
                          % (cle[0][:24] if i == 0 else "",
                             lib_cond(cle[1]) if i == 0 else "",
                             col_h[i] if i < len(col_h) else "",
                             col_m[i] if i < len(col_m) else ""))

        # --- tableau comparatif : une ligne par evaluation ---------------
        # Recapitulatif transversal : tout ce qui sert a departager, sur une
        # seule ligne par couple (modele, condition). Les tableaux precedents
        # gardent le detail ; celui-ci sert a la comparaison.
        if len(groupes) > 1:
            entete("TABLEAU COMPARATIF — une ligne par evaluation",
                   DEF_CONDITION
                   + ["F1 strict : par niveau, les identifiants obsoletes",
                      "          comptant comme des erreurs.",
                      "Jetons : moyenne par execution (entree + sortie telles que",
                      "          l'API les rapporte).",
                      "p50 : latence mediane de l'appel reussi, en millisecondes.",
                      "Stab. : part des echantillons dont les executions repetees",
                      "          rendent le meme triplet.",
                      "Sous-sp. : technique rendue sans sa sous-technique la ou",
                      "          la verite de terrain en attend une.",
                      "Sur-sp. : sous-technique proposee la ou aucune n'est",
                      "          attendue.",
                      "Obsol. / Abst. : part des affirmations obsoletes, et part",
                      "          des reponses sans identifiant, tous niveaux."])
            print("%-24s %-15s %-23s %8s %8s %7s %8s %8s %7s %7s"
                  % ("", "", "         F1 strict", "", "", "", "", "", "", ""))
            print("%-24s %-15s %7s %7s %7s %8s %8s %7s %8s %8s %7s %7s"
                  % ("Modele", "Condition", "Tact.", "Tech.", "S-t.",
                     "Jetons", "p50 ms", "Stab.", "Sous-sp.", "Sur-sp.",
                     "Obsol.", "Abst."))
            for cle in sorted(groupes):
                modele, cond = cle
                A = aux[cle]
                ms = [groupes[cle][n].metriques(False) for n in NIVEAUX]
                aff = sum(x["affirmations"] for x in ms)
                tot = sum(x["n"] for x in ms)
                obs = sum(groupes[cle][n].c[OBS] for n in NIVEAUX)
                abst = sum(x["abstentions"] for x in ms)
                print("%-24s %-15s %7.3f %7.3f %7.3f %8.0f %8.0f %7s %8s %8s %7s %7s"
                      % (modele[:24], lib_cond(cond),
                         ms[0]["f1"], ms[1]["f1"], ms[2]["f1"],
                         statistics.mean(A["jet"]) if A["jet"] else 0.0,
                         percentile(A["lat"], .5),
                         pct(stabilite(cle)),
                         pct(A["n1"] / A["n"] if A["n"] else 0),
                         pct(A["sur_spec"] / A["term_den"] if A["term_den"] else 0),
                         pct(obs / aff if aff else 0),
                         pct(abst / tot if tot else 0)))


        # --- classeur xlsx : toutes les etapes en un fichier ---------------
        def exporter_classeur():
            """Un classeur, une feuille par tableau, une couleur par feuille.
               Les comptes sont des valeurs ; precision, rappel, F1 et taux
               sont des FORMULES qui les referencent."""
            try:
                from openpyxl import Workbook
            except ImportError:
                print("[!] openpyxl n'est pas installe : le classeur xlsx ne")
                print("    peut pas etre produit. Les memes donnees restent")
                print("    disponibles dans les trois CSV et le rapport texte.")
                print("    Pour le classeur : pip install openpyxl")
                return None
            wb = Workbook()
            wb.remove(wb.active)
            cles = sorted(groupes)
            P0 = "0.0%"
            F3 = "0.000"

            # 1. Synthese (comparatif)
            lg = []
            for cle in cles:
                modele, cond = cle
                A = aux[cle]
                ms = [groupes[cle][n].metriques(False) for n in NIVEAUX]
                aff = sum(x["affirmations"] for x in ms)
                tot = sum(x["n"] for x in ms)
                obs = sum(groupes[cle][n].c[OBS] for n in NIVEAUX)
                lg.append([modele, lib_cond(cond),
                           ms[0]["f1"], ms[1]["f1"], ms[2]["f1"],
                           statistics.mean(A["jet"]) if A["jet"] else 0.0,
                           percentile(A["lat"], .5),
                           stabilite(cle),
                           (A["n1"] / A["n"]) if A["n"] else 0.0,
                           (A["sur_spec"] / A["term_den"]) if A["term_den"] else 0.0,
                           (obs / aff) if aff else 0.0,
                           (sum(x["abstentions"] for x in ms) / tot) if tot else 0.0])
            _ecrire_feuille(
                wb.create_sheet("Synthese"), COULEURS_FEUILLES["Synthese"],
                "SYNTHESE COMPARATIVE — une ligne par evaluation",
                ["F1 strict : les identifiants obsoletes comptent comme des erreurs.",
                 "Jetons : moyenne par execution telle que l'API la rapporte ; avec",
                 "cache de prompt, la consommation reelle vaut entree + cache lu +",
                 "cache ecrit (voir la feuille Cout).",
                 "Stabilite : part des echantillons dont les executions repetees",
                 "rendent le meme triplet."],
                ["Modele", "Condition", "F1 tactique", "F1 technique",
                 "F1 sous-technique", "Jetons/exec", "p50 (ms)", "Stabilite",
                 "Sous-specif.", "Sur-specif.", "Obsoletes", "Abstentions"],
                lg, {2: F3, 3: F3, 4: F3, 5: "0", 6: "0", 7: P0, 8: P0, 9: P0,
                     10: P0, 11: P0})

            # 2. Etiquetage — comptes bruts + controle d'integrite en formule
            lg = []
            for cle in cles:
                modele, cond = cle
                for n in NIVEAUX:
                    c = groupes[cle][n]
                    lg.append([modele, lib_cond(cond), LIB_NIVEAU[n], c.n,
                               c.c[VP], c.c[FP], c.c[HALL],
                               c.drapeaux["ancienne_version"],
                               c.drapeaux["identifiant_deprecie"],
                               c.c[OBS], c.c[FN],
                               c.drapeaux["mauvaise_matrice"], None])
            ws = wb.create_sheet("Etiquetage")
            entete_l = _ecrire_feuille(
                ws, COULEURS_FEUILLES["Etiquetage"],
                "ETIQUETAGE — une etiquette par niveau et par execution",
                ["Cinq categories, une par prediction : N = VP + FP + H + O + A",
                 "(l'egalite de la methodologie, verifiee par la formule Integrite).",
                 "VP juste ; FP faux ; H inexistant dans toute version ; O revoque",
                 "avec remplacant ; A abstention.",
                 "Les identifiants PERIMES — deprecies de la version figee, ou",
                 "d'une version anterieure — sont DES FP : les deux colonnes",
                 "« dont... » les detaillent, a titre indicatif, sans entrer",
                 "dans la somme. MM (hors matrice) : sous-ensemble des FP."],
                ["Modele", "Condition", "Niveau", "N", "VP", "FP",
                 "H (inexistant)", "dont anciennes versions", "dont deprecies",
                 "O (obsolete)", "A (abstention)", "MM (hors matrice)",
                 "Integrite N"],
                lg, cle_groupe=(0, 1))
            for i in range(len(lg)):
                r = entete_l + 1 + i
                ws.cell(row=r, column=13,
                        # N = VP + FP + H + O + A (methodologie) : les
                        # colonnes « dont » (H, I) sont hors somme, deja
                        # contenues dans FP ; G=H, J=O, K=A.
                        value=('=IF(D%d=E%d+F%d+G%d+J%d+K%d,"oui",'
                               'D%d&" attendu")' % (r, r, r, r, r, r, r)))

            # 3 & 4. Bases stricte et tolerante — F1 en formules
            for tol, nom in ((False, "Base stricte"), (True, "Base tolerante")):
                lg = []
                for cle in cles:
                    modele, cond = cle
                    for n in NIVEAUX:
                        m = groupes[cle][n].metriques(tol)
                        lg.append([modele, lib_cond(cond), LIB_NIVEAU[n],
                                   m["n"], m["vp"], m["fp"], m["fn"],
                                   None, None, None, stabilite(cle)])
                ws = wb.create_sheet(nom)
                el = _ecrire_feuille(
                    ws, COULEURS_FEUILLES[nom],
                    "QUALITE DU MAPPING — %s" % nom.upper(),
                    ["Base stricte : les obsoletes comptent comme des erreurs."
                     if not tol else
                     "Base tolerante : les obsoletes sont credites, leur remplacant",
                     "officiel etant la bonne reponse.",
                     "Precision = VP/(VP+FP) ; Rappel = VP/(VP+FN) ;",
                     "F1 = moyenne harmonique des deux. Les trois sont des formules.",
                     "Une prediction fausse compte FP *et* FN.",
                     "Stabilite : identique dans les deux bases, elle ne depend pas",
                     "de la verite de terrain."],
                    ["Modele", "Condition", "Niveau", "N", "VP", "FP", "FN",
                     "Precision", "Rappel", "F1", "Stabilite"],
                    lg, {3: "0", 4: "0", 5: "0", 6: "0", 7: "0.000",
                         8: "0.000", 9: "0.000", 10: "0.0%"}, cle_groupe=(0, 1))
                for i in range(len(lg)):
                    r = el + 1 + i
                    ws.cell(row=r, column=8, value="=IFERROR(E%d/(E%d+F%d),0)" % (r, r, r))
                    ws.cell(row=r, column=9, value="=IFERROR(E%d/(E%d+G%d),0)" % (r, r, r))
                    ws.cell(row=r, column=10,
                            value="=IFERROR(2*H%d*I%d/(H%d+I%d),0)" % (r, r, r, r))

            # 5. Attributs de diagnostic
            lg = []
            for cle in cles:
                modele, cond = cle
                A = aux[cle]
                lg.append([modele, lib_cond(cond),
                           sum(groupes[cle][n].drapeaux["mauvaise_matrice"]
                               for n in NIVEAUX),
                           groupes[cle]["sous_technique"].drapeaux["sous_technique_niee"],
                           groupes[cle]["tactique"].drapeaux["scission_defense_evasion"],
                           A["format"] + A["erreurs_api"],
                           (A["sur_spec"] / A["term_den"]) if A["term_den"] else 0.0,
                           (A["n1"] / A["n"]) if A["n"] else 0.0,
                           (A["n2_num"] / A["n2_den"]) if A["n2_den"] else 0.0])
            _ecrire_feuille(
                wb.create_sheet("Attributs"), COULEURS_FEUILLES["Attributs"],
                "ATTRIBUTS DE DIAGNOSTIC",
                ["s-t niee : repond « aucune » alors qu'une sous-technique existe.",
                 "scission v19 : TA0005 propose la ou TA0112 est attendu.",
                 "format : reponses rejetees imputables au modele",
                 "         (format, JSON invalide, reponse vide).",
                 "Sur-specification : sous-technique proposee la ou aucune n'est",
                 "attendue. N1, N2 : sous-specification."],
                ["Modele", "Condition", "Hors matrice", "s-t niee",
                 "Scission v19", "Format rejete", "Sur-specif.", "N1", "N2"],
                lg, {6: P0, 7: P0, 8: P0})

            # 6. Par matrice
            lg = []
            for (mo, co, ma) in sorted(groupes_m):
                g = groupes_m[(mo, co, ma)]
                lg.append([mo, lib_cond(co), ma,
                           g["tactique"].n,
                           g["tactique"].metriques(False)["f1"],
                           g["technique"].metriques(False)["f1"],
                           # CORRECTIF 2026-09 : pas de F1 s-t ICS
                           None if ma == "ics" else g["sous_technique"].metriques(False)["f1"],
                           None if ma == "ics" else g["sous_technique"].n])
            if lg:
                _ecrire_feuille(
                    wb.create_sheet("Par matrice"), COULEURS_FEUILLES["Par matrice"],
                    "VENTILATION PAR MATRICE — F1 stricts",
                    ["Les memes executions, reparties selon la matrice prescrite",
                     "par l'echantillon : enterprise (zone TI), ics (zone TO)."],
                    ["Modele", "Condition", "Matrice", "N", "F1 tactique",
                     "F1 technique", "F1 sous-technique", "N sous-technique"],
                    lg, {4: F3, 5: F3, 6: F3})

            # 7. Cout
            lg = []
            for cle in cles:
                modele, cond = cle
                A = aux[cle]
                moy = statistics.mean(A["jet"]) if A["jet"] else 0.0
                lg.append([modele, lib_cond(cond), moy,
                           percentile(A["lat"], .5), percentile(A["lat"], .95)])
            _ecrire_feuille(
                wb.create_sheet("Cout"), COULEURS_FEUILLES["Cout"],
                "COUT — jetons et temps",
                ["Jetons : moyenne par execution, cache compris et compte une fois.",
                 "Le cache lu et ecrit y est inclus quel que soit le fournisseur :",
                 "une campagne cachee et une campagne non cachee sont comparables."],
                ["Modele", "Condition", "Jetons/exec", "p50 (ms)", "p95 (ms)"],
                lg, {2: "0", 3: "0", 4: "0"})

            # 8. Usage MCP — memes definitions que le tableau imprime
            lg = []
            for cle in cles:
                if not est_mcp(cle[1]):
                    continue
                A = aux[cle]
                if not A["n"]:
                    continue
                mxt = A["mx_bon"] + A["mx_absent"] + A["mx_mauvais"]
                lg.append([cle[0], lib_cond(cle[1]), A["n"],
                           A["mcp_util"] / A["n"],
                           A["mcp_appels"] / A["n"],
                           A["tours"] / A["n"],
                           (A["mcp_pertinents"] / A["mcp_appels"]) if A["mcp_appels"] else 0.0,
                           (A["mcp_inconnus"] / A["mcp_appels"]) if A["mcp_appels"] else 0.0,
                           A["mcp_erreurs"], A["introuvables"],
                           (A["ancrees"] / A["ancrees_den"]) if A["ancrees_den"] else 0.0,
                           (A["mx_bon"] / mxt) if mxt else 0.0,
                           A["averti_puis_faux"]])
            if lg:
                _ecrire_feuille(
                    wb.create_sheet("Usage MCP"), COULEURS_FEUILLES["Usage MCP"],
                    "USAGE DU SERVEUR MCP",
                    ["Utilise : part des executions ayant emis au moins un appel.",
                     "Pertinents : appels vers un outil rendant des identifiants.",
                     "Outil inexistant : appels vers un outil que le serveur n'expose",
                     "pas. Dementis : identifiant soumis puis declare introuvable.",
                     "Ancrees : la technique retenue figure dans une reponse du",
                     "serveur. Conformite matrice : identifiants rendus appartenant",
                     "a la matrice prescrite. Averti puis faux : le serveur a signale",
                     "une homonymie et le modele a tout de meme retenu l'autre",
                     "matrice."],
                    ["Modele", "Condition", "Executions", "Utilise",
                     "Appels/exec", "Tours/exec", "Appels pertinents",
                     "Outil inexistant", "Erreurs", "Dementis",
                     "Reponses ancrees", "Conformite matrice", "Averti puis faux"],
                    lg, {3: P0, 4: "0.0", 5: "0.0", 6: P0, 7: P0,
                         8: "0", 9: "0", 10: P0, 11: P0, 12: "0"})

            # 9. Hallucinations — le detail, par modele
            lg = []
            for h in sorted(hallucinations,
                            key=lambda x: (x["modele"], str(x["condition"]),
                                           x["predit"], x["echantillon"], x["run"])):
                lg.append([h["modele"], lib_cond(h["condition"]), h["predit"],
                           LIB_NIVEAU[h["niveau"]], h["matrice"],
                           h["echantillon"], h["run"], h["attendu"] or "-"])
            _ecrire_feuille(
                wb.create_sheet("Hallucinations"), COULEURS_FEUILLES["Hallucinations"],
                "HALLUCINATIONS — identifiants inexistants, une ligne par occurrence",
                ["Un identifiant est compte ici s'il n'existe dans AUCUNE version",
                 "du referentiel : ni vivant, ni revoque, ni deprecie, ni dans une",
                 "version anterieure. Ce n'est ni un identifiant perime (feuille",
                 "Etiquetage, colonne F), ni un identifiant pris dans l'autre",
                 "matrice (colonne MM) : c'est une invention.",
                 "Feuille vide = aucune hallucination sur le perimetre evalue."],
                ["Modele", "Condition", "Identifiant", "Niveau", "Matrice",
                 "Echantillon", "Execution", "Attendu"],
                lg, cle_groupe=(0, 1))

            # 10. Detail par execution — une ligne par execution et par
            # niveau : la seule donnee que les CSV portaient et que le
            # classeur n'avait pas. Sa presence ici rend les CSV optionnels.
            lg = []
            for L in sorted(lignes, key=lambda x: (x["modele"], str(x["condition"]),
                                                   x["echantillon"], x["run"])):
                for n in NIVEAUX:
                    e = L["et"][n]
                    if n == "sous_technique" and not e["applicable"]:
                        continue
                    lg.append([L["modele"], lib_cond(L["condition"]),
                               L["echantillon"], L["run"], L["matrice"],
                               L["statut"], LIB_NIVEAU[n],
                               L["gt"][n] or "-", e["predit"] or "(vide)",
                               e["etiquette"],
                               "oui" if e.get("mauvaise_matrice") else "",
                               "oui" if e.get("ancienne_version") else "",
                               "oui" if e.get("identifiant_deprecie") else ""])
            _ecrire_feuille(
                wb.create_sheet("Detail par execution"),
                COULEURS_FEUILLES.get("Detail", "4A4A4A"),
                "DETAIL PAR EXECUTION — une ligne par execution et par niveau",
                ["La granularite la plus fine : ce que la verite de terrain",
                 "attendait, ce que le modele a repondu, l'etiquette qui en",
                 "decoule et les marques qui la qualifient.",
                 "Les lignes des autres feuilles sont des agregats de celle-ci.",
                 "Filtrer sur « Etiquette » pour retrouver n'importe quel cas."],
                ["Modele", "Condition", "Echantillon", "Execution", "Matrice",
                 "Statut", "Niveau", "Attendu", "Predit", "Etiquette",
                 "Hors matrice", "Ancienne version", "Deprecie"],
                lg, cle_groupe=(0, 1, 2))

            nom = getattr(a, "slug_rapport", None) \
                or ("__".join(a.libelles_eval) if getattr(a, "libelles_eval", None)
                    else "evaluation")
            chemin = preparer_sortie() / ("metriques_%s.xlsx" % nom[:120])
            wb.save(chemin)
            print("\n[*] classeur : %s" % chemin)
            print("    feuilles : %s" % ", ".join(w.title for w in wb.worksheets))
            return chemin

        exporter_classeur()

        # --- CSV ---
        if True:
            d = preparer_sortie()
            chemin_csv = d / ("metriques_%s.csv"
                              % getattr(a, "slug_rapport", "rapport"))
            f_csv = open(chemin_csv, "w", encoding="utf-8", newline="")
            with _SectionCSV(f_csv, "METRIQUES PAR MODELE") as f:
                f.write("modele,mcp,matrice,niveau,n,vp,fp,fn,abstentions,taux_abstention,"
                        "hallucinations,anciennes_versions,obsoletes,mauvaise_matrice,"
                        "precision,rappel,f1_strict,f1_tolerant\n")
                for (mo, mc, ma) in sorted(groupes_m):
                    for n in NIVEAUX:
                        if ma == "ics" and n == "sous_technique":
                            continue  # CORRECTIF 2026-09 : non rapporte
                        c = groupes_m[(mo, mc, ma)][n]
                        s, tol = c.metriques(False), c.metriques(True)
                        f.write("%s,%s,%s,%s,%d,%d,%d,%d,%d,%.4f,%d,%d,%d,%d,%.4f,%.4f,%.4f,%.4f\n"
                                % (mo, lib_cond(mc), ma, n, s["n"], s["vp"],
                                   s["fp"], s["fn"], s["abstentions"],
                                   s["abstentions"] / s["n"] if s["n"] else 0.0,
                                   c.c[HALL],
                                   c.drapeaux["ancienne_version"]
                                   + c.drapeaux["identifiant_deprecie"],
                                   c.c[OBS],
                                   c.drapeaux["mauvaise_matrice"],
                                   s["precision"], s["rappel"], s["f1"], tol["f1"]))
            with _SectionCSV(f_csv, "ETIQUETAGE DETAILLE") as f:
                f.write("echantillon,modele,run,zone,matrice,statut,"
                        "tactique_attendue,tactique_predite,etiquette_tactique,"
                        "technique_attendue,technique_predite,etiquette_technique,"
                        "sous_technique_attendue,sous_technique_predite,etiquette_sous_technique,"
                        "mcp_a_fourni_tactique,mcp_a_fourni_technique,"
                        "mcp_a_fourni_sous_technique\n")
                for L in sorted(lignes, key=lambda x: (x["modele"], x["echantillon"], x["run"])):
                    f.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n"
                            % (L["echantillon"], L["modele"], L["run"], L["zone"], L["matrice"],
                               L["statut"],
                               L["gt"]["tactique"], L["pred"]["tactique"],
                               L["et"]["tactique"]["etiquette"],
                               L["gt"]["technique"], L["pred"]["technique"],
                               L["et"]["technique"]["etiquette"],
                               L["gt"]["sous_technique"], L["pred"]["sous_technique"],
                               L["et"]["sous_technique"]["etiquette"],
                               L["mcp_rendu"]["tactique"],
                               L["mcp_rendu"]["technique"],
                               L["mcp_rendu"]["sous_technique"]))
            with _SectionCSV(f_csv, "USAGE MCP") as f:
                f.write("modele,mcp,executions,executions_avec_appel,taux_utilisation,appels_total,"
                        "appels_par_execution,outils_inconnus,taux_hallucination_outil,appels_en_erreur,"
                        "taux_appels_pertinents,taux_reponses_ancrees,tours_par_execution,"
                        "derive_version,matrice_correcte,matrice_omise,matrice_erronee,"
                        "taux_matrice_correcte,executions_matrice_conformes,dementis,"
                        "averti_puis_faux,"
                        + ",".join("cr_%s_%s" % (n, k) for n in NIVEAUX
                                   for k in ("n", "fournie_retenue", "fournie_autre",
                                             "non_fournie_juste", "non_fournie_faux"))
                        + ",candidats_par_execution,repartition_outils\n")
                for cle in sorted(aux):
                    A = aux[cle]
                    rep = ";".join("%s:%d" % kv for kv in sorted(A["outils"].items()))
                    mxt = A["mx_bon"] + A["mx_absent"] + A["mx_mauvais"]
                    f.write("%s,%s,%d,%d,%.4f,%d,%.2f,%d,%.4f,%d,%.4f,%.4f,%.2f,%d,"
                            "%d,%d,%d,%.4f,%d,%d,%d,%s,%.2f,%s\n"
                            % (cle[0], lib_cond(cle[1]), A["n"], A["mcp_util"],
                               A["mcp_util"] / A["n"] if A["n"] else 0, A["mcp_appels"],
                               A["mcp_appels"] / max(A["n"], 1), A["mcp_inconnus"],
                               A["mcp_inconnus"] / A["mcp_appels"] if A["mcp_appels"] else 0,
                               A["mcp_erreurs"],
                               A["mcp_pertinents"] / A["mcp_appels"] if A["mcp_appels"] else 0,
                               A["ancrees"] / A["ancrees_den"] if A["ancrees_den"] else 0,
                               A["tours"] / max(A["n"], 1), A["derive_version"],
                               A["mx_bon"], A["mx_absent"], A["mx_mauvais"],
                               A["mx_bon"] / mxt if mxt else 0,
                               A["mx_exec_conformes"], A["introuvables"],
                               A["averti_puis_faux"],
                               ",".join("%d" % A["cr"][n][k] for n in NIVEAUX
                                        for k in ("n", "rendu_retenu", "rendu_autre",
                                                  "absent_juste", "absent_faux")),
                               A["cand_tot"] / A["cand_den"] if A["cand_den"] else 0,
                               rep))
            f_csv.close()
            print("\n[*] donnees CSV : %s" % chemin_csv)
            print("    trois sections dans le meme fichier — METRIQUES PAR")
            print("    MODELE, ETIQUETAGE DETAILLE, USAGE MCP — chacune ouverte")
            print("    par une ligne ### et fermee par une ligne vide.")

        return hallucinations

    # Le rapport donne des taux ; le detail donne les CAS. Le script ne quitte
    # pas avant que l'utilisateur le demande, et propose une derniere fois
    # d'ajouter une evaluation tant que le plafond n'est pas atteint.
    import io as _io

    def rapport_trace(recs):
        """Banniere titree, rapport capture, fichier rapport_<nom>.txt."""
        titre, slug = titre_rapport(recs, getattr(a, "libelles_eval", None))
        a.slug_rapport = slug
        print("\n" + "#" * 78)
        print("#  RAPPORT — %s" % titre[:70])
        print("#" * 78)
        tampon = _io.StringIO()
        vrai = sys.stdout
        sys.stdout = _Tee(vrai, tampon)
        try:
            h = rapport(recs)
        finally:
            sys.stdout = vrai
        d = preparer_sortie()
        try:
            chemin = d / ("rapport_%s.txt" % slug)
            chemin.write_text("RAPPORT — %s\n%s\n\n" % (titre, "=" * 78)
                              + tampon.getvalue(), encoding="utf-8")
            print("\n[*] rapport texte : %s" % chemin)
        except OSError as e:
            print("\n[!] rapport texte non sauvegarde : %s" % e)
        return h

    hallucinations = rapport_trace(recs)
    if a.mode_menu:
        while True:
            menu_details(hallucinations)
            print("\n" + "=" * 62)
            print("  1. Nouvelle evaluation — repartir de zero")
            if a.n_evaluations < MAX_EVALUATIONS:
                print("  2. Ajouter une evaluation a la comparaison courante "
                      "(%d/%d)" % (a.n_evaluations, MAX_EVALUATIONS))
            print("  0. Fermer")
            print("=" * 62)
            choix = demander("Choix", "0").strip()
            if choix == "1":
                recs = a.nouvelle_comparaison()
                hallucinations = rapport_trace(recs)
            elif choix == "2" and a.n_evaluations < MAX_EVALUATIONS:
                if a.ajouter_evaluation(recs):
                    recapituler(recs)
                    hallucinations = rapport_trace(recs)
            else:
                break
    elif a.details_hallucinations:
        detail_hallucinations(hallucinations)



if __name__ == "__main__":
    main()
