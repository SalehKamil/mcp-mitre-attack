#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""
preparer_dataset.py — Construction du jeu de donnees d'evaluation
==================================================================
Produit, conformement a la methodologie d'evaluation :

  1. Les fichiers d'echantillons S###.jsonl : la telemetrie brute decoupee par
     attaque, SANS aucune etiquette MITRE (la reponse ne doit pas figurer dans
     la question).
  2. Le fichier verite_terrain.jsonl : un triplet attendu par echantillon,
     et rien d'autre.

CHAMPS DE LA VERITE DE TERRAIN (exactement ceux-ci, ni plus ni moins)
  echantillon              identifiant S###
  fichier                  nom du fichier d'echantillon correspondant
  zone                     TI | TO
  source                   sysmon | auditd | zeek
  matrice                  enterprise | ics
  tactique_attendue        {"id": "TA####",    "nom": "..."}  (UNE seule)
  technique_attendue       {"id": "T####",     "nom": "..."}  (technique parente)
  sous_technique_attendue  {"id": "T####.###", "nom": "..."}
                           ou {"id": "aucune", "nom": "aucune"}

Chaque niveau porte son identifiant ET son nom officiel dans le meme objet.

REGLES APPLIQUEES
  - Version d'ATT&CK FIGEE (defaut 19.2) : le referentiel ne bouge pas d'une
    execution a l'autre. Un identifiant revoque dans cette version est corrige
    vers son remplacant et signale dans le rapport.
  - La sous-technique est deduite de l'identifiant lui-meme (presence d'un
    point), jamais d'un champ texte annexe : cela corrige les traces ou le
    champ "sub_technique" est incoherent avec l'identifiant.
  - UNE seule tactique attendue par echantillon. Elle provient du champ
    "tactic" de la trace ; a defaut, elle est deduite du referentiel uniquement
    si la technique ne possede qu'une seule tactique officielle ; sinon le
    script marque A_COMPLETER et sort en erreur. Il n'invente jamais
    d'intention (voir TACTIQUES_MANUELLES en tete de script).
  - Controle de fuite : les cles auditd de laboratoire (key="T_xxx") sont
    neutralisees, puis le script verifie qu'aucun identifiant MITRE ne subsiste
    dans les echantillons produits.

ARBORESCENCE DU PROJET
  Le script vit dans dataset/ et ecrit a cote de lui. Aucun chemin n'est code
  en dur, aucun nom d'utilisateur n'apparait nulle part :

      <racine depot>/.github/skills/mitre-mapping/SKILL.md   <- skill publie
      <racine depot>/cas_d_usage/workflow_evaluation/...      <- ce projet

      <racine>/workflow_eval_multi_llm.json
      <racine>/resultats_tous_modeles.jsonl     <- ecrit par le workflow n8n
      <racine>/dataset/preparer_dataset.py      <- ce script
      <racine>/dataset/verite_terrain.jsonl
      <racine>/dataset/echantillons/S###.jsonl

  Le workflow resout <racine> soit par la variable d'environnement EVAL_RACINE,
  soit, a defaut, par le dossier depuis lequel n8n a ete lance. Le plus simple
  est donc d'ouvrir PowerShell en administrateur, de se placer a la racine du
  projet et de lancer n8n depuis la. Le script rappelle la marche a suivre a la
  fin de chaque execution reussie.

USAGE (une execution par dossier de zone ; la numerotation S### se poursuit et
le fichier de verite de terrain est partage) :
  python preparer_dataset.py --dossier dataset_ti_linux
  python preparer_dataset.py --dossier dataset_ti_windows_dc01
  python preparer_dataset.py --dossier dataset_to
"""
import argparse, glob, json, os, pathlib, re, shutil, sys, tempfile, urllib.request
from datetime import datetime, timezone

VERSION_ATTACK_DEFAUT = "19.2"
AUCUNE = "aucune"
DOSSIER_ECHANTILLONS = "echantillons"   # sous-dossier des S###.jsonl
FICHIER_RESULTATS = "resultats_tous_modeles.jsonl"  # ecrit par le workflow n8n
A_COMPLETER = "A_COMPLETER"
DOSSIER_RESULTATS = "resultats"                     # cote n8n
DOSSIER_SKILLS = "skills"                           # cote n8n
NOM_SKILL = "mitre-attack-mapping"        # nom du dossier attendu par le workflow
FICHIER_SKILL = "SKILL.md"
# Emplacements possibles du skill dans le depot, relatifs a sa racine ;
# le premier qui existe est retenu.
SOURCES_SKILL = (".github/skills/mitre-mapping",
                 ".github/skills/mitre-attack-mapping")
NOM_ADC = "application_default_credentials.json"    # identifiants gcloud


def paire(identifiant, nom):
    """Chaque niveau de la verite de terrain porte son identifiant et son nom."""
    return {"id": identifiant, "nom": nom}


def paire_a_completer():
    return paire(A_COMPLETER, A_COMPLETER)

# zone interne -> (zone publiee, matrice)
ZONES = {"IT_linux": ("TI", "enterprise"),
         "IT_windows": ("TI", "enterprise"),
         "OT": ("TO", "ics")}
BASE_STIX = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
FICHIER_MATRICE = {"enterprise": "enterprise-attack", "ics": "ics-attack"}

# IP considerees comme "attaquant" cote TO (le reste du trafic .95.x = procede)
ATTAQUANTS = {"192.168.90.6", "192.168.95.5"}

# ---------------------------------------------------------------------------
# Tactiques a renseigner A LA MAIN lorsque la technique en admet plusieurs et
# que la trace ne precise pas laquelle. Cle = identifiant tel qu'il figure dans
# la trace. Valeur = nom court de la tactique (ex. "impair-process-control").
# Tant qu'une entree necessaire est absente, le script sort en erreur.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# CORRECTIF 2026-09 — sous-techniques a trancher A LA MAIN.
# Quand la trace donne une technique PARENTE qui possede des sous-techniques
# dans la version figee, « aucune » n'est plus deduite automatiquement :
# calculer_metriques.py lit « aucune » comme « la technique n'en a pas », et
# compterait la sous-technique exacte en sur-specification (cas de S000 :
# balayage du port 502 = T0846.001 Port Scan, attendu « aucune »).
# Cle = identifiant tel qu'il figure dans la trace. Valeur = la sous-technique
# retenue, ou "aucune" si AUCUNE ne correspond au log (decision humaine,
# justifiee en commentaire).
# ---------------------------------------------------------------------------
SOUS_TECHNIQUES_MANUELLES = {
    # S000 : une source unique sonde le port 502 sur une plage d'adresses.
    "T0846": "T0846.001",
    # S029 : pare-feu hote Linux ; les sous-techniques visent le cloud (.001),
    # un equipement reseau (.002) ou le pare-feu Windows (.003).
    "T1686": "aucune",
    # S033 : ipconfig ; ni .001 (connexion Internet) ni .002 (Wi-Fi).
    "T1016": "aucune",
}

TACTIQUES_MANUELLES = {
    # T1692.001 est multi-tactique (Impair Process Control + Evasion). Le scenario
    # du README est une commande d'ecriture hostile : l'intention dominante est le
    # sabotage du pilotage, d'ou impair-process-control.
    "T1692.001": "impair-process-control",
}


# ---- 1. Referentiel MITRE : telechargement / cache / index ----------------
def charger_base_mitre(matrice, version, cache_dir):
    nom = "%s-%s.json" % (FICHIER_MATRICE[matrice], version)
    url = "%s/%s/%s" % (BASE_STIX, FICHIER_MATRICE[matrice], nom)
    tmp = tempfile.gettempdir()
    for p in [pathlib.Path(cache_dir) / nom, pathlib.Path(tmp) / nom]:
        if p.exists():
            print("[1] Referentiel %s v%s (cache) : %s" % (matrice, version, p))
            return json.load(open(p, encoding="utf-8-sig"))
    print("[1] Telechargement du referentiel %s v%s : %s" % (matrice, version, url))
    req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
    try:
        data = urllib.request.urlopen(req, timeout=300).read()
    except Exception as e:
        sys.exit("[!] Telechargement impossible (%s).\n"
                 "    Verifier que la version '%s' existe pour la matrice '%s',\n"
                 "    ou deposer le fichier %s dans --cache." % (e, version, matrice, nom))
    for d in (pathlib.Path(cache_dir), pathlib.Path(tmp)):
        try:
            d.mkdir(parents=True, exist_ok=True)
            (d / nom).write_bytes(data)
            break
        except OSError:
            continue
    return json.loads(data)


def indexer(bundle, version_demandee):
    """Renvoie (ref, revoques, tactiques).
       ref[ID]          = {"nom": ..., "tactiques": [noms courts]}
       revoques[ID]     = ID remplacant ou None
       tactiques[court] = {"id": "TA####", "nom": "..."}"""
    o = bundle["objects"]
    version = next((x.get("x_mitre_version") for x in o
                    if x.get("type") == "x-mitre-collection"), "?")
    if str(version) != str(version_demandee):
        print("    [!] version chargee v%s != version demandee v%s "
              "- la verite de terrain doit rester figee." % (version, version_demandee))
    tactiques = {}
    for x in o:
        if x.get("type") == "x-mitre-tactic":
            e = [r for r in x.get("external_references", [])
                 if r.get("source_name") == "mitre-attack"]
            tactiques[x["x_mitre_shortname"]] = {
                "id": e[0]["external_id"] if e else None, "nom": x["name"]}
    stix2attack = {}
    for x in o:
        if x.get("type") == "attack-pattern":
            e = [r for r in x.get("external_references", [])
                 if r.get("source_name") == "mitre-attack"]
            if e:
                stix2attack[x["id"]] = e[0]["external_id"]
    remplace = {x["source_ref"]: x["target_ref"] for x in o
                if x.get("type") == "relationship"
                and x.get("relationship_type") == "revoked-by"}
    ref, revoques = {}, {}
    for x in o:
        if x.get("type") != "attack-pattern":
            continue
        e = [r for r in x.get("external_references", [])
             if r.get("source_name") == "mitre-attack"]
        if not e:
            continue
        aid = e[0]["external_id"]
        if x.get("revoked"):
            cible = remplace.get(x["id"])
            revoques[aid] = stix2attack.get(cible) if cible else None
        elif not x.get("x_mitre_deprecated"):
            ref[aid] = {"nom": x["name"],
                        "tactiques": [p["phase_name"]
                                      for p in x.get("kill_chain_phases", [])]}
    print("    v%s : %d techniques en vigueur, %d revoquees"
          % (version, len(ref), len(revoques)))
    return ref, revoques, tactiques


# ---- horodatage ISO <-> epoch UTC ----------------------------------------
def iso2ep(s):
    s = s.strip(); tz = "+00:00"
    if s.endswith("Z"):
        s = s[:-1]
    else:
        m = re.search(r"([+-]\d{2}:\d{2})$", s)
        if m:
            tz, s = m.group(1), s[:m.start()]
    if "." in s:
        h, f = s.split(".", 1); s = "%s.%s" % (h, f[:6])
    return datetime.fromisoformat(s + tz).timestamp()


def ep2iso(ts):
    return (datetime.fromtimestamp(ts, timezone.utc)
            .isoformat(timespec="microseconds").replace("+00:00", "Z"))


# ---- parseurs de telemetrie ----------------------------------------------
def lire_zeek(chemins):
    evts = []
    for motif in chemins:
        for ch in sorted(glob.glob(motif)) or [motif]:
            if not os.path.exists(ch):
                continue
            for l in open(ch, encoding="utf-8"):
                l = l.strip()
                if not l:
                    continue
                d = json.loads(l)
                if "ts" not in d:
                    continue
                evts.append({"ts": float(d["ts"]),
                             "fichier": d.get("_log") or os.path.basename(ch),
                             "orig": d.get("id.orig_h"), "contenu": d})
    return evts


# Les cles auditd de laboratoire (-k T_execution, T_privesc, ...) enoncent la
# tactique attendue : elles sont neutralisees avant ecriture des echantillons.
_CLE_LABO = re.compile(r'key="T_[^"]*"')


def neutraliser_cle(lignes):
    return [_CLE_LABO.sub('key="audit"', l) for l in lignes]


_TS = re.compile(r"msg=audit\((\d+\.\d+):(\d+)\)")


def lire_auditd(chemins):
    evts = []
    for ch in chemins:
        if not os.path.exists(ch):
            continue
        bloc = []

        def vider(b):
            lg = [x for x in b if x.startswith("type=")]
            if not lg:
                return
            m = _TS.search(" ".join(lg))
            if not m:
                return
            evts.append({"ts": float(m.group(1)), "fichier": "auditd",
                         "orig": None, "contenu": neutraliser_cle(lg)})

        for l in open(ch, encoding="utf-8", errors="replace"):
            l = l.rstrip("\n")
            if l.strip() == "----":
                vider(bloc); bloc = []
            else:
                bloc.append(l)
        vider(bloc)
    return evts


def lire_sysmon(chemins):
    evts = []
    for ch in chemins:
        if not os.path.exists(ch):
            continue
        lignes = None
        for enc in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
            try:
                with open(ch, encoding=enc) as f:
                    lignes = f.readlines()
                break
            except UnicodeDecodeError:
                continue
        if lignes is None:
            continue
        for l in lignes:
            l = l.strip()
            if not l:
                continue
            try:
                d = json.loads(l)
            except Exception:
                continue
            tc = d.get("TimeCreated")
            if not tc:
                continue
            evts.append({"ts": iso2ep(tc), "fichier": "sysmon",
                         "orig": d.get("MachineName"), "contenu": d})
    return evts


PARSEURS = {"zeek": lire_zeek, "auditd": lire_auditd, "sysmon": lire_sysmon}


# ---- trace : chargement et resolution du triplet attendu ------------------
def charger_trace(chemin, source):
    fen, ignorees = [], 0
    for l in open(chemin, encoding="utf-8-sig"):
        l = l.strip()
        if not l:
            continue
        try:
            r = json.loads(l)
        except json.JSONDecodeError:
            ignorees += 1
            continue
        if "technique" not in r or "t0" not in r or "t1" not in r:
            ignorees += 1
            continue
        fen.append({"id_trace": r["technique"], "tac_trace": r.get("tactic"),
                    "t0": iso2ep(r["t0"]), "t1": iso2ep(r["t1"]),
                    "source": source})
    if ignorees:
        print("    [!] %d ligne(s) de trace IGNOREE(S) dans %s (champs technique/t0/t1 "
              "manquants ou JSON illisible) : autant d'echantillons en moins !"
              % (ignorees, chemin))
    return fen


def normaliser_tactique(v):
    """'Defense Impairment', 'defense-impairment', 'Defense_Impairment' -> forme courte."""
    return str(v or "").strip().lower().replace(" ", "-").replace("_", "-")


def resoudre(fen, ref, revoques, tactiques):
    """Remplit technique_attendue, sous_technique_attendue, tactique_attendue.
       Renvoie la liste des anomalies bloquantes."""
    anomalies = []
    for w in fen:
        brut = w["id_trace"]
        tid = brut
        w["correction"] = None
        w["technique_attendue"] = paire_a_completer()
        w["sous_technique_attendue"] = paire_a_completer()
        w["tactique_attendue"] = paire_a_completer()

        # a) identifiant valide dans la version figee ?
        if tid not in ref:
            remplacant = revoques.get(tid)
            if remplacant and remplacant in ref:
                w["correction"] = "%s revoque -> %s" % (tid, remplacant)
                tid = remplacant
            else:
                anomalies.append("%s : introuvable dans la version figee" % brut)
                continue

        # b) technique parente et sous-technique deduites de l'identifiant
        parent = tid.split(".")[0]
        if parent not in ref:
            anomalies.append("%s : technique parente %s absente du referentiel"
                             % (tid, parent))
            continue
        w["technique_attendue"] = paire(parent, ref[parent]["nom"])
        enfants = sorted(x for x in ref if x.startswith(parent + "."))
        if "." in tid:
            w["sous_technique_attendue"] = paire(tid, ref[tid]["nom"])
        elif not enfants:
            w["sous_technique_attendue"] = paire(AUCUNE, AUCUNE)
        elif brut in SOUS_TECHNIQUES_MANUELLES:
            choix = SOUS_TECHNIQUES_MANUELLES[brut]
            if choix == AUCUNE:
                w["sous_technique_attendue"] = paire(AUCUNE, AUCUNE)
            elif choix in enfants:
                w["sous_technique_attendue"] = paire(choix, ref[choix]["nom"])
            else:
                anomalies.append("%s : sous-technique manuelle '%s' invalide, "
                                 "attendu parmi %s ou 'aucune'" % (brut, choix, enfants))
                continue
        else:
            # CORRECTIF 2026-09 : plus de « aucune » implicite
            anomalies.append("%s : technique parente avec sous-techniques %s ; "
                             "renseigner SOUS_TECHNIQUES_MANUELLES['%s'] "
                             "(une sous-technique ou 'aucune')" % (brut, enfants, brut))
            continue
        officielles = ref[parent]["tactiques"]

        # c) tactique attendue : trace > table manuelle > deduction non ambigue
        court = normaliser_tactique(w["tac_trace"])
        if court and court in officielles:
            choisie = court
        elif court:
            anomalies.append("%s : tactique '%s' de la trace absente des tactiques "
                             "officielles %s" % (tid, w["tac_trace"], officielles))
            continue
        elif TACTIQUES_MANUELLES.get(brut):
            choisie = normaliser_tactique(TACTIQUES_MANUELLES[brut])
            if choisie not in officielles:
                anomalies.append("%s : tactique manuelle '%s' invalide, attendu parmi %s"
                                 % (tid, choisie, officielles))
                continue
        elif len(officielles) == 1:
            choisie = officielles[0]
        else:
            anomalies.append("%s : tactique ambigue, choisir parmi %s puis renseigner "
                             "TACTIQUES_MANUELLES['%s']" % (brut, officielles, brut))
            continue
        ident = tactiques.get(choisie, {}).get("id")
        if not ident:
            anomalies.append("%s : tactique '%s' sans identifiant TA####" % (tid, choisie))
            continue
        w["tactique_attendue"] = paire(ident, tactiques[choisie]["nom"])
    return anomalies


# ---- decoupe temporelle, plafond reseau, numerotation --------------------
def echantillon_uniforme(evts, cap):
    if cap <= 0 or len(evts) <= cap:
        return evts
    pas = len(evts) / cap
    return [evts[int(i * pas)] for i in range(cap)]


def decouper(fen, evts, cap_att, cap_proc, pad=0.0):
    for w in fen:
        w["evts"] = []
    orphelins = []
    for ev in sorted(evts, key=lambda e: e["ts"]):
        c = [w for w in fen if w["t0"] - pad <= ev["ts"] <= w["t1"] + pad]
        if not c:
            orphelins.append(ev)
        else:
            ch = min(c, key=lambda w: (abs(ev["ts"] - (w["t0"] + w["t1"]) / 2.0),
                                       w["t1"] - w["t0"]))
            ch["evts"].append(ev)
    for w in fen:
        if w["source"] == "zeek":
            conns = [e for e in w["evts"] if e["fichier"] == "conn.log"]
            devid = [e for e in w["evts"]
                     if e["fichier"] == "modbus_read_device_identification.log"]
            att = [e for e in w["evts"] if e["fichier"] == "modbus.log"
                   and e["orig"] in ATTAQUANTS]
            proc = [e for e in w["evts"] if e["fichier"] == "modbus.log"
                    and e["orig"] not in ATTAQUANTS]
            gardes = (conns + devid + echantillon_uniforme(att, cap_att)
                      + echantillon_uniforme(proc, cap_proc))
        else:
            gardes = w["evts"]
        gardes.sort(key=lambda e: e["ts"])
        w["evts"] = gardes
        for k, ev in enumerate(gardes, 1):
            ev["id_journal"] = "%s-%04d" % (w["echantillon"], k)
    orphelins.sort(key=lambda e: e["ts"])
    return orphelins


# ---- detection de zone et continuite de la numerotation ------------------
def detecter_zone(trouver):
    if trouver("trace_attaques_ti_linux.jsonl", "trace_attaques_linux_it.jsonl"):
        return "IT_linux"
    if trouver("trace_attaques_dc01.jsonl", "trace_attaques_ws01.jsonl"):
        return "IT_windows"
    if trouver("trace_attaques_zeek.jsonl", "trace_attaques_audit.jsonl"):
        return "OT"
    return None


def calculer_debut(d_ech, chemin_verite, cles_zone):
    """cles_zone : couples (zone, source) produits par cette execution.
       Renvoie (numero de depart, lignes des autres zones a conserver).
       Le numero de depart est choisi pour NE JAMAIS chevaucher les numeros deja
       occupes par les zones conservees : les identifiants restent uniques sur
       l'ensemble du corpus, quel que soit l'ordre de generation des zones."""
    conserver, occupes = [], set()
    if chemin_verite.exists():
        for l in open(chemin_verite, encoding="utf-8"):
            l = l.rstrip("\n")
            if not l.strip():
                continue
            try:
                r = json.loads(l)
            except Exception:
                conserver.append(l)
                continue
            if (r.get("zone"), r.get("source")) in cles_zone:
                continue  # sera reecrit par l'execution courante
            conserver.append(l)
            m = re.match(r"S(\d+)$", str(r.get("echantillon", "")))
            if m:
                occupes.add(int(m.group(1)))
    # numeros occupes aussi par des fichiers d'echantillons d'autres zones
    for p in d_ech.glob("S*.jsonl"):
        m = re.match(r"S(\d+)$", p.stem)
        if m:
            occupes.add(int(m.group(1)))
    debut = (max(occupes) + 1) if occupes else 0
    if occupes:
        print("[*] %d numero(s) deja occupe(s) par d'autres zones -> "
              "numerotation de cette zone a partir de S%03d" % (len(occupes), debut))
    else:
        print("[*] aucun echantillon existant -> numerotation a partir de S000")
    return debut, conserver


# ---- controle de fuite dans les echantillons produits --------------------
# Sans frontiere de mot : un identifiant colle a un nom de fichier
# (ex. "atomic_T1059.004.sh") est une fuite au meme titre qu'un identifiant isole.
_ID_MITRE = re.compile(r"(?<!\d)TA\d{4}(?!\d)|(?<!\d)T\d{4}(?:\.\d{3})?(?!\d)")


def controler_fuite(fichiers):
    fuites = []
    for f in fichiers:
        for n, l in enumerate(open(f, encoding="utf-8"), 1):
            trouves = set(_ID_MITRE.findall(l))
            if trouves:
                fuites.append((f.name, n, sorted(trouves)))
                break
    return fuites


# ---- racine du depot et empreinte du skill --------------------------------
def trouver_racine_projet():
    """Racine du depot (mitre-attack-framework), sans aucun chemin en dur.

       Le script vit dans <racine>/cas_d_usage/workflow_evaluation/dataset/ :
       on REMONTE depuis son propre emplacement jusqu'au premier dossier qui
       contient A LA FOIS .github et cas_d_usage — les deux vivent sur la meme
       racine, c'est le marqueur le plus sur, valable quel que soit le disque,
       le nom du clone ou l'utilisateur. Repli : un dossier nomme
       mitre-attack-framework. Renvoie None si rien n'est trouve."""
    ici = pathlib.Path(__file__).resolve()
    for p in ici.parents:
        if (p / ".github").is_dir() and (p / "cas_d_usage").is_dir():
            return p
    for p in ici.parents:
        if p.name == "mitre-attack-framework":
            return p
    return None


def empreinte_fnv1a64(octets):
    """Empreinte FNV-1a 64 bits, IDENTIQUE a celle que le workflow n8n calcule
       dans « Preparer le skill » (meme algorithme, meme parcours par points de
       code) : la valeur affichee ici doit se retrouver telle quelle dans
       meta.skill.empreinte de chaque ligne de resultats. Ce n'est pas un
       usage cryptographique, seulement un rattachement de version."""
    h = 0xcbf29ce484222325
    for ch in octets.decode("utf-8"):
        cp = ord(ch)
        while cp > 0:
            h = ((h ^ (cp & 0xff)) * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
            cp >>= 8
    return "%016x" % h


def localiser_skill(option):
    """Dossier source du skill. Ordre : --skill, puis SOURCES_SKILL sous la
       racine du depot. Renvoie (dossier, message d'erreur eventuel)."""
    if option:
        p = pathlib.Path(option).expanduser()
        if p.is_file() and p.name == FICHIER_SKILL:
            p = p.parent
        if not (p / FICHIER_SKILL).is_file():
            return None, "--skill : %s introuvable sous %s" % (FICHIER_SKILL, p)
        return p, None
    depot = trouver_racine_projet()
    if depot is None:
        return None, ("racine du depot introuvable en remontant depuis %s\n"
                      "              (marqueurs cherches : .github et cas_d_usage "
                      "cote a cote,\n               ou un dossier nomme "
                      "mitre-attack-framework)" % pathlib.Path(__file__).resolve().parent)
    essais = []
    for rel in SOURCES_SKILL:
        d = depot / pathlib.Path(rel)
        essais.append(str(d))
        if (d / FICHIER_SKILL).is_file():
            return d, None
    return None, ("skill introuvable — %s attendu dans l'un de :\n              %s"
                  % (FICHIER_SKILL, "\n              ".join(essais)))


def publier_skill(racine_n8n, option):
    """Copie le skill du depot vers <n8n>/%s/%s/, l'emplacement exact que lit
       le workflow (cle skill_chemin du noeud Configuration). Tout le dossier
       source est copie (SKILL.md et ses eventuelles ressources), apres purge
       de la destination pour ne pas melanger deux versions.
       Renvoie (chemin du SKILL.md publie, empreinte) ou (None, None).""" % (
        DOSSIER_SKILLS, NOM_SKILL)
    src, err = localiser_skill(option)
    if src is None:
        print("  skill             : NON copie — %s" % err)
        print("                      Le workflow de phase 3 s'arretera au demarrage ;")
        print("                      deposer le skill, ou passer skill_actif a false")
        print("                      dans sa Configuration, ou indiquer --skill.")
        return None, None
    dest = racine_n8n / DOSSIER_SKILLS / NOM_SKILL
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest)
    fichiers = sorted(x for x in dest.rglob("*") if x.is_file())
    publie = dest / FICHIER_SKILL
    emp = empreinte_fnv1a64(publie.read_bytes())
    print("  skill             : %s  (%d fichier(s), source %s)"
          % (publie, len(fichiers), src))
    print("                      empreinte fnv1a64 %s — a retrouver dans"
          " meta.skill.empreinte" % emp)
    return publie, emp


# ---- publication vers le dossier de fichiers de n8n ----------------------
def dossier_n8n(option):
    """Racine des fichiers de n8n, sans aucun chemin en dur.
       Ordre : --n8n-files, N8N_FILES_DIR, <repertoire personnel>/.n8n-files."""
    if option:
        return pathlib.Path(option).expanduser()
    env = os.environ.get("N8N_FILES_DIR")
    if env:
        return pathlib.Path(env).expanduser()
    return pathlib.Path.home() / ".n8n-files"


def trouver_adc(option):
    """Localise application_default_credentials.json sans chemin en dur.
       Ordre : --adc, GOOGLE_APPLICATION_CREDENTIALS, %APPDATA%/gcloud (Windows),
       ~/.config/gcloud (Linux, macOS), ~/AppData/Roaming/gcloud (repli)."""
    if option:
        p = pathlib.Path(option).expanduser()
        return p if p.exists() else None
    env = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if env and pathlib.Path(env).expanduser().exists():
        return pathlib.Path(env).expanduser()
    maison = pathlib.Path.home()
    candidats = []
    appdata = os.environ.get("APPDATA")
    if appdata:
        candidats.append(pathlib.Path(appdata) / "gcloud" / NOM_ADC)
    candidats += [maison / ".config" / "gcloud" / NOM_ADC,
                  maison / "AppData" / "Roaming" / "gcloud" / NOM_ADC]
    for c in candidats:
        if c.exists():
            return c
    return None


def publier(d_ech, racine, adc, skill_option=None):
    """Prepare le dossier de fichiers de n8n :

         <racine>/application_default_credentials.json   identifiants gcloud
         <racine>/dataset/S###.jsonl                     copie des echantillons
         <racine>/resultats/                             ecrit par le workflow
         <racine>/skills/mitre-attack-mapping/SKILL.md   procedure de mapping
                                                         (workflow de phase 3)

       La VERITE DE TERRAIN N'EST PAS PUBLIEE : les reponses attendues restent
       dans le dossier du projet et ne circulent jamais dans le pipeline.
       Renvoie (dossier_dataset, dossier_resultats, adc_publie)."""
    d_data = racine / "dataset"
    d_res = racine / DOSSIER_RESULTATS
    for d in (racine, d_data, d_res):
        d.mkdir(parents=True, exist_ok=True)
    # purge des echantillons publies precedemment : sinon un ancien S0xx
    # subsisterait alors qu'il ne fait plus partie du corpus courant.
    anciens = sorted(d_data.glob("S*.jsonl"))
    for f in anciens:
        f.unlink()
    copies = 0
    for f in sorted(d_ech.glob("S*.jsonl")):
        shutil.copy2(f, d_data / f.name)
        copies += 1
    adc_publie = None
    if adc:
        adc_publie = racine / NOM_ADC
        shutil.copy2(adc, adc_publie)
    print("\n[publication] %d echantillon(s) copie(s) (%d ancien(s) retire(s))"
          % (copies, len(anciens)))
    print("  echantillons      : %s" % d_data)
    print("  resultats         : %s" % d_res)
    if adc_publie:
        print("  gcloud            : %s" % adc_publie)
    else:
        print("  gcloud            : NON copie, fichier introuvable — le lancer une")
        print("                      fois avec : gcloud auth application-default login")
        print("                      ou indiquer le chemin avec --adc")
    skill_publie, _ = publier_skill(racine, skill_option)
    print("  verite de terrain : NON publiee (reste dans %s)" % d_ech.parent)
    return d_data, d_res, adc_publie, skill_publie


# ---- aide au lancement du workflow n8n -----------------------------------
def afficher_lancement(racine, d_ech):
    """Aucun chemin absolu dans le workflow : il resout la racine par
       N8N_FILES_DIR, sinon <repertoire personnel>/.n8n-files."""
    u = lambda x: str(x).replace("\\", "/")
    print("\n=== LANCEMENT DU WORKFLOW ===")
    print("Le workflow lit  : <racine>/dataset/S*.jsonl")
    print("           ecrit : <racine>/%s/%s" % (DOSSIER_RESULTATS, FICHIER_RESULTATS))
    print("           gcloud: <racine>/%s" % NOM_ADC)
    print("           skill : <racine>/%s/%s/%s   (workflow de phase 3)"
          % (DOSSIER_SKILLS, NOM_SKILL, FICHIER_SKILL))
    print("\nracine resolue sur cette machine : %s" % u(racine))
    print("Le workflow la retrouve seul (N8N_FILES_DIR, sinon ~/.n8n-files).")
    print("Pour la fixer explicitement avant de lancer n8n :")
    print("    PowerShell : $env:N8N_FILES_DIR = \"%s\"" % u(racine))
    print("    bash       : export N8N_FILES_DIR=\"%s\"" % u(racine))
    print("    puis       : npx n8n start")
    print("\nLa verite de terrain reste hors du pipeline : %s"
          % u(d_ech.parent / "verite_terrain.jsonl"))


# ---- pipeline ------------------------------------------------------------
def construire_parseur():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dossier", default=".", help="dossier des logs et traces (recursif)")
    ap.add_argument("--sortie", default=None, help="dossier de sortie (defaut : celui du script)")
    ap.add_argument("--cache", default=tempfile.gettempdir(), help="cache du referentiel STIX")
    ap.add_argument("--verite", default="verite_terrain.jsonl",
                    help="fichier de verite de terrain partage (dans --sortie)")
    ap.add_argument("--echantillons", default=DOSSIER_ECHANTILLONS,
                    help="sous-dossier des S###.jsonl (defaut : %s)" % DOSSIER_ECHANTILLONS)
    ap.add_argument("--version-attack", default=VERSION_ATTACK_DEFAUT,
                    help="version figee du referentiel (defaut %s)" % VERSION_ATTACK_DEFAUT)
    ap.add_argument("--cap-attaquant", type=int, default=300,
                    help="[TO] max lignes attaquant par echantillon reseau (0 = illimite)")
    ap.add_argument("--cap-procede", type=int, default=40,
                    help="[TO] max lignes procede par echantillon reseau (0 = illimite)")
    ap.add_argument("--zone", choices=list(ZONES), default=None, help="forcer la zone")
    ap.add_argument("--n8n-files", default=None,
                    help="racine des fichiers de n8n (defaut : $N8N_FILES_DIR "
                         "sinon <repertoire personnel>/.n8n-files)")
    ap.add_argument("--skill", default=None,
                    help="dossier (ou SKILL.md) du skill de mapping a publier "
                         "(defaut : <racine du depot>/.github/skills/mitre-mapping, "
                         "racine trouvee en remontant depuis ce script)")
    ap.add_argument("--adc", default=None,
                    help="fichier gcloud application_default_credentials.json "
                         "(defaut : detecte automatiquement)")
    ap.add_argument("--pas-de-publication", action="store_true",
                    help="ne rien copier vers le dossier de fichiers de n8n")
    ap.add_argument("--attendu", type=int, default=42,
                    help="nombre total d'echantillons attendu dans le corpus")
    ap.add_argument("--toutes-zones", action="store_true",
                    help="genere les trois zones en une seule commande, dans "
                         "l'ordre TO -> TI-linux -> TI-windows, avec une "
                         "numerotation S### continue repartant de S000, et "
                         "publie une seule fois a la fin. --dossier designe "
                         "alors le dossier PARENT contenant dataset_to, "
                         "dataset_ti_linux et dataset_ti_windows.")
    ap.add_argument("--dossiers-zones", default="dataset_to,dataset_ti_linux,"
                    "dataset_ti_windows",
                    help="[--toutes-zones] noms des sous-dossiers de zone, dans "
                         "l'ordre, separes par des virgules")
    return ap


def executer_zone(a):
    if a.sortie is None:
        a.sortie = os.path.dirname(os.path.abspath(__file__)) or "."
    D = a.dossier

    def trouver(*noms):
        for n in noms:
            hits = sorted(glob.glob(os.path.join(D, "**", n), recursive=True))
            if hits:
                return hits
        return []

    zone_interne = a.zone or detecter_zone(trouver)
    if zone_interne is None:
        sys.exit("[!] Aucune trace reconnue sous %s - attendu :\n"
                 "      IT_linux   : trace_attaques_ti_linux.jsonl\n"
                 "      IT_windows : trace_attaques_dc01.jsonl\n"
                 "      OT         : trace_attaques_zeek.jsonl et/ou trace_attaques_audit.jsonl"
                 % os.path.abspath(D))
    zone, matrice = ZONES[zone_interne]
    print("[*] Zone %s -> zone=%s, matrice=%s" % (zone_interne, zone, matrice))
    ref, revoques, tactiques = indexer(
        charger_base_mitre(matrice, a.version_attack, a.cache), a.version_attack)

    # --- localiser les fichiers de la zone ---
    print("\n[*] Localisation sous %s" % os.path.abspath(D))
    sources = []
    if zone_interne == "OT":
        zeek_journaux = []
        for n in ["modbus.log", "conn.log", "modbus_read_device_identification.log"]:
            hits = trouver(n)
            print("    [%s] %-48s -> %s" % ("ok" if hits else "--", n,
                                            hits[0] if hits else "introuvable"))
            if hits:
                zeek_journaux.append(hits[0])
        audit_p = (trouver("audit_to.log", "audit_ot.log", "audit.log", "*audit*.log") or [None])[0]
        tr_net = (trouver("trace_attaques_zeek.jsonl") or [None])[0]
        tr_host = (trouver("trace_attaques_audit.jsonl") or [None])[0]
        for lib, val in (("audit hote PLC", audit_p), ("trace reseau", tr_net),
                         ("trace hote", tr_host)):
            print("    [%s] %-48s -> %s" % ("ok" if val else "--", lib, val or "introuvable"))
        if tr_net and zeek_journaux:
            sources.append({"source": "zeek", "trace": tr_net, "journaux": zeek_journaux})
        elif tr_net and not zeek_journaux:
            print("\n    [!] TRACE RESEAU PRESENTE MAIS JOURNAUX ZEEK INTROUVABLES :")
            print("        les echantillons reseau de la zone TO ne seront PAS generes.")
        if tr_host and audit_p:
            sources.append({"source": "auditd", "trace": tr_host, "journaux": [audit_p]})
        elif tr_host and not audit_p:
            print("\n    [!] TRACE HOTE PRESENTE MAIS JOURNAL D'AUDIT INTROUVABLE")
            print("        (audit_to.log, audit_ot.log, audit.log ou *audit*.log attendu) :")
            print("        les echantillons hote PLC ne seront PAS generes.")
            candidats = sorted(glob.glob(os.path.join(D, "**", "*.log"),
                                         recursive=True))[:12]
            if candidats:
                print("        Fichiers .log visibles sous le dossier :")
                for c in candidats:
                    print("          - %s" % c)
                print("        Renommer le journal d'audit de l'hote en audit_ot.log,")
                print("        ou le deplacer dans ce dossier, puis relancer.")
    elif zone_interne == "IT_linux":
        audit_p = (trouver("audit_capture.log", "audit_ti.log", "audit.log") or [None])[0]
        tr = (trouver("trace_attaques_ti_linux.jsonl",
                      "trace_attaques_linux_it.jsonl") or [None])[0]
        for lib, val in (("telemetrie auditd", audit_p), ("trace des attaques", tr)):
            print("    [%s] %-48s -> %s" % ("ok" if val else "--", lib, val or "introuvable"))
        if tr and audit_p:
            sources.append({"source": "auditd", "trace": tr, "journaux": [audit_p]})
    else:
        telem = (trouver("telemetrie_dc01.jsonl", "telemetrie_ws01.jsonl",
                         "sysmon.jsonl") or [None])[0]
        tr = (trouver("trace_attaques_dc01.jsonl", "trace_attaques_ws01.jsonl") or [None])[0]
        for lib, val in (("telemetrie Sysmon", telem), ("trace des attaques", tr)):
            print("    [%s] %-48s -> %s" % ("ok" if val else "--", lib, val or "introuvable"))
        if tr and telem:
            sources.append({"source": "sysmon", "trace": tr, "journaux": [telem]})
    if not sources:
        sys.exit("\n[!] Fichiers de la zone introuvables - verifier --dossier.")

    # --- charger les traces et resoudre le triplet attendu ---
    toutes, anomalies = [], []
    for s in sources:
        f = charger_trace(s["trace"], s["source"])
        anomalies += resoudre(f, ref, revoques, tactiques)
        s["fen"] = f
        toutes += f
    toutes.sort(key=lambda w: w["t0"])

    # --- numerotation et continuite ---
    out = pathlib.Path(a.sortie)
    out.mkdir(parents=True, exist_ok=True)
    # la verite de terrain reste dans --sortie ; les echantillons vont dans un
    # sous-dossier dedie, pour ne pas melanger le corpus et les fichiers du projet.
    fv = out / a.verite if not os.path.isabs(a.verite) else pathlib.Path(a.verite)
    d_ech = (pathlib.Path(a.echantillons) if os.path.isabs(a.echantillons)
             else out / a.echantillons)
    d_ech.mkdir(parents=True, exist_ok=True)

    # Le dossier des echantillons est aligne sur la verite de terrain AVANT de
    # numeroter. ATTENTION a la PORTEE : cette execution ne traite QUE la zone
    # courante, elle ne doit donc toucher qu'aux echantillons de cette zone.
    #
    # CORRECTIF enchainement multi-zones : la version precedente supprimait du
    # dossier tout S###.jsonl absent de la verite de terrain. En enchainant les
    # zones (TO, puis TI-linux, puis TI-windows) avec une verite de terrain
    # d'abord vide ou partielle, elle effacait a chaque passage les echantillons
    # deja produits par les zones precedentes -> « dossier et verite desynchro-
    # nises ». On restreint desormais l'alignement aux couples (zone, source)
    # REECRITS par cette execution, exactement comme calculer_debut() plus bas ;
    # les echantillons des autres zones sont laisses intacts.
    cles_zone = set([(zone, s["source"]) for s in sources])
    a_ma_zone = set()   # S### appartenant a une zone reecrite ici
    conserves = set()   # S### appartenant a une autre zone (a preserver)
    if fv.exists():
        for l in open(fv, encoding="utf-8"):
            if not l.strip():
                continue
            try:
                r = json.loads(l)
            except Exception:
                continue
            (a_ma_zone if (r.get("zone"), r.get("source")) in cles_zone
             else conserves).add(r.get("echantillon"))
    deplaces, retires = 0, 0
    for f in sorted(out.glob("S*.jsonl")):          # ancienne disposition, a plat
        if f.stem in conserves:
            continue                                # echantillon d'une autre zone
        if f.stem in a_ma_zone:
            shutil.move(str(f), str(d_ech / f.name)); deplaces += 1
        else:
            f.unlink(); retires += 1                # residu de MA zone uniquement
    for f in sorted(d_ech.glob("S*.jsonl")):
        if f.stem in conserves:
            continue                                # ne jamais purger une autre zone
        if f.stem not in a_ma_zone:
            f.unlink(); retires += 1
    if deplaces:
        print("[*] %d echantillon(s) deplace(s) vers %s/" % (deplaces, d_ech))
    if retires:
        print("[*] %d echantillon(s) residuel(s) de cette zone retire(s) "
              "(absents de la verite de terrain)" % retires)

    debut, conserver = calculer_debut(d_ech, fv, cles_zone)
    for i, w in enumerate(toutes):
        w["echantillon"] = "S%03d" % (debut + i)

    # --- decouper la telemetrie ---
    for s in sources:
        evts = PARSEURS[s["source"]](s["journaux"])
        s["brut"] = len(evts)
        pad = 1.0 if s["source"] == "sysmon" else 0.0
        s["orphelins"] = decouper(s["fen"], evts, a.cap_attaquant, a.cap_procede, pad=pad)

    # --- ecrire les echantillons (SANS etiquette) ---
    ecrits = []
    for w in toutes:
        fe = d_ech / ("%s.jsonl" % w["echantillon"])
        with open(fe, "w", encoding="utf-8") as jour:
            for ev in w["evts"]:
                # zone et matrice sont du CONTEXTE, pas une etiquette : un
                # analyste sait toujours s'il regarde de l'OT ou de l'IT. Les
                # porter ici evite de publier la verite de terrain cote n8n.
                jour.write(json.dumps({"id_journal": ev["id_journal"],
                                       "zone": zone,
                                       "matrice": matrice,
                                       "source": w["source"],
                                       "horodatage": ep2iso(ev["ts"]),
                                       "contenu": ev["contenu"]},
                                      ensure_ascii=False) + "\n")
        ecrits.append(fe)

    # --- ecrire la verite de terrain (8 champs, rien d'autre) ---
    with open(fv, "w", encoding="utf-8") as vt:
        for l in conserver:
            vt.write(l + "\n")
        for w in toutes:
            vt.write(json.dumps({
                "echantillon": w["echantillon"],
                "fichier": "%s.jsonl" % w["echantillon"],
                "zone": zone,
                "source": w["source"],
                "matrice": matrice,
                "tactique_attendue": w["tactique_attendue"],
                "technique_attendue": w["technique_attendue"],
                "sous_technique_attendue": w["sous_technique_attendue"],
            }, ensure_ascii=False) + "\n")

    # --- rapport ---
    print("\n=== RAPPORT %s - referentiel %s v%s ==="
          % (zone_interne, matrice, a.version_attack))
    for s in sources:
        print("[%-7s] %d attaques | %d lignes brutes | %d hors fenetre"
              % (s["source"], len(s["fen"]), s["brut"], len(s["orphelins"])))
    print("\n%-5s %-7s %-11s %-11s %-15s %6s  %s"
          % ("ECH", "SOURCE", "TACTIQUE", "TECHNIQUE", "SOUS-TECHNIQUE", "#LOGS", "NOM"))
    vides = []
    for w in toutes:
        n = len(w["evts"])
        if n == 0:
            vides.append(w["echantillon"])
        st = w["sous_technique_attendue"]
        nom = st["nom"] if st["id"] not in (AUCUNE, A_COMPLETER) else w["technique_attendue"]["nom"]
        print("%-5s %-7s %-11s %-11s %-15s %6d  %s"
              % (w["echantillon"], w["source"], w["tactique_attendue"]["id"],
                 w["technique_attendue"]["id"], st["id"], n, nom))

    corriges = [w for w in toutes if w["correction"]]
    if corriges:
        print("\n[i] %d identifiant(s) revoque(s) corrige(s) vers la version figee :"
              % len(corriges))
        for w in corriges:
            print("      %s : %s" % (w["echantillon"], w["correction"]))
    if vides:
        print("\n[!] %d echantillon(s) sans aucune ligne de journal : %s"
              % (len(vides), ", ".join(vides)))

    fuites = controler_fuite(ecrits)
    if fuites:
        print("\n[!] FUITE : %d echantillon(s) contiennent un identifiant MITRE "
              "(la reponse figure dans la question) :" % len(fuites))
        for nom, ligne, ids in fuites:
            print("      %s ligne %d : %s" % (nom, ligne, ", ".join(ids)))
    else:
        print("\n[ok] Controle de fuite : aucun identifiant MITRE dans les echantillons.")

    # --- bilan global sur le corpus complet ---
    lignes = [json.loads(l) for l in open(fv, encoding="utf-8") if l.strip()]
    avec = sum(1 for r in lignes
               if r["sous_technique_attendue"]["id"] not in (AUCUNE, A_COMPLETER))
    sans = sum(1 for r in lignes if r["sous_technique_attendue"]["id"] == AUCUNE)
    incomplets = [r["echantillon"] for r in lignes
                  if A_COMPLETER in (r["tactique_attendue"]["id"],
                                     r["technique_attendue"]["id"],
                                     r["sous_technique_attendue"]["id"])]
    noms = [r["echantillon"] for r in lignes]
    doublons = sorted(set([x for x in noms if noms.count(x) > 1]))

    print("\n-> verite de terrain : %s" % fv)
    print("-> echantillons      : %s/  (%d fichiers ecrits pour cette zone)"
          % (d_ech, len(toutes)))
    print("-> corpus complet    : %d echantillons (%d avec sous-technique, %d sans)"
          % (len(lignes), avec, sans))
    repartition = {}
    for r in lignes:
        cle = "%s/%s" % (r.get("zone"), r.get("source"))
        repartition[cle] = repartition.get(cle, 0) + 1
    print("   repartition       : " + "  ".join("%s=%d" % kv
          for kv in sorted(repartition.items())))
    if len(lignes) != a.attendu:
        print("   [i] %d/%d - lancer les autres zones pour completer le corpus."
              % (len(lignes), a.attendu))
    if doublons:
        print("   [!] identifiants d'echantillon en double : %s" % ", ".join(doublons))
    presents = set(f.stem for f in d_ech.glob("S*.jsonl"))
    declares = set(noms)
    ecarts = sorted((presents - declares) | (declares - presents))
    if ecarts:
        print("   [!] dossier et verite de terrain desynchronises : %s"
              % ", ".join(ecarts))
    else:
        print("   [ok] %d fichier(s) dans %s/ correspondent exactement a la verite "
              "de terrain." % (len(presents), d_ech.name))

    if anomalies:
        print("\n[!] %d anomalie(s) bloquante(s) - la verite de terrain est INCOMPLETE :"
              % len(anomalies))
        for x in anomalies:
            print("      - %s" % x)
        print("\n    Les lignes concernees portent la valeur %s." % A_COMPLETER)
        print("    Corriger (voir TACTIQUES_MANUELLES en tete de script) puis relancer.")

    bloquant = bool(anomalies or incomplets or fuites or doublons or ecarts)
    if not bloquant:
        if a.pas_de_publication:
            print("\n[publication] ignoree (--pas-de-publication).")
        else:
            racine = dossier_n8n(a.n8n_files)
            try:
                publier(d_ech, racine, trouver_adc(a.adc), a.skill)
            except OSError as e:
                print("\n[publication] ECHEC : %s" % e)
                print("              Indiquer un autre dossier avec --n8n-files.")
                return False
            afficher_lancement(racine, d_ech)
        if len(lignes) != a.attendu:
            print("\n  [i] corpus partiel (%d/%d) : lancer les autres zones avant "
                  "l'evaluation." % (len(lignes), a.attendu))
        return True
    print("\n[!] Corpus inexploitable en l'etat : corriger les points ci-dessus "
          "avant de lancer le workflow.")
    return False


def reinitialiser_corpus(sortie, verite, echantillons):
    """--toutes-zones part d'un corpus PROPRE : on efface la verite de terrain
       et tous les S###.jsonl (a plat comme dans le sous-dossier) avant de
       regenerer. C'est ce qui garantit une numerotation continue de S000 et
       supprime toute trace d'une execution anterieure, quel que soit l'etat
       du dossier au depart."""
    out = pathlib.Path(sortie)
    fv = out / verite if not os.path.isabs(verite) else pathlib.Path(verite)
    d_ech = (pathlib.Path(echantillons) if os.path.isabs(echantillons)
             else out / echantillons)
    retires = 0
    if fv.exists():
        fv.unlink(); retires += 1
    for base in (out, d_ech):
        if base.exists():
            for f in sorted(base.glob("S*.jsonl")):
                f.unlink(); retires += 1
    if retires:
        print("[*] corpus precedent efface cote projet (%d fichier(s)) : "
              "regeneration complete a partir de S000." % retires)


def purger_n8n(racine):
    """Vide, cote n8n, ce que le pipeline consomme, AVANT toute nouvelle copie :
         <racine>/dataset/S###.jsonl                     anciens echantillons
         <racine>/skills/mitre-attack-mapping/           ancienne version du skill
       Le but est d'eviter tout doublon ou residu d'une campagne precedente :
       un ancien S0xx qui ne fait plus partie du corpus, ou une version obsolete
       du skill. Le dossier resultats/ n'est PAS touche : il contient les
       sorties du workflow, jamais regenerees par ce script.
       La verite de terrain n'y est de toute facon jamais publiee."""
    racine = pathlib.Path(racine)
    n = 0
    d_data = racine / "dataset"
    if d_data.exists():
        for f in sorted(d_data.glob("S*.jsonl")):
            f.unlink(); n += 1
    d_skill = racine / DOSSIER_SKILLS / NOM_SKILL
    if d_skill.exists():
        shutil.rmtree(d_skill); n += 1
    if n:
        print("[*] dossier n8n purge avant copie (%d element(s) : anciens "
              "echantillons + skill) -> %s" % (n, racine))
    return n


def toutes_zones(a):
    """Genere les trois zones dans l'ordre, en une seule commande.

       Chaque zone est traitee SANS publication et sans controle du total ;
       seule la derniere publie et verifie que le corpus complet atteint
       --attendu. Ainsi la numerotation reste continue et le skill n'est copie
       qu'une fois, a la fin."""
    zones = [z.strip() for z in a.dossiers_zones.split(",") if z.strip()]
    parent = a.dossier if a.dossier not in (None, "") else "."
    manquantes = [z for z in zones
                  if not pathlib.Path(parent, z).is_dir()]
    if manquantes:
        sys.exit("[!] --toutes-zones : sous-dossier(s) introuvable(s) sous %s :\n"
                 "      %s\n    Attendu : %s"
                 % (os.path.abspath(parent), ", ".join(manquantes),
                    ", ".join(zones)))
    if a.sortie is None:
        a.sortie = os.path.dirname(os.path.abspath(__file__)) or "."
    reinitialiser_corpus(a.sortie, a.verite, a.echantillons)
    # Purge cote n8n AVANT toute copie : on evite les doublons (ancien S0xx qui
    # ne fait plus partie du corpus, version obsolete du skill). Ignoree si la
    # publication est explicitement desactivee pour toute la passe.
    if not a.pas_de_publication:
        purger_n8n(dossier_n8n(a.n8n_files))

    total = len(zones)
    for i, zone_dir in enumerate(zones, 1):
        derniere = (i == total)
        print("\n" + "=" * 78)
        print("=== ZONE %d/%d : %s%s ===" % (i, total, zone_dir,
              "  (publication finale)" if derniere else ""))
        print("=" * 78)
        # copie superficielle des arguments, ajustee pour cette zone
        sous = argparse.Namespace(**vars(a))
        sous.toutes_zones = False
        sous.dossier = str(pathlib.Path(parent, zone_dir))
        sous.zone = None                      # laissee a la detection
        sous.pas_de_publication = not derniere  # publier seulement a la fin
        if not executer_zone(sous):
            sys.exit("\n[!] Zone %s en echec : corpus non publie. "
                     "Corriger puis relancer --toutes-zones." % zone_dir)
    print("\n[ok] Les %d zones ont ete generees et publiees en une passe." % total)


def main():
    a = construire_parseur().parse_args()
    if a.toutes_zones:
        toutes_zones(a)
    elif not executer_zone(a):
        sys.exit(1)


if __name__ == "__main__":
    main()
