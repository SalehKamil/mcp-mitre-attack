# Version 1.1.0 du serveur MCP MITRE ATT&CK - hybride Enterprise (IT) + ICS (OT).
"""MCP MITRE ATT&CK - serveur stdio exposant les matrices Enterprise et ICS a un client MCP.

Evolution directe de la v1.0 (Enterprise seul). Apports de la v1.1 :
  - seconde matrice ICS fusionnee dans la meme base, cloisonnee par champ "matrix"
  - journal d'audit JSONL asynchrone (Logs/mcp_audit.jsonl)
  - recherche scoree avec preuves de correspondance ("matched_in"), bornes et filtre de matrice

Tout l'acquis v1.0 est conserve : pipeline de detection (strategies, analytics,
canaux de logs), resolution par nom/alias, normalisation d'identifiants, ordre
kill-chain officiel, metadonnees de troncature, cache atomique, demarrage
asynchrone.

Usage:
  python mcp_mitre.py            Demarre le serveur MCP (stdio).
  python mcp_mitre.py --test     Charge la base et affiche un diagnostic.
  python mcp_mitre.py --no-audit Demarre sans journal d'audit.
  python mcp_mitre.py --help     Affiche ce message.

Variables d'environnement:
  MITRE_CACHE   Repertoire du cache local  (defaut: MITRE_DB/ a cote du script).
  MITRE_LOGS    Repertoire du journal d'audit (defaut: Logs/ a cote du script).
"""

import json,sys,os,re,queue,logging,threading,urllib.request
from pathlib import Path
from datetime import datetime
for _s in (sys.stdin,sys.stdout,sys.stderr):
    try:_s.reconfigure(encoding="utf-8",errors="replace")
    except Exception:pass
logging.basicConfig(level=logging.INFO,format="%(asctime)s %(message)s",handlers=[logging.StreamHandler(sys.stderr)])
log=logging.getLogger("mcp-mitre")

SERVER_NAME="mcp-mitre"
SERVER_VERSION="1.1.0"

# Les deux matrices. L'ordre compte : Enterprise est indexee en premier.
MATRICES={
    "Enterprise":"https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    "ICS":"https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json",
}
ATTACK_SOURCES=("mitre-attack","mitre-ics-attack")
KILL_CHAINS=("mitre-attack","mitre-ics-attack")

CACHE=Path(os.getenv("MITRE_CACHE",Path(__file__).resolve().parent/"MITRE_DB"))
DB_FILE=CACHE/"attack.json"
LOGS=Path(os.getenv("MITRE_LOGS",Path(__file__).resolve().parent/"Logs"))
AUDIT_FILE=LOGS/"mcp_audit.jsonl"
STALE_DAYS=30

SEARCH_DEFAULT_LIMIT=25
SEARCH_MAX_LIMIT=50
MAX_QUERY_LEN=256
STOPWORDS={"the","and","for","via","with","that","this","from","are","was","use","used","uses",
    "using","may","can","also","such","into","its","des","les","une","pour","par","dans","est","sur","aux","avec"}

#  Journal d'audit JSONL (thread dedie, non bloquant pour les reponses aux outils)

class AuditWriter:
    def __init__(self,path):
        self._q=queue.Queue(maxsize=10000);self._stop=threading.Event();self._f=None
        try:
            path.parent.mkdir(parents=True,exist_ok=True)
            self._f=open(path,"a",encoding="utf-8")
        except Exception as e:
            log.warning(f"Audit desactive ({e})");return
        self._t=threading.Thread(target=self._run,daemon=True,name="audit");self._t.start()
    def write(self,rec):
        if not self._f:return
        try:self._q.put_nowait(rec)
        except queue.Full:pass
    def _write(self,batch):
        if not batch:return
        try:
            self._f.write("".join(json.dumps(r,ensure_ascii=False)+"\n" for r in batch));self._f.flush()
        except Exception as e:log.warning(f"Audit error: {e}")
    def _run(self):
        while not self._stop.is_set():
            try:batch=[self._q.get(timeout=1.0)]      # bloque jusqu'au premier evenement
            except queue.Empty:continue
            while True:                               # puis vide la file d'un coup
                try:batch.append(self._q.get_nowait())
                except queue.Empty:break
            self._write(batch)
        # Drain final : aucun evenement n'est perdu a l'arret.
        batch=[]
        while True:
            try:batch.append(self._q.get_nowait())
            except queue.Empty:break
        self._write(batch)
        try:self._f.close()
        except Exception:pass
    def shutdown(self):
        if not self._f:return
        self._stop.set()
        try:self._t.join(timeout=3.0)
        except Exception:pass

# Instancie AVANT la base : les evenements de chargement du cache sont ainsi
# traces eux aussi. --no-audit desactive completement le journal.
_audit=None if "--no-audit" in sys.argv else AuditWriter(AUDIT_FILE)

def audit(event,**data):
    if _audit:_audit.write({"ts":datetime.now().isoformat(),"event":event,**data})

#  Base de connaissance fusionnee Enterprise + ICS

class MitreDB:
    FIELDS=("tactics","techniques","groups","software","mitigations","datasources","order","meta","spec")
    def __init__(self):
        self.tactics={};self.techniques={};self.groups={};self.software={};self.mitigations={};self.datasources={}
        self.order={};self.meta={};self.spec=""
        self.ready=False;self._lock=threading.Lock()
        self._load()

    #  Cache

    def _load(self):
        if not DB_FILE.exists():return False
        try:
            d=json.loads(DB_FILE.read_text(encoding="utf-8"))
            for k in self.FIELDS:
                if k in d:setattr(self,k,d[k])
            # Une base n'est "prete" que si CHAQUE matrice attendue est presente.
            # Sinon on retelecharge : un cache partiel ferait mapper le LLM dans
            # la mauvaise matrice sans qu'il puisse s'en rendre compte.
            self.ready=bool(self.techniques) and all(m in self.meta for m in MATRICES)
            if self.ready:
                log.info(f"Cache: {len(self.techniques)} techniques, {len(self.tactics)} tactiques ({', '.join(sorted(self.meta))})")
                audit("db_loaded",source="cache",techniques=len(self.techniques))
            else:
                log.warning("Cache incomplet (matrice manquante) : retelechargement")
                audit("cache_incomplete",matrices=sorted(self.meta))
            return self.ready
        except Exception as e:
            log.warning(f"Cache illisible ({e}) : retelechargement");audit("cache_invalid",error=str(e));return False

    def _write_cache(self):
        try:
            CACHE.mkdir(parents=True,exist_ok=True);tmp=DB_FILE.with_suffix(".tmp")
            tmp.write_text(json.dumps({k:getattr(self,k) for k in self.FIELDS},ensure_ascii=False),encoding="utf-8")
            tmp.replace(DB_FILE)   # remplacement atomique : un echec ne corrompt pas le cache existant
        except Exception as e:log.warning(f"Cache non ecrit: {e}")

    def age_days(self):
        ts=[m.get("updated") for m in self.meta.values() if m.get("updated")]
        if not ts:return None
        try:return round((datetime.now()-min(datetime.fromisoformat(t) for t in ts)).total_seconds()/86400,1)
        except Exception:return None

    def ensure(self):
        with self._lock:
            if not self.ready:self.download()
        return self.ready

    #  Telechargement

    def _fetch(self,name,url):
        log.info(f"Telechargement MITRE {name}...")
        audit("download_start",matrix=name,url=url)
        t0=datetime.now()
        req=urllib.request.Request(url,headers={"User-Agent":f"MCP-MITRE/{SERVER_VERSION}"})
        with urllib.request.urlopen(req,timeout=90) as r:bundle=json.loads(r.read())
        ms=int((datetime.now()-t0).total_seconds()*1000)
        audit("download_complete",matrix=name,duration_ms=ms)
        return bundle

    def download(self)->dict:
        """Telecharge les deux matrices puis reconstruit la base. La base en place
        n'est remplacee qu'en cas de succes complet."""
        bundles={};errors={}
        for name,url in MATRICES.items():
            try:bundles[name]=self._fetch(name,url)
            except Exception as e:
                errors[name]=str(e);log.error(f"Telechargement {name} echoue: {e}");audit("download_error",matrix=name,error=str(e))
        if errors:
            # Aucune modification de la base : un echec reseau ne doit pas vider
            # ni amputer une base deja chargee.
            return {"status":"error","errors":errors,"base_preservee":self.ready}
        try:
            self._parse(bundles)
        except Exception as e:
            log.error(f"Parsing echoue: {e}");audit("parse_error",error=str(e))
            return {"status":"error","errors":{"parse":str(e)},"base_preservee":self.ready}
        self.ready=True
        self._write_cache()
        log.info(f"MITRE pret: {len(self.techniques)} techniques, {len(self.tactics)} tactiques, "
                 f"{sum(1 for t in self.techniques.values() if t['detections'])} avec detection")
        audit("db_loaded",source="download",techniques=len(self.techniques))
        return {"status":"ok","matrices":{n:self.meta[n] for n in self.meta},
                "tactics":len(self.tactics),"techniques":len(self.techniques),
                "groups":len(self.groups),"software":len(self.software),
                "mitigations":len(self.mitigations),"data_sources":len(self.datasources)}

    #  Parsing

    def _aid(self,o):
        for r in o.get("external_references",[]):
            if r.get("source_name") in ATTACK_SOURCES and r.get("external_id"):return r["external_id"]
        return ""
    def _url(self,o):
        return next((r.get("url","") for r in o.get("external_references",[]) if r.get("source_name") in ATTACK_SOURCES),"")

    def _parse(self,bundles):
        """Trois passes sur les DEUX bundles reunis. Aucune dependance a l'ordre de
        publication des objets par MITRE, ni a l'ordre des matrices entre elles."""
        for a in("tactics","techniques","groups","software","mitigations","datasources"):getattr(self,a).clear()
        self.order={};self.meta={}
        idm={};rels=[];matrices={};comps={};analytics={};strategies={}
        seen=set()   # STIX id deja indexe (objets partages entre les deux bundles)

        # Passe 1 : indexation de tous les objets des deux matrices.
        for mx,bundle in bundles.items():
            n_obj=0
            for o in bundle.get("objects",[]):
                if o.get("revoked") or o.get("x_mitre_deprecated"):continue
                ot=o.get("type","");oid=o.get("id","");aid=self._aid(o);n_obj+=1
                if ot=="x-mitre-matrix":
                    matrices[mx]=o;self.spec=self.spec or o.get("x_mitre_attack_spec_version","")
                elif ot=="x-mitre-data-component":comps[oid]=o
                elif ot=="x-mitre-analytic":analytics[oid]=o
                elif ot=="x-mitre-detection-strategy":strategies[oid]=o
                elif ot=="relationship":rels.append(o)
                elif not aid:continue
                # Objets partages entre matrices (groupes et software portent les
                # MEMES identifiants G**** / S**** dans les deux bundles) : on
                # enrichit l'entree existante au lieu de l'ecraser, sinon les
                # relations deja collectees seraient perdues.
                elif oid in seen:
                    for store in (self.groups,self.software):
                        if aid in store and mx not in store[aid]["matrices"]:store[aid]["matrices"].append(mx)
                elif ot=="x-mitre-tactic":
                    seen.add(oid);idm[oid]=aid
                    self.tactics[aid]={"id":aid,"name":o.get("name",""),"matrix":mx,
                        "shortname":o.get("x_mitre_shortname",""),"description":o.get("description",""),"techniques":[]}
                elif ot=="attack-pattern":
                    seen.add(oid);idm[oid]=aid
                    phases=[k["phase_name"] for k in o.get("kill_chain_phases",[]) if k.get("kill_chain_name") in KILL_CHAINS]
                    self.techniques[aid]={"id":aid,"name":o.get("name",""),"matrix":mx,
                        "description":o.get("description",""),"platforms":o.get("x_mitre_platforms",[]),
                        "tactics":[],"phases":phases,"is_subtechnique":bool(o.get("x_mitre_is_subtechnique",False)),
                        "parent":"","subtechniques":[],"groups":[],"software":[],"mitigations":[],
                        "data_sources":[],"log_sources":[],"detection":"","detections":[],"url":self._url(o)}
                elif ot=="intrusion-set":
                    seen.add(oid);idm[oid]=aid
                    self.groups[aid]={"id":aid,"name":o.get("name",""),"matrices":[mx],
                        "description":o.get("description",""),"aliases":o.get("aliases",[]),
                        "techniques":[],"software":[],"url":self._url(o)}
                elif ot in("tool","malware"):
                    seen.add(oid);idm[oid]=aid
                    self.software[aid]={"id":aid,"name":o.get("name",""),"type":ot,"matrices":[mx],
                        "description":o.get("description",""),"platforms":o.get("x_mitre_platforms",[]),
                        "aliases":o.get("x_mitre_aliases",o.get("aliases",[])),"techniques":[],"url":self._url(o)}
                elif ot=="course-of-action":
                    seen.add(oid);idm[oid]=aid
                    self.mitigations[aid]={"id":aid,"name":o.get("name",""),"matrix":mx,
                        "description":o.get("description",""),"techniques":[],"url":self._url(o)}
            self.meta[mx]={"updated":datetime.now().isoformat(),"source":"github.com/mitre/cti","objects":n_obj}

        # Ordre kill-chain officiel, lu dans la matrice publiee, par matrice.
        for mx,m in matrices.items():
            self.order[mx]=[idm[r] for r in m.get("tactic_refs",[]) if r in idm and idm[r] in self.tactics] \
                           or sorted(t for t in self.tactics if self.tactics[t]["matrix"]==mx)

        # Passe 2 : rattachement technique -> tactique, CLOISONNE PAR MATRICE.
        # Les shortnames ("persistence", "execution"...) existent dans les deux
        # matrices : sans ce cloisonnement une technique ICS serait rattachee a la
        # tactique Enterprise homonyme.
        sn={}
        for tid,t in self.tactics.items():
            if t["shortname"]:sn[(t["matrix"],t["shortname"])]=tid
        for tid,t in self.techniques.items():
            for p in t["phases"]:
                x=sn.get((t["matrix"],p))
                if x and tid not in self.tactics[x]["techniques"]:
                    self.tactics[x]["techniques"].append(tid);t["tactics"].append(x)

        # Passe 3 : relations, tous les objets des deux matrices etant indexes.
        for o in rels:
            rt=o.get("relationship_type","");src=o.get("source_ref","");tgt=o.get("target_ref","")
            if rt=="detects":
                st=strategies.get(src);tid=idm.get(tgt,"")
                if st and tid in self.techniques:self._attach_detection(self.techniques[tid],st,analytics,comps)
                continue
            s=idm.get(src,"");t=idm.get(tgt,"")
            if not s or not t:continue
            if rt=="uses":
                if s in self.groups and t in self.techniques:
                    if t not in self.groups[s]["techniques"]:self.groups[s]["techniques"].append(t)
                    if s not in self.techniques[t]["groups"]:self.techniques[t]["groups"].append(s)
                elif s in self.software and t in self.techniques:
                    if t not in self.software[s]["techniques"]:self.software[s]["techniques"].append(t)
                    if s not in self.techniques[t]["software"]:self.techniques[t]["software"].append(s)
                elif s in self.groups and t in self.software:
                    if t not in self.groups[s]["software"]:self.groups[s]["software"].append(t)
            elif rt=="mitigates" and s in self.mitigations and t in self.techniques:
                if t not in self.mitigations[s]["techniques"]:self.mitigations[s]["techniques"].append(t)
                if s not in self.techniques[t]["mitigations"]:self.techniques[t]["mitigations"].append(s)
            elif rt=="subtechnique-of" and s in self.techniques and t in self.techniques:
                self.techniques[s]["parent"]=t
                if s not in self.techniques[t]["subtechniques"]:self.techniques[t]["subtechniques"].append(s)

        # Repli sur la numerotation pour toute sous-technique sans relation explicite.
        for tid,t in self.techniques.items():
            if t["is_subtechnique"] and not t["parent"] and "." in tid:
                p=tid.split(".")[0]
                if p in self.techniques:
                    t["parent"]=p
                    if tid not in self.techniques[p]["subtechniques"]:self.techniques[p]["subtechniques"].append(tid)
        for t in self.techniques.values():t["subtechniques"].sort();t["data_sources"].sort();t["log_sources"].sort()
        for tid in self.tactics:self.tactics[tid]["techniques"].sort()

        # Index inverse source de donnees -> techniques (composants, sources, canaux).
        for tid,t in self.techniques.items():
            for label in set(t["data_sources"])|set(t["log_sources"]):
                self.datasources.setdefault(label,[])
                if tid not in self.datasources[label]:self.datasources[label].append(tid)

    def _attach_detection(self,tech,st,analytics,comps):
        """Modele de detection courant : strategie -> analytics -> composants et canaux."""
        entry={"id":self._aid(st),"name":st.get("name",""),"analytics":[]}
        for ar in st.get("x_mitre_analytic_refs",[]):
            a=analytics.get(ar)
            if not a:continue
            ls=[]
            for r in a.get("x_mitre_log_source_references",[]):
                nm=(r.get("name") or "").strip();ch=(r.get("channel") or "").strip()
                # Cote ICS, certains canaux valent litteralement "None"/"N/A" :
                # sans ce filtre l'index se remplit de libelles parasites ("Asset:None").
                if ch.lower() in("none","n/a","-"):ch=""
                if nm.lower() in("none","n/a","-"):nm=""
                cn=comps.get(r.get("x_mitre_data_component_ref",""),{}).get("name","")
                ls.append({"component":cn,"source":nm,"channel":ch})
                if cn and cn not in tech["data_sources"]:tech["data_sources"].append(cn)
                for lab in (nm,f"{nm}:{ch}" if nm and ch else ""):
                    if lab and lab not in tech["log_sources"]:tech["log_sources"].append(lab)
            entry["analytics"].append({"name":a.get("name",""),"description":a.get("description",""),
                "platforms":a.get("x_mitre_platforms",[]),"log_sources":ls,
                "tuning":[m.get("field","") for m in a.get("x_mitre_mutable_elements",[]) if m.get("field")]})
        if not entry["analytics"] and not entry["name"]:return
        tech["detections"].append(entry)
        tech["detection"]="\n\n".join(f"{e['name']}: {x['description']}"
                                      for e in tech["detections"] for x in e["analytics"] if x["description"])

db=MitreDB()

#  Outils MCP

TOOLS={};ALIASES={}
def tool(name,desc,params=None,aliases=()):
    def deco(fn):
        props={};req=[]
        for pn,(pt,rq,pd) in(params or{}).items():
            props[pn]={"type":pt,"description":pd}
            if rq:req.append(pn)
        TOOLS[name]={"handler":fn,"schema":{"name":name,"description":desc,
            "inputSchema":{"type":"object","properties":props,"required":req}}}
        for a in aliases:ALIASES[a]=name
        return fn
    return deco

def J(o):return json.dumps(o,ensure_ascii=False,indent=2)

def TID(q):
    """Normalise un identifiant de technique : t1059.1 -> T1059.001, t0831 -> T0831."""
    q=(q or "").strip().upper().replace(" ","")
    if "." in q:
        a,b=q.split(".",1)
        if b.isdigit():return f"{a}.{int(b):03d}"
    return q
def technique(q):return db.techniques.get(TID(q))

def resolve(store,q):
    """Retrouve un objet par ID, nom exact, alias, puis nom partiel."""
    if not q:return None
    k=q.strip().upper()
    if k in store:return store[k]
    ql=q.strip().lower()
    for v in store.values():
        if v["name"].lower()==ql:return v
    for v in store.values():
        if any((a or "").lower()==ql for a in v.get("aliases",[])):return v
    for v in store.values():
        if ql in v["name"].lower():return v
    return None

def cut(items,n):
    """Tronque une liste en signalant explicitement la troncature au modele."""
    return items[:n],{"shown":min(n,len(items)),"total":len(items),"truncated":len(items)>n}

def MX(q):
    """Normalise un filtre de matrice. Renvoie 'Enterprise', 'ICS' ou None."""
    v=(q or "").strip().lower()
    if not v:return None
    if v.startswith(("ent","it")):return "Enterprise"
    if v.startswith(("ics","ot","scada")):return "ICS"
    return None

def tmx(t):
    """Matrice d'une technique, avec ses tactiques resolues."""
    return [{"id":x,"name":db.tactics[x]["name"]} for x in t["tactics"] if x in db.tactics]


@tool("mitre_stats","Version du serveur et statistiques de la base hybride chargee (Enterprise + ICS).")
def mitre_stats():
    p=sum(1 for t in db.techniques.values() if not t["is_subtechnique"])
    a=db.age_days()
    per={}
    for mx in MATRICES:
        per[mx]={"tactics":sum(1 for t in db.tactics.values() if t["matrix"]==mx),
                 "techniques":sum(1 for t in db.techniques.values() if t["matrix"]==mx),
                 "mitigations":sum(1 for m in db.mitigations.values() if m["matrix"]==mx),
                 "groups":sum(1 for g in db.groups.values() if mx in g["matrices"]),
                 "software":sum(1 for s in db.software.values() if mx in s["matrices"]),
                 "updated":db.meta.get(mx,{}).get("updated","")}
    return J({"server":SERVER_NAME,"server_version":SERVER_VERSION,"source":"github.com/mitre/cti",
        "attack_spec":db.spec,"age_days":a,"stale":bool(a is not None and a>STALE_DAYS),
        "matrices":per,
        "tactics":len(db.tactics),"techniques":len(db.techniques),"parents":p,"subtechniques":len(db.techniques)-p,
        "groups":len(db.groups),"software":len(db.software),"mitigations":len(db.mitigations),
        "data_sources":len(db.datasources),
        "techniques_with_detection":sum(1 for t in db.techniques.values() if t["detections"])})

@tool("mitre_update","Re-telecharge les deux matrices (Enterprise + ICS) et reconstruit la base.")
def mitre_update():return J(db.download())

@tool("mitre_tactics","Les tactiques ATT&CK dans l'ordre de la kill chain, par matrice. "
      "Sans argument : les deux matrices (15 Enterprise + 12 ICS).",
      {"matrix":("string",False,"Enterprise, ICS, ou vide pour les deux")},
      aliases=("get_tactics",))
def mitre_tactics(matrix=""):
    want=MX(matrix)
    out={}
    for mx in MATRICES:
        if want and mx!=want:continue
        out[mx]=[{"id":tid,"name":db.tactics[tid]["name"],"description":db.tactics[tid]["description"][:200],
                  "technique_count":len(db.tactics[tid]["techniques"])}
                 for tid in db.order.get(mx,[]) if tid in db.tactics]
    return J({"matrices":out})

@tool("mitre_tactic","Detail d'une tactique et de ses techniques parentes. Accepte un ID ou un nom ; "
      "un nom present dans les deux matrices (ex: Persistence) doit etre leve par l'argument matrix.",
      {"id":("string",True,"ex: TA0002, TA0110 ou Execution"),
       "matrix":("string",False,"Enterprise ou ICS, pour lever une ambiguite de nom")},
      aliases=("get_tactic",))
def mitre_tactic(id,matrix=""):
    want=MX(matrix)
    store={k:v for k,v in db.tactics.items() if not want or v["matrix"]==want}
    t=resolve(store,id)
    if not t:return J({"error":f"Tactique '{id}' non trouvee","matrix_filtre":want or "aucun"})
    # Homonymes entre matrices : on previent explicitement le modele.
    twins=[x["id"] for x in db.tactics.values() if x["name"].lower()==t["name"].lower() and x["id"]!=t["id"]]
    techs=[{"id":tid,"name":db.techniques[tid]["name"],"subtechniques":len(db.techniques[tid]["subtechniques"])}
           for tid in t["techniques"] if tid in db.techniques and not db.techniques[tid]["is_subtechnique"]]
    r={"id":t["id"],"name":t["name"],"matrix":t["matrix"],"description":t["description"],
       "technique_count":len(techs),"techniques":techs}
    if twins:r["homonyme_autre_matrice"]=twins
    return J(r)

@tool("mitre_search","Recherche scoree de techniques candidates (Enterprise + ICS) sur l'identifiant, le nom, "
      "la description, les sources de donnees, les canaux de logs (ex: 4688, WinEventLog:Security) et le texte "
      "des analytics. Renvoie des candidats CLASSES avec leur matrice, leur score et le champ matched_in qui "
      "indique OU la correspondance a eu lieu : un candidat ne matchant que sur 'description' est souvent "
      "fortuit. La recherche est LEXICALE, pas semantique : formuler la requete en mots-cles anglais ATT&CK. "
      "Confirmer chaque candidat retenu avec mitre_technique.",
      {"query":("string",True,"Mots-cles anglais ATT&CK, identifiant, canal de log ou event ID"),
       "matrix":("string",False,"Restreint a Enterprise ou ICS"),
       "limit":("integer",False,f"Nombre max de candidats (defaut {SEARCH_DEFAULT_LIMIT}, max {SEARCH_MAX_LIMIT})")},
      aliases=("search_techniques",))
def mitre_search(query,matrix="",limit=SEARCH_DEFAULT_LIMIT):
    if not isinstance(query,str):return J({"error":"query doit etre une chaine"})
    q=query.strip()
    if len(q)>MAX_QUERY_LEN:return J({"error":f"query trop longue ({len(q)} > {MAX_QUERY_LEN})"})
    if not q:return J({"query":query,"results":{"shown":0,"total":0,"truncated":False},"techniques":[]})
    try:limit=int(limit)
    except (TypeError,ValueError):limit=SEARCH_DEFAULT_LIMIT
    limit=max(1,min(limit,SEARCH_MAX_LIMIT))
    want=MX(matrix);ql=q.lower()

    # Tokens significatifs. Le point est conserve pendant le decoupage pour ne pas
    # casser T1059.001, puis retire en bord de token ("task." -> "task").
    tokens=[w.strip(".") for w in re.split(r"[^a-z0-9.]+",ql)]
    tokens=[w for w in tokens if len(w)>=3 and w not in STOPWORDS]
    m=re.search(r"\bt\d{4}(?:\.\d{1,3})?\b",ql)
    id_like=TID(m.group(0)) if m else None

    res=[]
    for tid,t in db.techniques.items():
        if want and t["matrix"]!=want:continue
        nl=t["name"].lower();dl=t["description"].lower();s=0;mi=set()
        if id_like:
            if tid==id_like:s+=100;mi.add("id")
            elif tid.startswith(id_like+".") or id_like.startswith(tid+"."):s+=60;mi.add("id")
        elif ql==tid.lower():s+=100;mi.add("id")
        elif ql in tid.lower():s+=10;mi.add("id")
        if ql==nl:s+=40;mi.add("name")
        elif nl.startswith(ql):s+=20;mi.add("name")
        elif ql in nl:s+=15;mi.add("name")
        if ql in dl:s+=4;mi.add("description")
        hits=[d for d in t["data_sources"]+t["log_sources"] if ql in d.lower()]
        if hits:s+=12;mi.add("data_source")
        if ql in t["detection"].lower():s+=6;mi.add("detection")
        for w in tokens:
            if w in nl:s+=4;mi.add("name")
            elif w in dl:s+=1;mi.add("description")
        if s>0:
            res.append({"id":tid,"name":t["name"],"matrix":t["matrix"],"score":s,"matched_in":sorted(mi),
                "is_subtechnique":t["is_subtechnique"],
                "tactics":[db.tactics[x]["name"] for x in t["tactics"] if x in db.tactics],
                "platforms":t["platforms"],"matched_sources":sorted(hits)[:5],
                "description":t["description"][:250]})
    res.sort(key=lambda x:(-x["score"],x["id"]))   # tri deterministe
    shown,meta=cut(res,limit)
    return J({"query":query,"matrix_filtre":want or "aucun","results":meta,"techniques":shown})

@tool("mitre_technique","Detail complet d'une technique Enterprise (T1***) ou ICS (T0***) : description, "
      "matrice, tactiques, plateformes, strategies de detection et analytics, sources de donnees et canaux "
      "de logs, sous-techniques, groupes APT, software, mitigations.",
      {"id":("string",True,"ex: T1059.001, t1059.1 ou T0831")},
      aliases=("get_technique",))
def mitre_technique(id):
    t=technique(id)
    if not t:return J({"error":f"Technique '{id}' non trouvee"})
    g,gm=cut(t["groups"],20);s,sm=cut(t["software"],20);m,mm=cut(t["mitigations"],15)
    return J({"id":t["id"],"name":t["name"],"matrix":t["matrix"],"description":t["description"],"url":t["url"],
        "platforms":t["platforms"],"tactics":tmx(t),"phases":t["phases"],
        "is_subtechnique":t["is_subtechnique"],"parent":t["parent"],
        "subtechniques_detail":[{"id":x,"name":db.techniques[x]["name"]} for x in t["subtechniques"] if x in db.techniques],
        "data_sources":t["data_sources"],"log_sources":t["log_sources"],
        "detection":t["detection"],"detections":t["detections"],
        "groups":gm,"groups_detail":[{"id":x,"name":db.groups[x]["name"],"matrices":db.groups[x]["matrices"],
            "aliases":db.groups[x]["aliases"][:5]} for x in g if x in db.groups],
        "software":sm,"software_detail":[{"id":x,"name":db.software[x]["name"],"type":db.software[x]["type"]} for x in s if x in db.software],
        "mitigations":mm,"mitigations_detail":[{"id":x,"name":db.mitigations[x]["name"],"matrix":db.mitigations[x]["matrix"],
            "description":db.mitigations[x]["description"][:300]} for x in m if x in db.mitigations]})

@tool("mitre_groups","Groupes APT. Sans argument : top 50 par nombre de techniques. Avec technique_id : "
      "les groupes connus pour utiliser cette technique.",
      {"technique_id":("string",False,"ID technique (optionnel)"),
       "matrix":("string",False,"Restreint aux groupes actifs sur Enterprise ou ICS")},
      aliases=("get_groups",))
def mitre_groups(technique_id="",matrix=""):
    want=MX(matrix)
    if technique_id:
        t=technique(technique_id)
        if not t:return J({"error":f"Technique '{technique_id}' non trouvee"})
        ids=[x for x in t["groups"] if x in db.groups and (not want or want in db.groups[x]["matrices"])]
        g,meta=cut(ids,30)
        return J({"technique":t["id"],"matrix":t["matrix"],"results":meta,
            "groups":[{"id":x,"name":db.groups[x]["name"],"matrices":db.groups[x]["matrices"],
                       "aliases":db.groups[x]["aliases"][:5]} for x in g]})
    pool=[g for g in db.groups.values() if not want or want in g["matrices"]]
    r=sorted(pool,key=lambda g:(-len(g["techniques"]),g["id"]))
    g,meta=cut(r,50)
    return J({"matrix_filtre":want or "aucun","results":meta,
        "groups":[{"id":x["id"],"name":x["name"],"matrices":x["matrices"],"aliases":x["aliases"][:5],
                   "technique_count":len(x["techniques"])} for x in g]})

@tool("mitre_group","Detail d'un groupe APT, par ID, nom ou alias publie. Les techniques sont annotees de "
      "leur matrice : un groupe hybride comme Sandworm en possede dans les deux.",
      {"id":("string",True,"ex: G0034, Sandworm Team ou ELECTRUM")},
      aliases=("get_group",))
def mitre_group(id):
    g=resolve(db.groups,id)
    if not g:return J({"error":f"Groupe '{id}' non trouve"})
    t,tm=cut(g["techniques"],50);s,sm=cut(g["software"],20)
    return J({"id":g["id"],"name":g["name"],"matrices":g["matrices"],"aliases":g["aliases"],
        "description":g["description"],"url":g["url"],
        "techniques":tm,"techniques_detail":[{"id":x,"name":db.techniques[x]["name"],"matrix":db.techniques[x]["matrix"],
            "tactics":[db.tactics[y]["name"] for y in db.techniques[x]["tactics"] if y in db.tactics]} for x in t if x in db.techniques],
        "software":sm,"software_detail":[{"id":x,"name":db.software[x]["name"],"type":db.software[x]["type"]} for x in s if x in db.software]})

@tool("mitre_software","Software/malware. Sans argument : top 50. Avec un ID de technique : les software "
      "associes. Avec un ID S**** ou un nom (Mimikatz, Industroyer) : la fiche detaillee.",
      {"technique_id":("string",False,"ID technique, ID software ou nom (optionnel)")},
      aliases=("get_software",))
def mitre_software(technique_id=""):
    q=(technique_id or "").strip()
    if q:
        t=technique(q)
        if t:
            s,meta=cut(t["software"],30)
            return J({"technique":t["id"],"matrix":t["matrix"],"results":meta,
                "software":[{"id":x,"name":db.software[x]["name"],"type":db.software[x]["type"],
                             "matrices":db.software[x]["matrices"]} for x in s if x in db.software]})
        sw=resolve(db.software,q)
        if sw:
            t2,tm=cut(sw["techniques"],50)
            return J({"id":sw["id"],"name":sw["name"],"type":sw["type"],"matrices":sw["matrices"],
                "aliases":sw["aliases"],"platforms":sw["platforms"],"description":sw["description"],"url":sw["url"],
                "techniques":tm,"techniques_detail":[{"id":x,"name":db.techniques[x]["name"],
                    "matrix":db.techniques[x]["matrix"]} for x in t2 if x in db.techniques]})
        return J({"error":f"'{technique_id}' non trouve"})
    r=sorted(db.software.values(),key=lambda s:(-len(s["techniques"]),s["id"]))
    s,meta=cut(r,50)
    return J({"results":meta,"software":[{"id":x["id"],"name":x["name"],"type":x["type"],
        "matrices":x["matrices"],"technique_count":len(x["techniques"])} for x in s]})

@tool("mitre_mitigations","Les mitigations officielles associees a une technique, avec leur description complete.",
      {"technique_id":("string",True,"ex: T1059.001 ou T0831")})
def mitre_mitigations(technique_id):
    t=technique(technique_id)
    if not t:return J({"error":f"Technique '{technique_id}' non trouvee"})
    return J({"technique":t["id"],"name":t["name"],"matrix":t["matrix"],"count":len(t["mitigations"]),
        "mitigations":[{"id":m,"name":db.mitigations[m]["name"],"matrix":db.mitigations[m]["matrix"],
            "description":db.mitigations[m]["description"],"url":db.mitigations[m]["url"]}
            for m in t["mitigations"] if m in db.mitigations]})

@tool("mitre_mitigation","Detail d'une contre-mesure et de toutes les techniques qu'elle couvre. "
      "Accepte un ID Enterprise (M1***), un ID ICS (M0***) ou un nom.",
      {"id":("string",True,"ex: M1043, M0801 ou Credential Access Protection")},
      aliases=("get_mitigation",))
def mitre_mitigation(id):
    m=resolve(db.mitigations,id)
    if not m:return J({"error":f"Mitigation '{id}' non trouvee"})
    t,meta=cut(m["techniques"],50)
    return J({"id":m["id"],"name":m["name"],"matrix":m["matrix"],"description":m["description"],"url":m["url"],
        "techniques":meta,"techniques_detail":[{"id":x,"name":db.techniques[x]["name"],
            "matrix":db.techniques[x]["matrix"]} for x in t if x in db.techniques]})

@tool("mitre_datasources","Techniques observables a partir d'une source de donnees, d'un composant, d'un canal "
      "de logs ou d'un identifiant d'evenement. Requetes valides : Process Creation, WinEventLog:Security, "
      "4688, AWS:CloudTrail, Network Traffic Content.",
      {"query":("string",True,"ex: Process Creation, WinEventLog:Security, 4688"),
       "matrix":("string",False,"Restreint a Enterprise ou ICS")},
      aliases=("get_datasources",))
def mitre_datasources(query,matrix=""):
    q=(query or "").strip().lower();want=MX(matrix)
    if not q:return J({"query":query,"matched_sources":[],"matched_source_count":0,
        "results":{"shown":0,"total":0,"truncated":False},"techniques":[]})
    matches={dn:tids for dn,tids in db.datasources.items() if q in dn.lower()}
    techs={}
    for tids in matches.values():
        for tid in tids:
            if tid in db.techniques and tid not in techs:
                t=db.techniques[tid]
                if want and t["matrix"]!=want:continue
                techs[tid]={"id":tid,"name":t["name"],"matrix":t["matrix"],
                    "tactics":[db.tactics[x]["name"] for x in t["tactics"] if x in db.tactics],
                    "platforms":t["platforms"]}
    out,meta=cut(sorted(techs.values(),key=lambda x:x["id"]),50)
    return J({"query":query,"matrix_filtre":want or "aucun","matched_sources":sorted(matches)[:40],
        "matched_source_count":len(matches),"results":meta,"techniques":out})

#  Boucle MCP (stdio JSON-RPC)

def run():
    if not db.ready:threading.Thread(target=db.ensure,daemon=True).start()
    log.info(f"MCP {SERVER_NAME} v{SERVER_VERSION}: {len(TOOLS)} outils, {len(db.techniques)} techniques")
    audit("server_start",pid=os.getpid(),version=SERVER_VERSION,tools=len(TOOLS))
    while True:
        try:
            line=sys.stdin.readline()
            if not line:break
            line=line.strip()
            if not line:continue
            try:msg=json.loads(line)
            except json.JSONDecodeError:log.warning("Message JSON invalide ignore");continue
            batch=isinstance(msg,list)
            out=[r for r in (handle(m) for m in (msg if batch else [msg])) if r]
            if out:sys.stdout.write(json.dumps(out if batch else out[0],ensure_ascii=False)+"\n");sys.stdout.flush()
        except KeyboardInterrupt:break
        except Exception as e:log.error(e)
    audit("server_stop")
    if _audit:_audit.shutdown()

def handle(msg):
    if not isinstance(msg,dict):return None
    method,mid,params=msg.get("method",""),msg.get("id"),msg.get("params") or {}
    if mid is None:return None
    if method=="initialize":
        v=params.get("protocolVersion")
        return R(mid,{"protocolVersion":v if isinstance(v,str) else "2024-11-05",
            "capabilities":{"tools":{}},"serverInfo":{"name":SERVER_NAME,"version":SERVER_VERSION}})
    if method=="tools/list":return R(mid,{"tools":[t["schema"] for t in TOOLS.values()]})
    if method=="tools/call":
        name,args=params.get("name",""),params.get("arguments") or {}
        name=ALIASES.get(name,name)          # compatibilite avec la nomenclature get_*
        t=TOOLS.get(name)
        if not t:return E(mid,-32602,f"Outil inconnu: {params.get('name','')}")
        if not db.ensure():
            return R(mid,{"content":[{"type":"text","text":J({"error":"Base MITRE indisponible"})}],"isError":True})
        try:
            res=t["handler"](**args);audit("tool_call",tool=name,status="success")
            return R(mid,{"content":[{"type":"text","text":res}]})
        except TypeError as e:
            audit("tool_call",tool=name,status="bad_args",error=str(e))
            return R(mid,{"content":[{"type":"text","text":J({"error":f"Arguments invalides: {e}",
                "attendus":sorted(t['schema']['inputSchema']['properties'])})}],"isError":True})
        except Exception as e:
            audit("tool_call",tool=name,status="error",error=str(e))
            return R(mid,{"content":[{"type":"text","text":J({"error":str(e)})}],"isError":True})
    if method in("resources/list","prompts/list"):return R(mid,{method.split("/")[0]:[]})
    if method=="ping":return R(mid,{})
    return E(mid,-32601,f"Methode inconnue: {method}")

def R(mid,result):return{"jsonrpc":"2.0","id":mid,"result":result}
def E(mid,code,msg):return{"jsonrpc":"2.0","id":mid,"error":{"code":code,"message":msg}}

if __name__=="__main__":
    if "--help" in sys.argv:print(__doc__);sys.exit(0)
    if "--test" in sys.argv:
        ok=db.ensure()
        print(f"Serveur : {SERVER_NAME} v{SERVER_VERSION}")
        print(f"MITRE   : github.com/mitre/cti (spec {db.spec or '?'})")
        for mx in MATRICES:
            n_t=sum(1 for t in db.tactics.values() if t["matrix"]==mx)
            n_k=sum(1 for t in db.techniques.values() if t["matrix"]==mx)
            n_d=sum(1 for t in db.techniques.values() if t["matrix"]==mx and t["detections"])
            flag="" if n_k else "  << MATRICE VIDE"
            print(f"  {mx:11} {n_t:3} tactiques, {n_k:4} techniques, {n_d:4} avec detection{flag}")
        print(f"  Total       {len(db.tactics)} tactiques, {len(db.techniques)} techniques")
        print(f"              {len(db.groups)} groupes, {len(db.software)} software, {len(db.mitigations)} mitigations")
        print(f"              {len(db.datasources)} sources de donnees")
        print(f"  Liens       {sum(len(t['techniques']) for t in db.tactics.values())} tactique-technique, "
              f"{sum(len(t['subtechniques']) for t in db.techniques.values())} parent-sous-technique")
        print(f"Outils ({len(TOOLS)}) : {list(TOOLS.keys())}")
        print(f"Alias   ({len(ALIASES)}) : {list(ALIASES.keys())}")
        empty=[m for m in MATRICES if not any(t["matrix"]==m for t in db.techniques.values())]
        if not ok or empty:
            print(f"ECHEC : matrices vides ou manquantes : {empty or 'base indisponible'}");sys.exit(1)
        if sum(len(t["techniques"]) for t in db.tactics.values())==0:
            print("ECHEC : aucun lien tactique-technique");sys.exit(1)
        print("OK");sys.exit(0)
    run()
