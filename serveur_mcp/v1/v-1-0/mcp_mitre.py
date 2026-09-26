# Version 1.0 du serveur MCP.
"""MCP MITRE ATT&CK - serveur stdio exposant la base Enterprise ATT&CK a un client MCP.

Usage:
  python mcp_mitre.py          Demarre le serveur MCP (stdio).
  python mcp_mitre.py --test   Charge la base et affiche un diagnostic.
  python mcp_mitre.py --help   Affiche ce message.

Variable d'environnement:
  MITRE_CACHE   Repertoire du cache local (defaut: MITRE_DB/ a cote du script).
"""

import json,sys,os,logging,threading,urllib.request
from pathlib import Path
from datetime import datetime
for _s in (sys.stdin,sys.stdout,sys.stderr):
    try:_s.reconfigure(encoding="utf-8",errors="replace")
    except Exception:pass
logging.basicConfig(level=logging.INFO,format="%(asctime)s %(message)s",handlers=[logging.StreamHandler(sys.stderr)])
log=logging.getLogger("mcp-mitre")

STIX_URL="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CACHE=Path(os.getenv("MITRE_CACHE",Path(__file__).resolve().parent/"MITRE_DB"))
DB_FILE=CACHE/"enterprise.json"
STALE_DAYS=30

class MitreDB:
    FIELDS=("tactics","techniques","groups","software","mitigations","datasources","order","source","updated","spec")
    def __init__(self):
        self.tactics={};self.techniques={};self.groups={};self.software={};self.mitigations={};self.datasources={}
        self.order=[];self.source="";self.updated="";self.spec=""
        self.ready=False;self._lock=threading.Lock()
        self._load()
    def _load(self):
        if not DB_FILE.exists():return False
        try:
            d=json.loads(DB_FILE.read_text(encoding="utf-8"))
            for k in self.FIELDS:
                if k in d:setattr(self,k,d[k])
            self.ready=bool(self.techniques)
            if self.ready:log.info(f"MITRE cache: {len(self.techniques)} techniques, {len(self.groups)} groups, {len(self.software)} software")
            return self.ready
        except Exception as e:log.warning(f"Cache error: {e}");return False
    def age_days(self):
        try:return round((datetime.now()-datetime.fromisoformat(self.updated)).total_seconds()/86400,1)
        except Exception:return None
    def ensure(self):
        with self._lock:
            if not self.ready:self.download()
        return self.ready
    def download(self)->dict:
        try:
            log.info("Telechargement de MITRE ATT&CK Enterprise...")
            with urllib.request.urlopen(urllib.request.Request(STIX_URL,headers={"User-Agent":"MCP/1.0"}),timeout=90) as r:stix=json.loads(r.read())
            self._parse(stix);self.source="github.com/mitre/cti";self.updated=datetime.now().isoformat();self.ready=True
            try:
                CACHE.mkdir(parents=True,exist_ok=True);tmp=DB_FILE.with_suffix(".tmp")
                tmp.write_text(json.dumps({k:getattr(self,k) for k in self.FIELDS},ensure_ascii=False),encoding="utf-8");tmp.replace(DB_FILE)
            except Exception as e:log.warning(f"Cache non ecrit: {e}")
            log.info(f"MITRE: {len(self.techniques)} techniques, {len(self.groups)} groups, {len(self.software)} software")
            return {"status":"ok","techniques":len(self.techniques),"groups":len(self.groups),"tactics":len(self.tactics),"data_sources":len(self.datasources)}
        except Exception as e:log.error(f"Telechargement erreur: {e}");self.source=self.source or "unavailable";return {"status":"error","message":str(e)}
    def _aid(self,o):
        for r in o.get("external_references",[]):
            if r.get("source_name")=="mitre-attack" and r.get("external_id"):return r["external_id"]
        return ""
    def _url(self,o):return next((r.get("url","") for r in o.get("external_references",[]) if r.get("source_name")=="mitre-attack"),"")
    def _parse(self,stix):
        for a in("tactics","techniques","groups","software","mitigations","datasources"):getattr(self,a).clear()
        self.order=[]
        objs=[o for o in stix.get("objects",[]) if not(o.get("revoked") or o.get("x_mitre_deprecated"))]
        idm={};rels=[];matrix=None;comps={};analytics={};strategies={}
        # Passe 1 : indexation de tous les objets, sans aucune dependance a l'ordre du bundle.
        for o in objs:
            ot=o.get("type","");aid=self._aid(o);oid=o.get("id","")
            if ot=="x-mitre-matrix":
                if not matrix:matrix=o;self.spec=o.get("x_mitre_attack_spec_version","")
            elif ot=="x-mitre-tactic" and aid:
                idm[oid]=aid;self.tactics[aid]={"id":aid,"name":o.get("name",""),"shortname":o.get("x_mitre_shortname",""),"description":o.get("description",""),"techniques":[]}
            elif ot=="attack-pattern" and aid:
                idm[oid]=aid;phases=[k["phase_name"] for k in o.get("kill_chain_phases",[]) if k.get("kill_chain_name")=="mitre-attack"]
                is_sub=bool(o.get("x_mitre_is_subtechnique",False))
                self.techniques[aid]={"id":aid,"name":o.get("name",""),"description":o.get("description",""),"platforms":o.get("x_mitre_platforms",[]),
                    "tactics":[],"phases":phases,"is_subtechnique":is_sub,"parent":"","subtechniques":[],"groups":[],"software":[],"mitigations":[],
                    "data_sources":[],"log_sources":[],"detection":"","detections":[],"url":self._url(o)}
            elif ot=="intrusion-set" and aid:
                idm[oid]=aid;self.groups[aid]={"id":aid,"name":o.get("name",""),"description":o.get("description",""),"aliases":o.get("aliases",[]),"techniques":[],"software":[],"url":self._url(o)}
            elif ot in("tool","malware") and aid:
                idm[oid]=aid;self.software[aid]={"id":aid,"name":o.get("name",""),"type":ot,"description":o.get("description",""),"platforms":o.get("x_mitre_platforms",[]),"aliases":o.get("x_mitre_aliases",o.get("aliases",[])),"techniques":[],"url":self._url(o)}
            elif ot=="course-of-action" and aid:
                idm[oid]=aid;self.mitigations[aid]={"id":aid,"name":o.get("name",""),"description":o.get("description",""),"techniques":[],"url":self._url(o)}
            elif ot=="x-mitre-data-component":comps[oid]=o
            elif ot=="x-mitre-analytic":analytics[oid]=o
            elif ot=="x-mitre-detection-strategy":strategies[oid]=o
            elif ot=="relationship":rels.append(o)
        # Ordre kill-chain lu dans la matrice officielle plutot que code en dur.
        self.order=[idm[r] for r in (matrix or {}).get("tactic_refs",[]) if r in idm and idm[r] in self.tactics] or sorted(self.tactics)
        # Passe 2 : rattachement technique -> tactique, toutes les tactiques etant connues.
        sn={t["shortname"]:tid for tid,t in self.tactics.items() if t["shortname"]}
        for tid,t in self.techniques.items():
            for p in t["phases"]:
                x=sn.get(p)
                if x and tid not in self.tactics[x]["techniques"]:
                    self.tactics[x]["techniques"].append(tid);t["tactics"].append(x)
        # Passe 3 : relations, tous les objets etant deja indexes.
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
        # Index inverse source de donnees -> techniques (composants, sources de logs et canaux).
        for tid,t in self.techniques.items():
            for label in set(t["data_sources"])|set(t["log_sources"]):
                self.datasources.setdefault(label,[])
                if tid not in self.datasources[label]:self.datasources[label].append(tid)
    def _attach_detection(self,tech,st,analytics,comps):
        entry={"id":self._aid(st),"name":st.get("name",""),"analytics":[]}
        for ar in st.get("x_mitre_analytic_refs",[]):
            a=analytics.get(ar)
            if not a:continue
            ls=[]
            for r in a.get("x_mitre_log_source_references",[]):
                nm=(r.get("name") or "").strip();ch=(r.get("channel") or "").strip()
                cn=comps.get(r.get("x_mitre_data_component_ref",""),{}).get("name","")
                ls.append({"component":cn,"source":nm,"channel":ch})
                if cn and cn not in tech["data_sources"]:tech["data_sources"].append(cn)
                for lab in (nm,f"{nm}:{ch}" if nm and ch else ""):
                    if lab and lab not in tech["log_sources"]:tech["log_sources"].append(lab)
            entry["analytics"].append({"name":a.get("name",""),"description":a.get("description",""),"platforms":a.get("x_mitre_platforms",[]),
                "log_sources":ls,"tuning":[m.get("field","") for m in a.get("x_mitre_mutable_elements",[]) if m.get("field")]})
        if not entry["analytics"] and not entry["name"]:return
        tech["detections"].append(entry)
        tech["detection"]="\n\n".join(f"{e['name']}: {x['description']}" for e in tech["detections"] for x in e["analytics"] if x["description"])

db=MitreDB()

TOOLS={}
def tool(name,desc,params=None):
    def deco(fn):
        props={};req=[]
        for pn,(pt,rq,pd) in(params or{}).items():
            props[pn]={"type":pt,"description":pd}
            if rq:req.append(pn)
        TOOLS[name]={"handler":fn,"schema":{"name":name,"description":desc,"inputSchema":{"type":"object","properties":props,"required":req}}}
        return fn
    return deco
def J(o):return json.dumps(o,ensure_ascii=False,indent=2)
def TID(q):
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
    """Tronque une liste en signalant explicitement la troncature."""
    return items[:n],{"shown":min(n,len(items)),"total":len(items),"truncated":len(items)>n}

@tool("mitre_stats","Statistiques de la base MITRE ATT&CK chargée.")
def mitre_stats():
    p=sum(1 for t in db.techniques.values() if not t["is_subtechnique"])
    a=db.age_days()
    return J({"source":db.source,"updated":db.updated,"age_days":a,"stale":bool(a is not None and a>STALE_DAYS),"attack_spec":db.spec,
        "tactics":len(db.tactics),"techniques":len(db.techniques),"parents":p,"subtechniques":len(db.techniques)-p,
        "groups":len(db.groups),"software":len(db.software),"mitigations":len(db.mitigations),"data_sources":len(db.datasources),
        "techniques_with_detection":sum(1 for t in db.techniques.values() if t["detections"])})

@tool("mitre_update","Re-télécharge la base MITRE Enterprise depuis GitHub.")
def mitre_update():return J(db.download())

@tool("mitre_tactics","Les tactiques ATT&CK dans l'ordre de la kill chain.")
def mitre_tactics():
    return J([{"id":tid,"name":db.tactics[tid]["name"],"description":db.tactics[tid]["description"][:200],"technique_count":len(db.tactics[tid]["techniques"])} for tid in db.order if tid in db.tactics])

@tool("mitre_tactic","Détails d'une tactique + ses techniques.",{"id":("string",True,"ex: TA0002 ou Execution")})
def mitre_tactic(id):
    t=resolve(db.tactics,id)
    if not t:return J({"error":f"'{id}' non trouvée"})
    techs=[{"id":tid,"name":db.techniques[tid]["name"],"subtechniques":len(db.techniques[tid]["subtechniques"])} for tid in t["techniques"] if tid in db.techniques and not db.techniques[tid]["is_subtechnique"]]
    return J({"id":t["id"],"name":t["name"],"description":t["description"],"technique_count":len(techs),"techniques":techs})

@tool("mitre_search","Recherche de techniques par mot-clé : nom, description, ID, source de données, canal de log (ex: 4688) ou texte de détection.",{"query":("string",True,"Mot-clé")})
def mitre_search(query):
    q=(query or "").strip().lower()
    if not q:return J({"query":query,"results":{"shown":0,"total":0,"truncated":False},"techniques":[]})
    res=[]
    for tid,t in db.techniques.items():
        n=t["name"].lower();s=0
        if q==tid.lower():s+=40
        elif q in tid.lower():s+=10
        if q==n:s+=20
        elif n.startswith(q):s+=8
        elif q in n:s+=5
        if q in t["description"].lower():s+=2
        hits=[d for d in t["data_sources"]+t["log_sources"] if q in d.lower()]
        if hits:s+=4
        if q in t["detection"].lower():s+=2
        if s>0:res.append({"id":tid,"name":t["name"],"description":t["description"][:250],"platforms":t["platforms"],
            "tactics":[db.tactics[x]["name"] for x in t["tactics"] if x in db.tactics],"is_subtechnique":t["is_subtechnique"],
            "matched_sources":sorted(hits)[:5],"score":s})
    res.sort(key=lambda x:(-x["score"],x["id"]))
    shown,meta=cut(res,25)
    return J({"query":query,"results":meta,"techniques":shown})

@tool("mitre_technique","Détails complets d'une technique : description, stratégies de détection et analytics, sources de données, groupes APT, software, mitigations, sous-techniques.",{"id":("string",True,"ex: T1059.001")})
def mitre_technique(id):
    t=technique(id)
    if not t:return J({"error":f"'{id}' non trouvée"})
    g,gm=cut(t["groups"],20);s,sm=cut(t["software"],20);m,mm=cut(t["mitigations"],15)
    return J({"id":t["id"],"name":t["name"],"description":t["description"],"url":t["url"],"platforms":t["platforms"],
        "tactics":[{"id":x,"name":db.tactics[x]["name"]} for x in t["tactics"] if x in db.tactics],"phases":t["phases"],
        "is_subtechnique":t["is_subtechnique"],"parent":t["parent"],
        "subtechniques_detail":[{"id":x,"name":db.techniques[x]["name"]} for x in t["subtechniques"] if x in db.techniques],
        "data_sources":t["data_sources"],"log_sources":t["log_sources"],"detection":t["detection"],"detections":t["detections"],
        "groups":gm,"groups_detail":[{"id":x,"name":db.groups[x]["name"],"aliases":db.groups[x]["aliases"][:5]} for x in g if x in db.groups],
        "software":sm,"software_detail":[{"id":x,"name":db.software[x]["name"],"type":db.software[x]["type"]} for x in s if x in db.software],
        "mitigations":mm,"mitigations_detail":[{"id":x,"name":db.mitigations[x]["name"],"description":db.mitigations[x]["description"][:300]} for x in m if x in db.mitigations]})

@tool("mitre_groups","Groupes APT. Sans argument: top 50 par nombre de techniques. Avec technique_id: groupes utilisant cette technique.",{"technique_id":("string",False,"ID technique (optionnel)")})
def mitre_groups(technique_id=""):
    if technique_id:
        t=technique(technique_id)
        if not t:return J({"error":f"'{technique_id}' non trouvée"})
        g,meta=cut(t["groups"],30)
        return J({"technique":t["id"],"results":meta,"groups":[{"id":x,"name":db.groups[x]["name"],"aliases":db.groups[x]["aliases"][:5]} for x in g if x in db.groups]})
    r=sorted(db.groups.values(),key=lambda g:(-len(g["techniques"]),g["id"]))
    g,meta=cut(r,50)
    return J({"results":meta,"groups":[{"id":x["id"],"name":x["name"],"aliases":x["aliases"][:5],"technique_count":len(x["techniques"])} for x in g]})

@tool("mitre_group","Détails d'un groupe APT, par ID, nom ou alias.",{"id":("string",True,"ex: G0016, APT29 ou Cozy Bear")})
def mitre_group(id):
    g=resolve(db.groups,id)
    if not g:return J({"error":f"'{id}' non trouvé"})
    t,tm=cut(g["techniques"],50);s,sm=cut(g["software"],20)
    return J({"id":g["id"],"name":g["name"],"aliases":g["aliases"],"description":g["description"],"url":g["url"],
        "techniques":tm,"techniques_detail":[{"id":x,"name":db.techniques[x]["name"],"tactics":[db.tactics[y]["name"] for y in db.techniques[x]["tactics"] if y in db.tactics]} for x in t if x in db.techniques],
        "software":sm,"software_detail":[{"id":x,"name":db.software[x]["name"],"type":db.software[x]["type"]} for x in s if x in db.software]})

@tool("mitre_software","Software/malware. Sans argument: top 50. Avec un ID de technique: les software associés. Avec un ID S**** ou un nom: la fiche détaillée.",{"technique_id":("string",False,"ID technique, ID software ou nom (optionnel)")})
def mitre_software(technique_id=""):
    q=(technique_id or "").strip()
    if q:
        t=technique(q)
        if t:
            s,meta=cut(t["software"],30)
            return J({"technique":t["id"],"results":meta,"software":[{"id":x,"name":db.software[x]["name"],"type":db.software[x]["type"]} for x in s if x in db.software]})
        sw=resolve(db.software,q)
        if sw:
            t2,tm=cut(sw["techniques"],50)
            return J({"id":sw["id"],"name":sw["name"],"type":sw["type"],"aliases":sw["aliases"],"platforms":sw["platforms"],"description":sw["description"],"url":sw["url"],
                "techniques":tm,"techniques_detail":[{"id":x,"name":db.techniques[x]["name"]} for x in t2 if x in db.techniques]})
        return J({"error":f"'{technique_id}' non trouvé"})
    r=sorted(db.software.values(),key=lambda s:(-len(s["techniques"]),s["id"]))
    s,meta=cut(r,50)
    return J({"results":meta,"software":[{"id":x["id"],"name":x["name"],"type":x["type"],"technique_count":len(x["techniques"])} for x in s]})

@tool("mitre_mitigations","Mitigations pour une technique.",{"technique_id":("string",True,"ex: T1059.001")})
def mitre_mitigations(technique_id):
    t=technique(technique_id)
    if not t:return J({"error":f"'{technique_id}' non trouvée"})
    return J({"technique":t["id"],"name":t["name"],"count":len(t["mitigations"]),
        "mitigations":[{"id":m,"name":db.mitigations[m]["name"],"description":db.mitigations[m]["description"],"url":db.mitigations[m]["url"]} for m in t["mitigations"] if m in db.mitigations]})

@tool("mitre_datasources","Techniques détectables à partir d'une source de données, d'un canal de log ou d'un identifiant d'événement.",{"query":("string",True,"ex: Process Creation, WinEventLog:Security, 4688, AWS:CloudTrail")})
def mitre_datasources(query):
    q=(query or "").strip().lower()
    if not q:return J({"query":query,"matched_sources":[],"matched_source_count":0,"results":{"shown":0,"total":0,"truncated":False},"techniques":[]})
    matches={dn:tids for dn,tids in db.datasources.items() if q in dn.lower()}
    techs={}
    for tids in matches.values():
        for tid in tids:
            if tid in db.techniques and tid not in techs:
                t=db.techniques[tid]
                techs[tid]={"id":tid,"name":t["name"],"tactics":[db.tactics[x]["name"] for x in t["tactics"] if x in db.tactics],"platforms":t["platforms"]}
    out,meta=cut(sorted(techs.values(),key=lambda x:x["id"]),50)
    return J({"query":query,"matched_sources":sorted(matches)[:40],"matched_source_count":len(matches),"results":meta,"techniques":out})

def run():
    if not db.ready:threading.Thread(target=db.ensure,daemon=True).start()
    log.info(f"MCP mcp-mitre: {len(TOOLS)} tools, {len(db.techniques)} techniques")
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

def handle(msg):
    if not isinstance(msg,dict):return None
    method,mid,params=msg.get("method",""),msg.get("id"),msg.get("params") or {}
    if mid is None:return None
    if method=="initialize":
        v=params.get("protocolVersion")
        return R(mid,{"protocolVersion":v if isinstance(v,str) else "2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"mcp-mitre","version":"1.0.0"}})
    if method=="tools/list":return R(mid,{"tools":[t["schema"] for t in TOOLS.values()]})
    if method=="tools/call":
        name,args=params.get("name",""),params.get("arguments") or {}
        t=TOOLS.get(name)
        if not t:return E(mid,-32602,f"Unknown: {name}")
        if not db.ensure():return R(mid,{"content":[{"type":"text","text":J({"error":"Base MITRE indisponible","source":db.source})}],"isError":True})
        try:return R(mid,{"content":[{"type":"text","text":t["handler"](**args)}]})
        except TypeError as e:return R(mid,{"content":[{"type":"text","text":J({"error":f"Arguments invalides: {e}"})}],"isError":True})
        except Exception as e:return R(mid,{"content":[{"type":"text","text":J({"error":str(e)})}],"isError":True})
    if method in("resources/list","prompts/list"):return R(mid,{method.split("/")[0]:[]})
    if method=="ping":return R(mid,{})
    return E(mid,-32601,f"Not found: {method}")
def R(mid,result):return{"jsonrpc":"2.0","id":mid,"result":result}
def E(mid,code,msg):return{"jsonrpc":"2.0","id":mid,"error":{"code":code,"message":msg}}

if __name__=="__main__":
    if "--help" in sys.argv:print(__doc__);sys.exit(0)
    if "--test" in sys.argv:
        db.ensure()
        print(f"MITRE: {db.source} (spec {db.spec or '?'})")
        print(f"  {len(db.tactics)} tactics, {len(db.techniques)} techniques")
        print(f"  {len(db.groups)} groups, {len(db.software)} software, {len(db.mitigations)} mitigations")
        print(f"  {len(db.datasources)} data sources, {sum(1 for t in db.techniques.values() if t['detections'])} techniques avec detection")
        print(f"  {sum(len(t['techniques']) for t in db.tactics.values())} liens tactique-technique, {sum(len(t['subtechniques']) for t in db.techniques.values())} liens parent-sous-technique")
        print(f"Tools ({len(TOOLS)}): {list(TOOLS.keys())}");sys.exit(0)
    run()
