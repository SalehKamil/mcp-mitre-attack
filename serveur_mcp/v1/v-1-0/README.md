# MCP MITRE ATT&CK

Ce serveur MCP expose la base de connaissances MITRE ATT&CK Enterprise à un modèle de langage (LLM) compatible, ici Claude Desktop.

Au premier lancement, la base complète est téléchargée depuis le dépôt officiel GitHub de MITRE (environ 48 MB au format STIX), analysée, puis mise en cache localement sous forme condensée (environ 5 MB). Les lancements suivants sont instantanés. Le téléchargement se fait en arrière-plan : le serveur répond à son client dès le démarrage, même si la base n'est pas encore prête.

---

## Prérequis

Python 3.8 ou supérieur et un client MCP compatible (Claude Desktop). Aucune dépendance externe n'est requise.

---

## Installation et lancement

```bash
git clone https://github.com/hq-bac-a-sable/mcp-attack-framework.git
cd mcp-attack-framework
python mcp_mitre.py
```

Le script n'ayant aucune dépendance, il fonctionne aussi bien avec `uv` :

```bash
uv run mcp_mitre.py
```

Pour vérifier que la base est correctement chargée :

```bash
python mcp_mitre.py --test
```

La sortie attendue indique le nombre d'objets chargés et le nombre de liens reconstruits :

```
MITRE: github.com/mitre/cti (spec 3.3.0)
  15 tactics, 697 techniques
  176 groups, 825 software, 44 mitigations
  2795 data sources, 697 techniques avec detection
  872 liens tactique-technique, 475 liens parent-sous-technique
Tools (11): ['mitre_stats', 'mitre_update', ...]
```

`python mcp_mitre.py --help` affiche les options disponibles.

---

## Configuration Claude Desktop

Modifier votre fichier `claude_desktop_config.json` :

```json
{
  "mcpServers": {
    "mitre": {
      "command": "python",
      "args": ["C:\\chemin\\vers\\mcp_mitre.py"]
    }
  }
}
```

Emplacement du fichier :
- Windows : `%APPDATA%\Claude\claude_desktop_config.json`
- macOS : `~/Library/Application Support/Claude/claude_desktop_config.json`

Redémarrer Claude Desktop après modification. Les journaux du serveur sont écrits sur la sortie d'erreur standard et visibles dans les logs MCP du client.

---

## Outils MCP disponibles

| Outil | Description |
|---|---|
| `mitre_stats` | Statistiques générales de la base et fraîcheur du cache |
| `mitre_update` | Re-télécharge la base depuis GitHub |
| `mitre_tactics` | Les tactiques ATT&CK dans l'ordre de la kill chain |
| `mitre_tactic` | Détails d'une tactique et ses techniques |
| `mitre_search` | Recherche de techniques par mot-clé |
| `mitre_technique` | Détails complets d'une technique |
| `mitre_groups` | Groupes APT, filtrables par technique |
| `mitre_group` | Détails d'un groupe APT |
| `mitre_software` | Logiciels et malwares, filtrables par technique |
| `mitre_mitigations` | Mitigations pour une technique donnée |
| `mitre_datasources` | Techniques détectables par une source de données |

### Détail des fonctions

**`mitre_stats`** — Sans argument. Retourne la source, la date du dernier téléchargement, l'âge du cache en jours, la version de spécification ATT&CK et le décompte de chaque type d'objet. Le champ `stale` passe à `true` au-delà de 30 jours.

**`mitre_update`** — Sans argument. Force un nouveau téléchargement et reconstruit le cache. Le fichier n'est remplacé qu'une fois l'écriture terminée, un échec en cours de route ne corrompt donc pas le cache existant.

**`mitre_tactics`** — Sans argument. Retourne les tactiques dans l'ordre canonique de la kill chain, lu directement dans la matrice publiée par MITRE, avec le nombre de techniques rattachées à chacune.

**`mitre_tactic(id)`** — Accepte un identifiant (`TA0002`) ou un nom (`Execution`). Retourne la description de la tactique et la liste de ses techniques parentes avec leur nombre de sous-techniques.

**`mitre_search(query)`** — Recherche pondérée sur l'identifiant, le nom, la description, les sources de données, les canaux de journalisation et le texte des analytics de détection. Un identifiant d'événement comme `4688`, un nom de canal comme `WinEventLog:Security` ou `AWS:CloudTrail`, un nom de binaire comme `rundll32` sont donc des requêtes valides. Les correspondances exactes sur l'identifiant puis sur le nom sont priorisées. Retourne les 25 meilleurs résultats, avec un bloc `results` indiquant le nombre total de correspondances et si la liste a été tronquée.

**`mitre_technique(id)`** — Accepte `T1059.001`, `t1059.001` ou `T1059.1`, la numérotation des sous-techniques étant normalisée. Retourne la description, les tactiques de rattachement, les plateformes, la technique parente et les sous-techniques, les sources de données et canaux de logs associés, les stratégies de détection avec leurs analytics et leurs paramètres de réglage, ainsi que les groupes APT, logiciels et mitigations liés.

**`mitre_groups(technique_id)`** — Sans argument, retourne les 50 groupes les plus actifs par nombre de techniques. Avec un identifiant de technique, retourne les groupes connus pour l'utiliser.

**`mitre_group(id)`** — Accepte un identifiant (`G0016`), un nom (`APT29`) ou n'importe quel alias publié (`Cozy Bear`, `Midnight Blizzard`). Retourne la fiche du groupe, ses alias, ses techniques avec leur tactique, et ses logiciels.

**`mitre_software(technique_id)`** — Sans argument, retourne les 50 logiciels les plus répandus. Avec un identifiant de technique, retourne les logiciels qui l'utilisent. Avec un identifiant `S****` ou un nom (`Mimikatz`), retourne la fiche détaillée du logiciel.

**`mitre_mitigations(technique_id)`** — Retourne les mitigations officielles associées à une technique, avec leur description complète et leur URL.

**`mitre_datasources(query)`** — Recherche par sous-chaîne sur les composants de données, les sources de journalisation et les canaux. `Process Creation`, `WinEventLog:Security`, `4688`, `linux:syslog` ou `AWS:CloudTrail` sont des requêtes valides. Retourne les sources correspondantes et les techniques observables à partir de celles-ci.

### Conventions de réponse

Toutes les réponses sont du JSON. Les listes potentiellement longues sont tronquées et accompagnées d'un bloc indiquant le nombre d'éléments affichés, le total et si une troncature a eu lieu, afin que le modèle sache qu'il ne voit qu'une partie du résultat. Une entité introuvable retourne un objet `error` plutôt qu'une exception.

---

## Évaluation du prototype

Pour évaluer la qualité du mapping, il est recommandé de soumettre au modèle des logs réels ou simulés et d'observer sa capacité à identifier les techniques ATT&CK correspondantes. On peut utiliser des journaux d'événements Windows, des alertes SIEM ou des signaux réseau suspects, puis comparer les résultats obtenus avec les techniques attendues. Cette approche permet de mesurer concrètement la précision du tool calling, la pertinence du raisonnement et la capacité à reconstruire une kill chain complète à partir d'une séquence d'événements.

Le chemin le plus direct consiste à partir d'un identifiant d'événement observé et à remonter vers les techniques : un `4688` avec une ligne de commande suspecte, un `4624` de type 3 inhabituel, un appel CloudTrail atypique. Les analytics retournées par `mitre_technique` décrivent les conditions de détection et les éléments à ajuster pour limiter les faux positifs.

---

## Données

La base provient du dépôt officiel [github.com/mitre/cti](https://github.com/mitre/cti), au format STIX 2.1, domaine Enterprise ATT&CK uniquement.

Les objets révoqués et dépréciés sont écartés au chargement. Les relations `uses`, `mitigates`, `subtechnique-of` et `detects` sont reconstruites après indexation complète du bundle, de sorte que le résultat ne dépend pas de l'ordre dans lequel MITRE publie ses objets. La partie détection s'appuie sur les objets `x-mitre-detection-strategy`, `x-mitre-analytic` et `x-mitre-data-component`, qui portent les sources de journalisation et les canaux exploitables.

Le cache est écrit dans `MITRE_DB/enterprise.json` à côté du script. Ce chemin peut être redéfini par la variable d'environnement `MITRE_CACHE`. La mise à jour se fait via l'outil `mitre_update` ou en supprimant le fichier de cache.

---

## Limites connues

- Domaine Enterprise uniquement : ni Mobile, ni ICS.
- Les campagnes (`campaign`) ne sont pas exposées.
- La recherche est lexicale, sans correction orthographique ni synonymes : `powershell` fonctionne, `power shell` en deux mots ne renvoie rien.
- Le cache n'expire pas automatiquement ; `mitre_stats` signale simplement qu'il a plus de 30 jours.
