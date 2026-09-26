# Cas 0 : Test du serveur MCP MITRE ATT&CK depuis VSCode avec GitHub Copilot

Ce scénario initial consiste à tester le serveur MCP MITRE ATT&CK en local avec GitHub Copilot (en mode agent) depuis VS Code.
Son but est de vérifier :
- que le serveur démarreque,
- que ses outils sont accessibles à l'agent,
- et que la skill est bien reconnue avant de passer aux scénarios plus avancés. 

À l'issue de ce cas, vous pourrez poser des questions ATT&CK en langage naturel à Copilot qui intérrogera le base MITRE ATT&CK.


## Prérequis

- **uv** installé (gestionnaire de paquets Python) — voir https://docs.astral.sh/uv/
- **VS Code** avec l'extension GitHub Copilot, connectée au compte hyrdo, et le **mode agent** activé.
- Un fichier **`pyproject.toml`** présent dans `serveur_mcp_MITRE/v2/` (il déclare les dépendances : `mcp`, `uvicorn`, `pyjwt`).
- La skill **`mitre-attack-assistant`** présente dans **`.github/skills/`**.


### 1. Récupérer le projet (git clone)

```bash
git clone <url-du-depot>
cd mcp-mitre-attack
```

### 2. Ouvrir le projet dans VS Code


```bash
code .
```

Ouvrir le dossier bien `mcp-mitre-attack/` (et non un sous-dossier) : pour aligner `.vscode/mcp.json` et `.github/skills/`.


### 3. Démarrer le serveur MCP

Depuis **Terminal Windows** :
```bash 
cd server_mcp 
cd v2/v2-2 #choisir la version
uv run mcp_mitre.py
```

Depuis VSCode : 
1. Ouvrir la palette de commandes : *Ctrl+Shift+P* (Windows / Linux) ou *Cmd+Shift+P* (macOS).
2. Taper puis choisir **`MCP: List Servers`**.
3. Sélectionner **`mitre`** → Start (ou Restart s'il était déjà lancé).
4. Pour suivre les logs : sélectionner le serveur → Show Output.

> Au premier démarrage, le serveur télécharge la base MITRE ATT&CK.

### 5. Ouvrir le chat Copilot et charger la skill
Dans VSCode : 
1. Ouvrir le chat Copilot : *Ctrl+Shift+I* (ou *Cmd+Shift+I* sur macOS).
2. Assurez-vous d'être en *mode agent*.
3. Tape **`@skills`** et sélectionne la skill **`mitre-attack-assistant`**.

> La skill s'active aussi automatiquement dès qu'une question touche à ATT&CK, mais la sélectionner explicitement garantit son utilisation.

### 3 types de requêtes à tester :

La skill couvre trois types d'usage. Voici un exemple de chacun :

**A. Expliquer une technique / une tactique**
```text
C'est quoi la technique T1003.001 (OS Credential Dumping : LSASS Memory) ?
```
```text
Explique la tactique TA0006 (Credential Access) et liste ses techniques.
```

**B. Mapper un comportement vers ATT&CK** (scénario, logs, commandes, rapport)
```text
Voici un extrait de logs : une tâche planifiée a été créée pour exécuter un
script à chaque ouverture de session, puis le processus lsass.exe a été lu en
mémoire. Mappe ce comportement sur MITRE ATT&CK (tactique → technique → sous-technique).
```
```text
Un acteur s'est connecté depuis un VPN externe avec un compte valide, puis a
désactivé l'antivirus. Donne le mapping ATT&CK correspondant.
```

**C. Assistance : mitigations et sources de détection**
```text
Quelles mitigations recommande ATT&CK pour la technique T1003.001 ?
```
```text
Quelles sources de données permettent de détecter T1059 (Command and Scripting Interpreter) ?
```

Si Copilot répond en s'appuyant sur les outils du serveur (identifiants ATT&CK exacts, version de la base citée).