# Cas d'usage — Serveur MCP MITRE ATT&CK

## Présentation

Ce répertoire rassemble les **scénarios d'utilisation** du serveur MCP MITRE ATT&CK. Ils sont conçus comme une **progression** : on valide d'abord que le serveur fonctionne (cas 0), puis on enrichit peu à peu l'interface, les données et le contexte, jusqu'à la sécurisation de la chaîne de traitement elle-même.

Chaque cas dispose — ou disposera — de son propre dossier et de ses instructions. À ce stade, **seul le cas 0 est accessible** ; les **cas 1 à 5 sont en cours de conception et de développement**.

## Vue d'ensemble

| Cas | Sujet | Statut |
|---|---|---|
| [Cas 0](cas_0/) | Tester le serveur depuis VS Code (Copilot) | **Accessible** |
| Cas 1 | Utilisation depuis une interface de chat | En conception / développement |
| Cas 2 | Mapping sur un jeu de logs public | En conception / développement |
| Cas 3 | Connexion à un SIEM (Splunk) | En conception / développement |
| Cas 4 | Orchestration de plusieurs serveurs MCP (contexte Hydro-Québec) | En conception / développement |
| Cas 5 | Analyse du code via MITRE ATLAS (sécurisation) | En conception / développement |

---

### Cas 0 — Tester le serveur MCP depuis VS Code avec GitHub Copilot

**Statut : accessible** — [ouvrir le cas 0](cas_0/)

Scénario de départ et de **validation**. Il consiste à démarrer le serveur MCP en local (mode `stdio`) depuis VS Code et à l'interroger via GitHub Copilot, à l'aide de la skill `mitre-attack-assistant`. Objectif : confirmer que le serveur démarre, que ses outils sont accessibles à l'agent et que la skill est reconnue, **avant** d'aborder les scénarios plus avancés.

### Cas 1 — Utilisation depuis une interface de chat

**Statut : en cours de conception et de développement.** 

Ce cas généralise le cas 0 au-delà de l'éditeur : le serveur MCP est interrogé depuis une interface de chat. Le LLM répond aux questions ATT&CK en s'appuyant sur le protocole MCP. 

Objectif : offrir un point d'accès conversationnel portable au serveur.

### Cas 2 — Mapping sur un jeu de logs public

**Statut : en cours de conception et de développement.**

Ce cas ajoute un jeu de données de logs public afin que le LLM puisse réaliser le processus de mapping. 

Objectif : éprouver la qualité du mapping sur des données concrètes et reproductibles.

### Cas 3 — Connexion à un SIEM (Splunk)

**Statut : en cours de conception et de développement.**

Ce cas connecte des logs issus d'un SIEM (Splunk) pour les rendre exploitables par le LLM à travers le serveur MCP. On passe d'un jeu de données figé (cas 2) à une source opérationnelle.

Objectif : rapprocher le mapping ATT&CK des conditions réelles d'un centre des opérations de sécurité (SOC) pour évaluation du prototype MCP plus adéquate.

### Cas 4 — Orchestration de plusieurs serveurs MCP (contexte Hydro-Québec)

**Statut : en cours de conception et de développement.**

Ce cas relie le serveur MCP à **plusieurs serveurs MCP internes d'Hydro-Québec** afin de récupérer des données et de **fournir au LLM le contexte propre à Hydro-Québec**. Objectif : enrichir les réponses avec des informations spécifiques à l'organisation, au-delà du seul référentiel ATT&CK.

### Cas 5 — Analyse du code via MITRE ATLAS (sécurisation)

**Statut : en cours de conception et de développement.**

Ce cas met le projet face à lui-même : le LLM analyse le code du serveur MCP à l'aide du référentiel MITRE ATLAS (le cadre des menaces visant les systèmes d'intelligence artificielle) et propose des corrections et des améliorations. 

Objectif : sécuriser la chaîne de traitement IA elle-même, en cohérence avec l'objectif « sécuriser la pipeline avec MITRE ATLAS » du projet.

---

*Vous trouverez les schémas (draw.io) sont disponibles dans [ce même répèrtoire](./) et les instructions détaillées de chaque cas seront ajoutés au fur et à mesure de leur développement.*
