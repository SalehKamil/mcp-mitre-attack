# Évaluation de modèles d'intelligence artificielle sur le classement de journaux dans MITRE ATT&CK

## 1. Introduction

Ce répertoire permet de refaire notre évaluation et d'obtenir les mêmes
résultats. L'évaluation mesure si un modèle d'intelligence artificielle sait
associer un journal d'attaque informatique à la bonne entrée du catalogue MITRE
ATT&CK, et ce qu'il gagne quand il peut consulter ce catalogue.

L'évaluation se fait avec quatre workflows. Chacun reprend le précédent et
ajoute une seule chose :

1. **Workflow 1 — modèle seul.** Le modèle répond de mémoire.
2. **Workflow 2 — modèle + serveur MCP.** Le modèle peut consulter le catalogue
   ATT&CK avant de répondre.
3. **Workflow 3 — modèle + serveur MCP + skill.** Le modèle reçoit en plus une
   méthode de travail écrite.
4. **Workflow 4 — modèle + serveur MCP + skill + cache.** Même chose que le
   workflow 3, avec le cache de prompt activé pour réduire le coût.

### Les mots à connaître

- **Modèle d'IA** : programme d'intelligence artificielle qui lit un texte et
  écrit une réponse (Claude, GPT, Gemini, DeepSeek, Kimi, Qwen).
- **Fournisseur** : entreprise qui met un modèle à disposition sur Internet
  (Anthropic, OpenAI, Google, DeepSeek, Moonshot, Alibaba).
- **MITRE ATT&CK** : catalogue public des comportements des attaquants
  informatiques. Chaque comportement porte un identifiant. Nous utilisons la
  version 19.2.
- **Tactique, technique, sous-technique** : les trois niveaux du catalogue. La
  tactique est le but de l'attaquant, la technique est le moyen utilisé, la
  sous-technique est une forme plus précise de la technique.
- **Matrice** : une partie du catalogue. **Enterprise** concerne les ordinateurs
  et serveurs d'une entreprise ; **ICS** concerne les systèmes industriels.
- **Journal** : fichier dans lequel un ordinateur ou un appareil enregistre ce
  qui s'y passe.
- **Échantillon** : un fichier de journaux qui correspond à une seule action
  d'attaque.
- **Vérité de terrain** : la liste des bonnes réponses, une par échantillon.
- **Exécution** : un échantillon envoyé une fois à un modèle. Chaque échantillon
  est envoyé trois fois, soit 126 exécutions pour les 42 échantillons.
- **Campagne** : toutes les exécutions d'un modèle avec un workflow.
- **Workflow** : suite d'étapes qui s'enchaînent automatiquement.
- **n8n** : logiciel qui crée et lance les workflows, dans un navigateur web.
- **Nœud** : une étape d'un workflow n8n. Un double-clic l'ouvre.
- **Clé API** : code secret donné par un fournisseur. Il permet aux workflows
  d'interroger ses modèles et sert à facturer l'utilisation.
- **Serveur MCP** : programme qui donne au modèle un accès direct au catalogue
  ATT&CK, par des outils. MCP (*Model Context Protocol*) est la règle commune
  qui permet à un modèle d'utiliser ces outils.
- **Outil** : fonction du serveur MCP que le modèle peut utiliser : chercher une
  technique, lire sa fiche, lister les tactiques.
- **Skill** : fichier texte ajouté aux consignes du modèle. Il décrit la méthode
  à suivre, étape par étape. Il ne contient aucune réponse.
- **Jeton** : petit morceau de texte. Les fournisseurs facturent au nombre de
  jetons lus et écrits par le modèle.
- **Cache de prompt** : service du fournisseur qui reconnaît une partie du texte
  déjà envoyée et la facture beaucoup moins cher. Le prompt est le texte
  envoyé au modèle.
- **Terminal** : fenêtre dans laquelle on tape des commandes. Sous Windows :
  l'Invite de commandes ou PowerShell.
- **uv** : outil qui lance les programmes Python du projet. Il installe tout
  seul ce dont ils ont besoin, y compris Python.

---

## 2. Le dataset

Le dataset contient **42 échantillons** : 28 viennent d'ordinateurs et de
serveurs d'entreprise (matrice Enterprise), 14 viennent d'un système industriel
(matrice ICS). Ils couvrent 13 tactiques, 36 techniques et 22 sous-techniques.
Les journaux ont été créés en laboratoire pour ce projet et n'ont jamais été
publiés : aucun modèle n'a pu les voir pendant son apprentissage.

Le dossier [`dataset/`](dataset/) contient les échantillons, la vérité de
terrain et le script `preparer_dataset.py`. La création du dataset, la liste des
bonnes réponses et l'utilisation du script sont expliquées dans
[`dataset/README.md`](dataset/README.md).

---

## 3. Les workflows

Les quatre workflows se trouvent dans ce répertoire :

- [`evaluation_llm.json`](evaluation_llm.json) — workflow 1, modèle seul ;
- [`evaluation_llm_mcp.json`](evaluation_llm_mcp.json) — workflow 2, avec le
  serveur MCP ;
- [`evaluation_llm_mcp_skill.json`](evaluation_llm_mcp_skill.json) — workflow
  3, avec le serveur MCP et le skill ;
- [`evaluation_llm_mcp_skill_cache.json`](evaluation_llm_mcp_skill_cache.json)
  — workflow 4, avec le serveur MCP, le skill et le cache.

Tous les modèles peuvent être testés avec les quatre workflows.

### 3.1 Ce que fait chaque workflow

**Workflow 1 — modèle seul.** Le workflow envoie chaque échantillon au modèle
avec des consignes. Le modèle doit répondre par la tactique, la technique et la
sous-technique, ainsi que le passage du journal qui justifie sa réponse. Il
répond de mémoire, en un seul échange.

**Workflow 2 — ajout du serveur MCP.** Avant de répondre, le modèle peut
utiliser les outils du serveur MCP pour chercher dans le catalogue ATT&CK et
vérifier ses réponses. Le serveur ne renvoie que des identifiants qui existent
dans la version 19.2 du catalogue. Le modèle doit utiliser au moins un outil.
Il a droit à huit échanges au maximum avec le serveur avant de donner sa
réponse. Un paragraphe est ajouté à ses consignes pour lui demander d'utiliser
les outils.

**Workflow 3 — ajout du skill.** Le contenu du fichier `SKILL.md` est ajouté aux
consignes du modèle. Il décrit une méthode en neuf étapes : lister les outils,
isoler le passage exact du journal, fixer la matrice, chercher avec des
mots-clés précis, lire la fiche des deux ou trois meilleures réponses possibles,
choisir entre elles selon des règles, faire six vérifications, ne pas répondre
si les informations manquent, puis répondre dans la forme demandée. Le
paragraphe ajouté dans le workflow 2 est retiré, pour que seul le skill guide
le modèle.

**Workflow 4 — ajout du cache.** Identique au workflow 3, avec le cache de
prompt activé. À chaque échange, le modèle relit tout ce qui a déjà été envoyé ;
le cache permet de payer cette partie beaucoup moins cher. Le modèle reçoit
exactement les mêmes informations qu'avec le workflow 3.

Chaque workflow enregistre les réponses dans le dossier `resultats`, un fichier
par modèle :

- workflows 1 et 2 : `resultats__<modele>.jsonl` ;
- workflow 3 : `resultats__<modele>_skill.jsonl` ;
- workflow 4 : `resultats__<modele>_skill_cache.jsonl`.

`<modele>` est remplacé par le nom du modèle testé.

### 3.2 Refaire l'évaluation, étape par étape

#### Étape 1 — Installer les logiciels

Installez sur votre ordinateur :

1. **Node.js**, version 18 ou plus récente, depuis nodejs.org. n8n en a besoin.
2. **uv**. Ouvrez un terminal et tapez la commande qui correspond à votre
   système :

   ```bash
   # Windows (PowerShell)
   powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

   # Linux ou macOS
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

   Fermez ensuite le terminal et ouvrez-en un nouveau.
3. **Google Cloud CLI**, seulement si vous testez les modèles Gemini avec la
   méthode A (étape 6). Téléchargement : cloud.google.com/sdk/docs/install.

n8n n'a pas besoin d'être installé à l'avance : la commande de l'étape 4 le
télécharge au premier lancement. Utilisez n8n sur votre ordinateur et non la
version en ligne (*n8n Cloud*), qui ne peut pas lire vos fichiers.

#### Étape 2 — Exécuter le script `preparer_dataset.py`

Ce script est **obligatoire avant tout lancement**, quel que soit le workflow.
Il copie dans le dossier de travail de n8n, `.n8n-files`, tout ce dont les
workflows ont besoin :

- les 42 échantillons ;
- le fichier du skill, `SKILL.md`, utilisé par les workflows 3 et 4 ;
- le fichier d'autorisation Google, si vous testez Gemini avec la méthode A
  (étape 6).

n8n ne peut lire que les fichiers de ce dossier. Sans ce script, les workflows
ne trouvent ni les échantillons ni le skill.

Dans un terminal ouvert dans le dossier `dataset`, tapez :

```bash
uv run preparer_dataset.py
```

À la fin, le script affiche le chemin du dossier `.n8n-files` qu'il a utilisé.
Notez-le : il vous servira à l'étape 5.

Vérifiez ensuite qu'un dossier `resultats` existe dans `.n8n-files`, et
créez-le s'il manque. Les workflows y enregistrent les réponses. Ils créent
eux-mêmes les fichiers de résultats, mais pas le dossier. Le détail de ce script est expliqué
dans [`dataset/README.md`](dataset/README.md).

Si vous testez Gemini avec la méthode A, faites d'abord l'étape 6, puis
relancez ce script pour qu'il copie le fichier d'autorisation Google.

#### Étape 3 — Lancer le serveur MCP (workflows 2, 3 et 4)

Les workflows 2, 3 et 4 ont besoin du serveur MCP MITRE ATT&CK. Il doit
fonctionner pendant toute la campagne. Son installation et son fonctionnement
sont décrits dans son propre README.

1. Ouvrez un terminal dans le dossier du serveur MCP.
2. Vérifiez le catalogue :

   ```bash
   uv run mcp_mitre.py --test
   ```

   Au premier lancement, le serveur télécharge le catalogue ATT&CK, ce qui peut
   prendre quelques minutes. La commande doit se terminer par `OK`. Si elle
   affiche `ECHEC`, le catalogue est incomplet : ne lancez pas de campagne.
3. Démarrez le serveur :

   ```bash
   uv run mcp_mitre.py --http
   ```

   **Laissez ce terminal ouvert.** Si vous le fermez, le serveur s'arrête.
4. Vérifiez que le serveur répond. Dans un second terminal, tapez :

   ```bash
   curl http://127.0.0.1:8733/healthz
   ```

   La réponse doit contenir `"status": "ok"` et `"ready": true`.

Utilisez toujours l'adresse `127.0.0.1` et jamais `localhost` : avec
`localhost`, la connexion peut échouer même si le serveur fonctionne.

#### Étape 4 — Lancer n8n et importer le workflow

1. Ouvrez un terminal et placez-vous dans votre dossier personnel, puis lancez
   n8n :

   ```bash
   # Windows
   cd %USERPROFILE%
   npx n8n

   # Linux ou macOS
   cd ~
   npx n8n
   ```

2. n8n affiche une adresse web. Ouvrez-la dans votre navigateur. **Laissez ce
   terminal ouvert** pendant toute la campagne.
3. Dans n8n, ouvrez le menu **Workflows**, choisissez **Import from File**, puis
   sélectionnez le fichier du workflow à tester.

Si n8n s'arrête pendant une longue campagne à cause d'un manque de mémoire,
relancez-le avec plus de mémoire : tapez
`set NODE_OPTIONS=--max-old-space-size=4096` sous Windows, ou
`export NODE_OPTIONS=--max-old-space-size=4096` sous Linux et macOS, puis
`npx n8n`.

#### Étape 5 — Modifier le workflow

Les quatre workflows sont fournis sans clé API et sans modèle activé. **Dans
chacun des quatre workflows**, faites les modifications suivantes.

**1. Ajouter les clés API.** Ouvrez le nœud `Configuration`. En haut se trouve
ce bloc :

```js
const CLES = {
  anthropic:  "COLLER_CLE_ANTHROPIC",   // console.anthropic.com
  openai:     "COLLER_CLE_OPENAI",      // platform.openai.com
  google:     "COLLER_CLE_GEMINI",      // aistudio.google.com — METHODE B uniquement
  agregateur: "COLLER_CLE_AGREGATEUR",  // conserve au cas ou
  deepseek:   "COLLER_CLE_DEEPSEEK",    // platform.deepseek.com
  qwen:       "COLLER_CLE_QWEN",        // Alibaba Cloud Model Studio (DashScope)
  kimi:       "COLLER_CLE_KIMI",        // platform.moonshot.ai
};
```

Remplacez `COLLER_CLE_…` par votre clé, entre les guillemets, pour chaque
fournisseur dont vous testez un modèle :

- `anthropic` pour Claude Opus 4.8 et Claude Sonnet 5 — clé à créer sur
  console.anthropic.com ;
- `openai` pour GPT-5.6 Sol et GPT-5.6 Luna — sur platform.openai.com ;
- `google` pour Gemini, **seulement avec la méthode B** (étape 6) — sur
  aistudio.google.com ;
- `kimi` pour Kimi K3 — sur platform.moonshot.ai ;
- `deepseek` pour DeepSeek V4 Pro et DeepSeek V4 Flash — sur
  platform.deepseek.com ;
- `qwen` pour Qwen3.8 — sur Alibaba Cloud Model Studio, service DashScope,
  version internationale.

La ligne `agregateur` n'est plus utilisée : laissez-la telle quelle. Chaque
compte doit disposer d'un crédit ou d'un moyen de paiement, sinon les demandes
sont refusées. Si une clé reste à `COLLER_…` pour un modèle activé, la campagne
s'arrête dès le départ.

**2. Indiquer le dossier de travail.** Toujours dans le nœud `Configuration`,
trouvez la ligne :

```js
const RACINE_MANUELLE = "C:/Users/<nom_du_user>/.n8n-files";
```

Remplacez ce chemin par celui affiché par `preparer_dataset.py` à l'étape 2.
Vous pouvez aussi écrire `""` à la place du chemin, si vous avez lancé n8n
depuis votre dossier personnel comme à l'étape 4 : le workflow trouve alors le
dossier tout seul. Si `<nom_du_user>` reste dans le chemin, la campagne
s'arrête avec le message « Aucun échantillon lu ».

**3. Activer les modèles à tester.** Ouvrez le nœud `Preparer les iterations`.
Il contient la liste des dix modèles, tous marqués `actif:false`. Pour chaque
modèle à tester, remplacez `actif:false` par `actif:true` :

```js
{ actif:true,  fournisseur:"anthropic", modele:"claude-opus-4-8", ... },
{ actif:false, fournisseur:"anthropic", modele:"claude-sonnet-5", ... },
```

Vous pouvez activer plusieurs modèles : ils sont testés l'un après l'autre,
chacun dans son propre fichier de résultats. Si aucun modèle n'est activé, la
campagne s'arrête avec le message « Aucun modèle actif ».

Dans le nœud `Configuration`, laissez `MODELE_FORCE = ""`. Si cette ligne
contient un nom de modèle, le workflow ignore les choix `actif`.

**4. Pour les workflows 2, 3 et 4 : vérifier la version du serveur.** Dans le
nœud `Configuration`, l'option `mcp_version_attendue` indique la version du
serveur MCP exigée, `"2.2.2"`. Si le serveur lancé à l'étape 3 n'a pas cette
version, la campagne s'arrête dès le départ. Pour obtenir les mêmes résultats
que nous, lisez la partie 3.3.

**5. Pour les modèles Gemini : indiquer le projet Google.** Seulement avec la
méthode A (étape 6). Dans le nœud `Configuration`, remplacez
`id_projet_vertex_google` par l'identifiant de votre projet Google Cloud :

```js
const PROJET_GCP = "id_projet_vertex_google";
```

Les autres réglages du nœud `Configuration` sont ceux de nos tests. Ne les
changez pas si vous voulez obtenir les mêmes résultats.

#### Étape 6 — Pour les modèles Gemini seulement : choisir une méthode d'accès

Google propose deux façons d'utiliser Gemini. Au moment de nos tests, les
conditions étaient les suivantes ; vérifiez-les avant de commencer, car elles
peuvent changer :

- avec **Google AI Studio** (méthode B), il faut payer à l'avance, au minimum
  10 $, et les crédits gratuits de Google Cloud ne s'appliquent pas ;
- avec **Vertex AI** (méthode A), les crédits gratuits de Google Cloud
  s'appliquent.

Nos tests utilisent la méthode A.

**Méthode A — Vertex AI, avec les crédits gratuits de Google Cloud.** Il n'y a
pas de clé API : le workflow utilise un fichier d'autorisation Google et s'en
sert tout seul avant chaque demande.

1. Créez un compte sur cloud.google.com/free avec un compte Google qui n'a
   jamais servi sur Google Cloud. Vous recevez 300 $ de crédits gratuits,
   valables environ 90 jours. Google demande une carte bancaire pour vérifier
   votre identité, mais ne la débite pas automatiquement.
2. Dans un terminal, connectez-vous à votre compte Google :

   ```bash
   gcloud auth login
   ```

3. Affichez vos projets et notez l'identifiant de celui qui est lié aux crédits
   gratuits (colonne `PROJECT_ID`) :

   ```bash
   gcloud projects list
   ```

4. Choisissez ce projet et activez Vertex AI, en remplaçant `<PROJECT_ID>` par
   votre identifiant :

   ```bash
   gcloud config set project <PROJECT_ID>
   gcloud services enable aiplatform.googleapis.com --project=<PROJECT_ID>
   ```

5. Créez le fichier d'autorisation. La commande ouvre votre navigateur :

   ```bash
   gcloud auth application-default login
   ```

6. Vérifiez que l'autorisation fonctionne. La commande doit afficher un long
   code :

   ```bash
   gcloud auth application-default print-access-token
   ```

7. Relancez `preparer_dataset.py` (étape 2) : il copie le fichier
   d'autorisation dans `.n8n-files`.
8. Dans le workflow, indiquez l'identifiant du projet (étape 5, point 5) et
   activez les modèles `google/gemini-3.1-pro-preview` et
   `google/gemini-3.8-flash` (étape 5, point 3).

Pour suivre vos crédits, ouvrez console.cloud.google.com, rubrique
**Facturation** :

1. **Crédits** affiche le montant qu'il vous reste.
2. **Rapports** affiche vos dépenses. Choisissez le service *Vertex AI* pour ne
   voir que Gemini.
3. **Budgets et alertes** permet de créer un budget. Google vous envoie un
   courriel quand vos dépenses approchent de ce budget.

À la fin de la période gratuite, quand les crédits sont épuisés ou après 90
jours, Google suspend les services tant que vous n'avez pas activé un compte
payant. Rien n'est débité sans votre accord.

**Méthode B — Google AI Studio, avec une clé payée à l'avance.**

1. Créez une clé sur aistudio.google.com/app/apikey.
2. Achetez au moins 10 $ de crédit sur aistudio.google.com. Sans crédit, les
   demandes sont refusées avec l'erreur `429 RESOURCE_EXHAUSTED`.
3. Collez la clé sur la ligne `google` du nœud `Configuration` (étape 5,
   point 1).
4. Dans le nœud `Preparer les iterations`, laissez les modèles
   `google/gemini-…` en `actif:false`. Juste en dessous se trouvent les deux
   modèles de la méthode B, désactivés : leurs lignes commencent par `//`.
   Supprimez ces `//` pour les activer.

#### Étape 7 — Faire un essai

1. Dans le nœud `Configuration`, mettez `limite_samples: 4` : seuls quatre
   échantillons seront testés.
2. Mettez aussi `suffixe_sortie: "_essai"` : l'essai sera enregistré dans un
   fichier à part.
3. Lancez le workflow avec le bouton d'exécution de n8n (*Execute workflow* ou
   *Test workflow*, selon la version de n8n).
4. Ouvrez le fichier de résultats dans `.n8n-files/resultats` et vérifiez que
   les lignes contiennent `"statut": "ok"`.

#### Étape 8 — Lancer la campagne complète

1. Remettez `limite_samples: 0` (tous les échantillons) et la valeur d'origine
   de `suffixe_sortie`.
2. Relancez le workflow.
3. Laissez les terminaux de n8n et du serveur MCP ouverts jusqu'à la fin.
4. À la fin, ouvrez le nœud `Synthese de campagne`. Il indique, pour chaque
   modèle, combien d'exécutions ont réussi et combien ont échoué.

Chaque réponse est écrite dans le fichier de résultats dès qu'elle arrive. Si
une panne survient, seule l'exécution en cours est perdue.

Pour relancer une campagne :

- **workflows 3 et 4** : relancez-les simplement. Ils sautent les exécutions
  déjà réussies et s'arrêtent avec le message « campagne déjà complète » si
  tout est fait ;
- **workflows 1 et 2** : renommez d'abord le fichier de résultats, ou changez
  `suffixe_sortie`. Sinon, les nouvelles réponses s'ajoutent aux anciennes et
  certaines exécutions sont comptées deux fois.

#### Étape 9 — Calculer les scores

Le script [`calculer_metriques.py`](calculer_metriques.py) compare les réponses
des modèles à la vérité de terrain et calcule les scores. Dans un terminal
ouvert dans ce répertoire, tapez :

```bash
uv run calculer_metriques.py
```

Le script pose trois questions :

1. **Le workflow à évaluer** : tapez `1`, `2`, `3` ou `4`.
2. **Le dossier des résultats** : appuyez sur Entrée pour garder le dossier
   proposé, `.n8n-files/resultats`.
3. **Les modèles** : tous, ou seulement certains.

Le script trouve seul la vérité de terrain. Au premier lancement, il télécharge
le catalogue ATT&CK, ce qui demande une connexion à Internet. Il produit un
rapport texte et un fichier CSV, qui s'ouvre dans un tableur. Pour obtenir
aussi un fichier Excel, lancez-le avec `uv run --with openpyxl
calculer_metriques.py`. Pour calculer les coûts en dollars, placez à côté du
script un fichier `tarifs.json` qui indique le prix des modèles.

Toutes les options du script sont décrites au début du fichier
`calculer_metriques.py`.

### 3.3 Obtenir les mêmes résultats que nous

Pour refaire exactement nos campagnes :

1. Testez **Claude Opus 4.8** (`claude-opus-4-8`) avec les workflows 2, 3 et 4,
   et les dix modèles avec le workflow 1.
2. Utilisez les **42 échantillons** (`limite_samples: 0`) et **trois
   exécutions** par échantillon (`runs_par_question: 3`).
3. Ne changez pas les autres réglages du nœud `Configuration`.
4. Pour les workflows 2, 3 et 4, utilisez la **version 2.2.1 du serveur MCP**,
   celle de nos campagnes, et remplacez `"2.2.2"` par `"2.2.1"` dans l'option
   `mcp_version_attendue`. La version 2.2.2 donne les mêmes réponses sur le
   catalogue ATT&CK ; seules les descriptions de trois outils du catalogue
   interne diffèrent.
5. Calculez les scores avec la **version 19.2** du catalogue, qui est la valeur
   par défaut du script `calculer_metriques.py`.

Certains fournisseurs, dont Anthropic, n'acceptent pas le réglage qui rend les
réponses d'un modèle plus régulières. Les réponses peuvent donc varier un peu
d'une campagne à l'autre, et les scores avec elles.

### 3.4 En cas de problème

- **« Aucun modèle actif »** : aucun modèle n'est en `actif:true`. Activez-en au
  moins un (étape 5, point 3).
- **« Modèle(s) non configuré(s) »** : la clé API d'un modèle activé est restée
  à `COLLER_…`. Collez la clé (étape 5, point 1).
- **« Aucun échantillon lu »** : le chemin du dossier de travail est faux, ou
  `preparer_dataset.py` n'a pas été exécuté. Corrigez `RACINE_MANUELLE` (étape
  5, point 2) et exécutez le script (étape 2).
- **« Access to the file is not allowed »** : un fichier se trouve en dehors du
  dossier `.n8n-files`. Relancez `preparer_dataset.py`.
- **La campagne tourne mais aucun fichier de résultats n'apparaît** : le dossier
  `resultats` n'existe pas. Créez-le dans `.n8n-files`.
- **« Serveur MCP injoignable »** : le serveur n'est pas démarré, ou l'adresse
  utilise `localhost`. Refaites l'étape 3.
- **« Serveur MCP en version … »** : la version du serveur ne correspond pas à
  `mcp_version_attendue`. Lancez la bonne version du serveur, ou corrigez
  l'option (étape 5, point 4).
- **« MODELE_FORCE … vise un modèle marqué actif:false »** : remettez
  `MODELE_FORCE = ""` dans le nœud `Configuration`.
- **« campagne déjà complète »** : toutes les exécutions sont déjà faites.
  Renommez le fichier de résultats pour recommencer.
- **Erreur `429 RESOURCE_EXHAUSTED` avec Gemini** : le crédit Google AI Studio
  est épuisé (méthode B).
- **Erreurs `429` répétées avec Kimi** : un compte Moonshot non rechargé est
  limité à trois demandes par minute. Le workflow attend déjà 21 secondes entre
  deux demandes ; rechargez le compte si les erreurs continuent.
- **Erreur `401 invalid_api_key`** : la clé API est fausse. Vérifiez-la et
  recollez-la.

---

## 4. Résultats

Modèle Claude Opus 4.8, 126 exécutions par workflow :

| Workflow | F1 technique | F1 tactique | F1 sous-technique | F1 technique ICS | Stabilité | Coût |
|---|---|---|---|---|---|---|
| 1. Modèle seul | 0,563 | 0,587 | 0,636 | 0,262 | 76,2 % | 4,63 $ |
| 2. + serveur MCP | 0,706 | 0,802 | 0,758 | 0,524 | 71,4 % | 31,32 $ |
| 3. + skill | 0,738 | 0,873 | 0,758 | 0,500 | 85,7 % | 45,71 $ |
| 4. + skill + cache | 0,730 | 0,865 | 0,758 | 0,500 | 83,3 % | 16,23 $ |

- **F1** : score de 0 à 1 qui mesure la justesse des réponses à un niveau ; 1
  veut dire que toutes les réponses sont justes.
- **F1 technique ICS** : le score au niveau technique, sur les seuls
  échantillons industriels.
- **Stabilité** : part des échantillons pour lesquels les trois exécutions
  donnent la même réponse.
- **Coût** : prix total des 126 exécutions, selon les tarifs du 16 septembre
  2026.

Les résultats détaillés se trouvent dans le dossier [`rapport/`](rapport/).
