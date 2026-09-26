# Formats de sortie

> Chargé pour les intentions **A (Expliquer)**, **B (Mapper)** et **C (Assister)**.
> Gabarits alignés sur les recommandations de présentation CISA/MITRE. Tous les
> identifiants des exemples ci-dessous sont **illustratifs** : dans une vraie
> réponse, ils proviennent du serveur MCP.

---

## Format A — Explication d'une technique / tactique / mitigation

Pour « c'est quoi T1003.001 ? », « en quoi consiste Credential Access ? », etc.
Après appel à `get_technique` / `get_tactic` / `get_mitigation` :

```
**<ID> — <Nom exact renvoyé par l'outil>**  (matrice : Enterprise/ICS)

<Explication en 2-4 phrases, reformulée à partir de la description de l'outil.>

- Tactique(s) : <TAxxxx — nom>
- Plateformes : <si pertinent, d'après l'outil>
- Sous-techniques : <liste si la technique en a>
- Mitigations clés : <Mxxxx — nom> (si demandé / pertinent)
- Sources de détection : <si pertinent>

Version ATT&CK : <release> (source : mitre_stats).
```

Règles : reformuler la description (ne pas recopier de longs blocs) ; ne lister
que les champs réellement renvoyés par l'outil ; ne rien ajouter de mémoire.

---

## Format B — Mapping d'un comportement (format CISA)

Deux composantes complémentaires, comme recommandé par CISA : un **récit avec
mapping en ligne**, puis un **tableau de synthèse**.

### B.1 Récit avec mapping en ligne
Lier l'ID entre crochets directement dans la phrase qui décrit le comportement,
avec assez de contexte pour justifier le mapping.

> Exemple de style :
> « L'acteur a communiqué avec son infrastructure C2 en HTTP [T1071.001] sur le
> port 4444 [T1571]. »

(À préférer à une simple liste d'ID sans contexte : le « pourquoi » du mapping
doit être lisible.)

### B.2 Tableau de synthèse

| Tactique | Technique | ID | Usage (procédé observé) | Confiance | Recommandation (mitigation / détection) |
|---|---|---|---|---|---|
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | Dump mémoire de lsass.exe via comportement type procdump | Élevée | Protéger LSASS (M1043) ; surveiller l'accès à lsass par un compte non-système |
| Lateral Movement | Remote Services: RDP | T1021.001 | Déplacement latéral via session RDP | Moyenne | Restreindre RDP, MFA |

Colonnes :
- **Usage** : le procédé concret observé dans l'entrée (le « quoi »).
- **Confiance** : Élevée / Moyenne / Faible + (en note) la preuve qui la motive.
- **Recommandation** : mitigations `Mxxxx` et/ou pistes de détection issues de
  l'outil (`get_technique` renvoie les mitigations ; `get_datasources` aide pour
  la détection).

### B.3 Bloc final obligatoire

```
Lacunes / non mappé : <comportements ambigus ou non étayés, tactiques attendues
mais absentes — p. ex. aucun signe d'accès initial>.
Version ATT&CK : <release> (mitre_stats).
Matrices couvertes : Enterprise / ICS.
```

Ne jamais omettre les lacunes : signaler ce qui n'a pas pu être mappé fait
partie d'un mapping de qualité (évite le biais « occasions manquées »).

---

## Format C — Assistance ciblée (mitigations / détection)

Pour « quelles mitigations pour T1059 ? », « quelles techniques détecte la
source Process Creation ? » :

```
**Objet : <ID/technique ou source de données>**

Mitigations (via get_technique / get_mitigation) :
- <Mxxxx — nom> : <reformulation courte>
- ...

Détection / sources de données (via get_datasources) :
- <source> → techniques associées : <Txxxx, ...>

Version ATT&CK : <release> (mitre_stats).
```

---

## Règles transverses de présentation

1. **Identifiants entre crochets** dans le texte courant (`[T1566.002]`) — c'est
   la convention CISA/MITRE.
2. **Noms ATT&CK en anglais** (libellés canoniques) ; le texte explicatif en
   français.
3. **Reformuler**, ne pas recopier de longues descriptions de l'outil.
4. **Citer la version** ATT&CK dans toute réponse A, B ou C.
5. **Calibrer la confiance** : ne pas présenter un mapping incertain comme
   certain ; exposer la preuve.
6. **Signaler l'incertitude et les lacunes** explicitement plutôt que de combler
   par de la mémoire non vérifiée.
