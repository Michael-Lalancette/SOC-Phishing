# 🐟 Rapport d'Incident - [NOM_INCIDENT]

> 💡 Analyse d'une campagne de phishing [TYPE] ciblant [ORGANISATION/SECTEUR].

![email-screenshot](./images/email-screenshot.png)

---

## 1. 📌 Résumé Exécutif

### Contexte

Le [DATE], une alerte de sécurité a signalé un e-mail de phishing ciblant [CIBLE]. L'attaquant a usurpé l'identité de [EXPEDITEUR_USURPE] en exploitant [VECTEUR_EXPLOITATION].

Le message prétendait [PRETEXTE] et contenait [VECTEUR: lien/pièce jointe] vers [TYPE_MALWARE/URL].

L'exécution du fichier permettrait :
- **[MALWARE_1]** : [Capacités principales]
- **[MALWARE_2]** : [Capacités principales]
- **[MALWARE_3]** : [Capacités principales]

### Analyse de la Menace

**Échec des contrôles d'authentification** :
- SPF : [pass/fail/softfail/none] (IP `[IP]` [statut])
- DKIM : [pass/fail/none] ([détails])
- DMARC : [pass/fail/none] ([détails])

[Conclusion sur l'authentification et recommandations DMARC si applicable]

**Infrastructure malveillante identifiée** :
- Hébergement : [ASN] (`[IP]`)
- Distribution : [Familles de malware identifiées]
- C2 : [Domaine/IP C2]
- Exfiltration : [Canal utilisé]

### Sophistication de l'Attaque

- **[CARACTERISTIQUE_1]** : [Description]
- **[CARACTERISTIQUE_2]** : [Description]
- **[CARACTERISTIQUE_3]** : [Description]
- **[CARACTERISTIQUE_4]** : [Description]
- **[CARACTERISTIQUE_5]** : [Description]

### Actions Préventives Appliquées

**Blocage immédiat** :
- IPs malveillantes (`[IP_1]`, `[IP_2]`)
- Domaines C2 (`[DOMAINE_1]`, `[DOMAINE_2]`)
- URLs de distribution (`[URL_1]`, `[URL_2]`)
- Hashes des malwares identifiés

**Mesures de protection** :
- [Action 1]
- [Action 2]
- [Action 3]
- Surveillance renforcée activée ([DUREE])

**✅ Résultat** : [Statut final - menace neutralisée/compromission détectée/etc.]

### Conclusion

[Résumé de l'incident, leçons apprises, et importance des mesures préventives]

> 💡 [Point clé à retenir pour l'organisation]

---

## 2. 🔍 Analyse des Headers SMTP

### Trajet du Message

Le message suit un parcours [normal/atypique] :

```
[Fournisseur 1] ([domaine] - [IP])
  ↓
[Fournisseur 2] ([domaine] - [IP])
  ↓
[Fournisseur 3] ([domaine] - [IP])
  ↓
[Destination finale]
```

**Observation** : [Analyse du trajet et anomalies détectées]

### Résultats d'Authentification

| Protocole | Résultat | IP Concernée | Analyse |
|-----------|----------|--------------|---------|
| **SPF** | [résultat] | `[IP]` | [Analyse] |
| **DKIM** | [résultat] | `[IP]` | [Analyse] |
| **DMARC** | [résultat] | - | [Analyse] |

![headers-analysis](./images/headers.png)

**Conclusion** : [Synthèse de l'analyse d'authentification]

### Return-Path

```
From: [adresse]
Return-Path: [adresse]
```

[Analyse de l'alignement et implications pour l'authenticité]

---

## 3. 🔍 Analyse du Corps du Message

### Contenu

Le message imite [type de document/communication] avec les éléments suivants :
- **Sujet** : [Sujet exact]
- **Référence** : [Numéro de référence]
- **Date** : [Date mentionnée]
- **Montant/Détail** : [Informations clés]
- **Code d'accès fourni** : [Code si applicable]

### URL/Pièce Jointe Malveillante

```
[URL ou nom de fichier]
```

| Attribut | Valeur |
|----------|--------|
| Type | [Type de vecteur] |
| IP/Domaine hébergement | `[IP/Domaine]` |
| ASN | [ASN] |
| Port | [Port] |

### Techniques d'Ingénierie Sociale

1. **[Technique 1]** - [Description]
2. **[Technique 2]** - [Description]
3. **[Technique 3]** - [Description]
4. **[Technique 4]** - [Description]

---

## 4. 🔬 Analyse Statique

### Réputation de l'Infrastructure

**VirusTotal** : [Résumé des détections]

![virustotal](./images/virustotal.png)

**URLhaus/MalwareBazaar** : [Résumé des findings]

![urlhaus](./images/urlhaus.png)

**ASN** : [Détails ASN et réputation]

### Familles de Malware Identifiées

#### 1. [MALWARE_1]
- **SHA256** : `[hash]`
- **Fonction** : [Description]
- **Impact** : [Impact sur le système]
- **Capacités** : [Liste des capacités]
- **[Attribut spécifique]** : [Détail]

#### 2. [MALWARE_2]
- **SHA256** : `[hash]`
- **Fonction** : [Description]
- **Persistence** : [Mécanisme de persistence]
  - Fichier 1 : `[nom]` ([rôle])
  - Fichier 2 : `[nom]` ([rôle])
- **C2** : `[domaine/IP]` ([type])

#### 3. [MALWARE_3]
- **SHA256** : `[hash]`
- **Fonction** : [Description]
- **Exfiltration** : [Canal d'exfiltration]
- **[Identifiant]** : `[valeur]`

---

## 5. 🔬 Analyse Dynamique (Sandbox)

### Chaîne d'Infection

```
1. [Étape 1]
2. [Étape 2]
3. [Étape 3]
4. [Étape 4]
5. [Étape 5]
6. [Étape 6]
```

### Techniques d'Évasion

**[Technique d'évasion identifiée]** :
- [Détail 1]
- [Détail 2]
- Commande décodée : `[commande]`

![evasion-technique](./images/evasion.png)

### Persistence

**Clé de registre modifiée** :
```
[Chemin de registre complet]
```

[Description du mécanisme de persistence] :
1. `[fichier_1]` ([rôle])
2. `[fichier_2]` ([rôle])

---

## 6. 🏷️ Indicateurs de Compromission (IoCs)

### Adresses E-mail
```
[email_1] (usurpé)
[email_2]
```

### Adresses IP
```
[IP_1]       ([Description/Rôle])
[IP_2]       ([Description/Rôle])
[IP_3]       ([Description/Rôle])
```

### Domaines & URLs
```
# [Catégorie 1]
[domaine/URL_1]
[domaine/URL_2]
--------------------------------------------------------
# [Catégorie 2]
[domaine/URL_3]
[domaine/URL_4]
--------------------------------------------------------
# [Catégorie 3]
[domaine/URL_5]
[domaine/URL_6]
```

### Hashes SHA256
```
[hash_1]  ([Malware_1])
[hash_2]  ([Malware_2])
[hash_3]  ([Malware_3])
```

### Artefacts de Persistence
```
Registry: [Chemin]
Fichiers: [liste des fichiers]
```

### Identifiants Externes
```
[identifiant_1] ([Description])
[identifiant_2] ([Description])
```

---

## 7. 🧬 Mapping MITRE ATT&CK

| Tactic | Technique | ID | Détails |
|--------|-----------|-----|---------|
| [Tactic] | [Technique] | [TID] | [Description de l'implémentation] |
| [Tactic] | [Technique] | [TID] | [Description de l'implémentation] |
| [Tactic] | [Technique] | [TID] | [Description de l'implémentation] |
| [Tactic] | [Technique] | [TID] | [Description de l'implémentation] |
| [Tactic] | [Technique] | [TID] | [Description de l'implémentation] |

**Total** : [X] techniques identifiées

---

## 8. 🌐 Réponses aux Questions d'Investigation

### Question 1
**[Question posée]**

**Réponse** : `[Réponse]`

**Méthode** : [Méthodologie utilisée pour obtenir la réponse]

![question-1](./images/q1.png)

---

### Question 2
**[Question posée]**

**Réponse** : `[Réponse]`

**Méthode** : [Méthodologie utilisée pour obtenir la réponse]

---

### Question 3
**[Question posée]**

**Réponse** : `[Réponse]`

**Méthode** : [Méthodologie utilisée pour obtenir la réponse]

![question-3](./images/q3.png)

---

### Question 4
**[Question posée]**

**Réponse** : `[Réponse]`

**Méthode** : [Méthodologie utilisée pour obtenir la réponse]

---

### Question 5
**[Question posée]**

**Réponse** : `[Réponse]`

**Méthode** : [Méthodologie utilisée pour obtenir la réponse]

---

### Question 6
**[Question posée]**

**Réponse** : `[Réponse]`

**Méthode** : [Méthodologie utilisée pour obtenir la réponse]

---

### Question 7
**[Question posée]**

**Réponse** : `[Réponse]`

**Méthode** : [Méthodologie utilisée pour obtenir la réponse]

---

### Question 8
**[Question posée]**

**Réponse** : `[Réponse]`

**Méthode** : [Méthodologie utilisée pour obtenir la réponse]

---

### Question 9
**[Question posée]**

**Réponse** : `[Réponse]`

**Méthode** : [Méthodologie utilisée pour obtenir la réponse]

---

### Question 10
**[Question posée]**

**Réponse** : `[Réponse]`

**Méthode** : [Méthodologie utilisée pour obtenir la réponse]

---

## 9. 🧰 Outils Utilisés

| Catégorie | Outil | Usage |
|-----------|-------|-------|
| Email Analysis | [Outil] | [Usage spécifique] |
| Threat Intel | [Outil] | [Usage spécifique] |
| Threat Intel | [Outil] | [Usage spécifique] |
| Sandbox | [Outil] | [Usage spécifique] |
| Sandbox | [Outil] | [Usage spécifique] |
| Deobfuscation | [Outil] | [Usage spécifique] |
| Framework | [Outil] | [Usage spécifique] |

---

## 10. 📊 Références

**Source du cas** : [Lien vers la source]

**Documentation malware** :
- [Lien Malpedia/autre - Malware 1]
- [Lien Malpedia/autre - Malware 2]
- [Lien Malpedia/autre - Malware 3]

**Threat Intelligence** :
- URLhaus : [https://urlhaus.abuse.ch/](https://urlhaus.abuse.ch/)
- MalwareBazaar : [https://bazaar.abuse.ch/](https://bazaar.abuse.ch/)
- [Autres sources utilisées]

---

> ⚠️ **Disclaimer** : Ce document est à but éducatif. Ne manipulez pas d'artefacts malveillants sur des machines non isolées. Toutes les actions actives (HEAD, expansion d'URL, exécution de pièces jointes) doivent être faites dans une VM/sandbox isolée.

*Dernière modification : [DATE]*
