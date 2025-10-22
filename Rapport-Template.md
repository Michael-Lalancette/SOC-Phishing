# 📋 Rapport d'Incident - Analyse de Phishing

> **Modèle de rapport pour documenter les incidents de phishing détectés par le SOC**

---

## 📊 Informations générales

| **Champ** | **Détails** |
|-----------|-------------|
| **ID Incident** | INC-YYYY-XXXX |
| **Date de réception** | YYYY-MM-DD HH:MM UTC |
| **Date de détection** | YYYY-MM-DD HH:MM UTC |
| **Date d'analyse** | YYYY-MM-DD HH:MM UTC |
| **Analyste(s)** | Nom(s) de l'analyste / Équipe |
| **Niveau de sévérité** | 🟢 Faible / 🟡 Moyen / 🟠 Élevé / 🔴 Critique |
| **Statut** | 🔵 En cours / 🟢 Résolu / 🟡 En surveillance / 🔴 Escalade |
| **Type d'attaque** | Spearphishing / Credential Harvesting / Malware / BEC / Autre |

---

## 🎯 Résumé exécutif

### Description de l'incident
> *[Décrire en 2-3 phrases la nature de l'attaque, le vecteur utilisé et l'objectif apparent de l'attaquant]*

**Exemple :** Un e-mail de phishing se faisant passer pour [Organisation/Service] a été envoyé à [X] utilisateurs. Le message contenait [lien malveillant/pièce jointe] visant à [voler des credentials/installer un malware]. L'attaque a été détectée par [mécanisme de détection] et [X] utilisateurs ont interagi avec le contenu malveillant.

### Impact
- **Utilisateurs ciblés** : [Nombre] employés
- **Utilisateurs compromis** : [Nombre] confirmés
- **Données exposées** : [Type de données] / Aucune
- **Systèmes affectés** : [Postes de travail / Serveurs / Aucun]

### Niveau de sophistication
- [ ] 🟢 **Faible** : Phishing générique, facilement détectable
- [ ] 🟡 **Moyen** : Ciblage sectoriel, quelques personnalisations
- [ ] 🟠 **Élevé** : Spear-phishing ciblé, forte personnalisation
- [ ] 🔴 **Critique** : APT présumée, techniques avancées, zero-day

### Actions immédiates prises
> *[Résumer en bullet points les actions de containment et de remédiation]*

- ✅ Blocage des IoCs (IPs, domaines, URLs)
- ✅ Quarantaine des e-mails similaires
- ✅ Réinitialisation des credentials compromis
- ✅ Notification des utilisateurs ciblés

---

## 📧 Analyse de l'e-mail

### Métadonnées de base

| **Champ** | **Valeur** |
|-----------|------------|
| **Sujet** | [Sujet du message] |
| **Expéditeur affiché** | [Nom] <adresse@domaine.com> |
| **Expéditeur réel (Return-Path)** | adresse@domaine.com |
| **Reply-To** | [Si différent] |
| **Date d'envoi** | YYYY-MM-DD HH:MM UTC |
| **Message-ID** | <id@serveur.com> |
| **Destinataires** | [Liste ou nombre] |

### Analyse des headers SMTP

#### Chemin d'envoi (Received hops)
```
[Copier les headers Received du plus ancien au plus récent]

Received: from [serveur1] by [serveur2]
Received: from [serveur2] by [serveur3]
...
```

#### Résultats d'authentification

| **Protocole** | **Résultat** | **Détails** |
|---------------|--------------|-------------|
| **SPF** | ✅ Pass / ❌ Fail / ⚠️ Softfail / ❓ None | [Détails du résultat] |
| **DKIM** | ✅ Pass / ❌ Fail / ❓ None | [Signature et domaine] |
| **DMARC** | ✅ Pass / ❌ Fail / ❓ None | [Politique appliquée] |

#### Adresses IP impliquées

| **IP** | **Géolocalisation** | **Réputation** | **Notes** |
|--------|---------------------|----------------|-----------|
| X.X.X.X | Pays, Ville | ✅ Clean / ⚠️ Suspect / ❌ Malveillant | [ASN, Fournisseur, etc.] |

#### 🚩 Red Flags identifiés dans les headers
- [ ] Incohérence entre From et Return-Path
- [ ] Échec SPF/DKIM/DMARC
- [ ] IP d'origine suspecte ou blacklistée
- [ ] Reply-To différent de l'expéditeur
- [ ] Reverse DNS incohérent
- [ ] Faux headers ajoutés (X-Virus-Scan, etc.)
- [ ] Timestamps anormaux ou incohérents

**Détails :**
> *[Expliquer les anomalies détectées]*

---

## 📝 Analyse du contenu

### Corps du message

**Langue** : [Français / Anglais / Autre]  
**Format** : [ ] Texte brut / [ ] HTML / [ ] Multipart

**Prétexte utilisé** :
> *[Décrire le scénario/prétexte : facture, livraison, support IT, RH, sécurité, etc.]*

**Message (extrait ou résumé)** :
```
[Copier ou résumer le contenu pertinent du message]
```

### Techniques d'ingénierie sociale

- [ ] Sentiment d'urgence ("Agissez maintenant", "Expire dans 24h")
- [ ] Menace ou peur ("Compte suspendu", "Action légale")
- [ ] Autorité usurpée (direction, IT, support, banque)
- [ ] Curiosité ("Vous avez reçu un document", "Nouvelle fonctionnalité")
- [ ] Récompense/gain ("Remboursement", "Cadeau", "Promotion")
- [ ] Demande d'informations sensibles (mot de passe, coordonnées bancaires)
- [ ] Formulaire intégré dans l'e-mail

### 🚩 Red Flags identifiés dans le contenu

- [ ] Salutation générique ("Cher client", "Madame, Monsieur")
- [ ] Fautes d'orthographe ou de grammaire
- [ ] Formatage incohérent (polices, couleurs, logos flous)
- [ ] Liens hypertextes trompeurs
- [ ] Demande inhabituelle pour l'organisation
- [ ] Pièce jointe ou lien non sollicité
- [ ] Signature vague ou absente
- [ ] Pixels de tracking détectés

**Détails :**
> *[Expliquer les indicateurs d'ingénierie sociale observés]*

---

## 🔗 Analyse des liens

### URLs identifiées

| **Texte affiché** | **URL réelle** | **Réputation** | **Destination finale** |
|-------------------|----------------|----------------|------------------------|
| [Texte du lien] | hxxps://domaine[.]com/path | ✅ Clean / ⚠️ Suspect / ❌ Malveillant | [Après redirections] |

### Analyse détaillée des domaines

#### Domaine principal : `domaine.com`

| **Attribut** | **Valeur** |
|--------------|------------|
| **WHOIS - Date de création** | YYYY-MM-DD |
| **WHOIS - Registrar** | [Nom du registrar] |
| **WHOIS - Statut** | Active / Suspended / Expired |
| **Hébergement** | [Fournisseur, Pays] |
| **Certificat SSL/TLS** | ✅ Valide / ❌ Invalide / ⚠️ Auto-signé |
| **Age du domaine** | [X] jours/mois/ans |

**Réputation (sources multiples)** :
- **VirusTotal** : [X/90 moteurs] - [Lien vers le rapport]
- **URLhaus** : ✅ Clean / ❌ Listé comme malveillant
- **PhishTank** : ✅ Clean / ❌ Listé comme phishing
- **urlscan.io** : [Lien vers le scan] - [Verdict]

### 🚩 Red Flags identifiés pour les liens

- [ ] URL raccourcie (bit.ly, tinyurl, etc.)
- [ ] Domaine récemment créé (< 30 jours)
- [ ] Typosquatting / homoglyphes
- [ ] IP brute sans nom de domaine
- [ ] Hébergement sur services gratuits
- [ ] Certificat SSL suspect ou manquant
- [ ] Redirections multiples
- [ ] Téléchargement automatique détecté

**Détails :**
> *[Expliquer la chaîne de redirection et le comportement observé]*

### Capture d'écran de la page de phishing

> *[Insérer capture d'écran annotée si applicable]*

![Page de phishing](./screenshots/phishing-page.png)

---

## 📎 Analyse des pièces jointes

### Fichiers attachés

| **Nom du fichier** | **Extension** | **Taille** | **Type réel** |
|--------------------|---------------|------------|---------------|
| [nom.ext] | .pdf / .docx / .zip | XX KB/MB | [Type MIME réel] |

### Analyse de hash

| **Algorithme** | **Hash** | **Réputation** |
|----------------|----------|----------------|
| **MD5** | [hash MD5] | ✅ Clean / ❌ Malveillant |
| **SHA256** | [hash SHA256] | ✅ Clean / ❌ Malveillant |

**Réputation (sources)** :
- **VirusTotal** : [X/70 moteurs] - [Lien vers le rapport]
- **MalwareBazaar** : ✅ Inconnu / ❌ Listé - [Famille de malware]
- **Hybrid Analysis** : [Verdict] - [Lien vers le rapport]

### Analyse statique

**Métadonnées (exiftool)** :
```
[Résultats pertinents de exiftool]
Author: [Nom]
Created: YYYY-MM-DD
Software: [Application utilisée]
```

**Macros / Scripts détectés** :
- [ ] Macros VBA présentes
- [ ] JavaScript embarqué
- [ ] Scripts PowerShell
- [ ] Autre : [Préciser]

**Extraction (olevba/pdfparser)** :
```
[Code ou commandes suspectes extraites]
```

### Analyse dynamique (Sandbox)

**Plateforme** : Any.Run / Joe Sandbox / Hybrid Analysis  
**Lien vers le rapport** : [URL]

**Comportement observé** :
- [ ] Connexion réseau vers [IPs/domaines]
- [ ] Téléchargement de payload secondaire
- [ ] Modification du registre
- [ ] Création de tâches planifiées
- [ ] Exfiltration de données
- [ ] Chiffrement de fichiers
- [ ] Autre : [Préciser]

**Processus créés** :
```
[Liste des processus suspects lancés]
```

**Connexions réseau** :
```
[IPs et domaines contactés]
```

### 🚩 Red Flags identifiés pour les pièces jointes

- [ ] Extension double (.pdf.exe)
- [ ] Format dangereux (.exe, .scr, .vbs, .js)
- [ ] Archive protégée par mot de passe (fourni dans le mail)
- [ ] Taille incohérente avec le contexte
- [ ] Nom générique (document.doc, invoice.pdf)
- [ ] Macros activées sans contenu significatif
- [ ] Détections antivirus multiples

**Détails :**
> *[Décrire le payload et son comportement]*

---

## 🎯 Indicateurs de compromission (IoCs)

### 📧 E-mails

```
expediteur@domaine.com
reply-to@autre-domaine.com
```

### 🌐 Domaines

```
domaine-suspect[.]com
phishing-site[.]net
```

### 🔗 URLs complètes

```
hxxps://domaine-suspect[.]com/login/verify
hxxp://185[.]203[.]116[.]55/invoice.php
```

### 🌍 Adresses IP

```
185.203.116.55 (Pays - ASN - Fournisseur)
192.0.2.100 (Pays - ASN - Fournisseur)
```

### 🔐 Hashes de fichiers

```
MD5:    d41d8cd98f00b204e9800998ecf8427e
SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### 📋 Autres artefacts

```
Message-ID: <abc123@serveur.com>
User-Agent: [Client d'envoi identifié]
C2 URLs: [Si applicable]
```

---

## 🎯 Mapping MITRE ATT&CK

### Tactiques et techniques identifiées

| **Tactique** | **Technique** | **ID** | **Détails** |
|--------------|---------------|--------|-------------|
| Initial Access | Phishing | [T1566](https://attack.mitre.org/techniques/T1566/) | E-mail de phishing |
| Initial Access | Spearphishing Link | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Lien vers page de phishing |
| Initial Access | Spearphishing Attachment | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Pièce jointe malveillante |
| Credential Access | Input Capture | [T1056](https://attack.mitre.org/techniques/T1056/) | Formulaire de phishing |
| Collection | Data from Information Repositories | [T1213](https://attack.mitre.org/techniques/T1213/) | [Si applicable] |
| Exfiltration | Exfiltration Over Web Service | [T1567](https://attack.mitre.org/techniques/T1567/) | [Si applicable] |

**Procédures observées** :
> *[Décrire les techniques spécifiques utilisées par l'attaquant]*

---

## 📊 Évaluation des risques

### CIA Triad

| **Critère** | **Niveau** | **Justification** |
|-------------|------------|-------------------|
| **Confidentiality** | 🟢 Faible / 🟡 Moyen / 🟠 Élevé / 🔴 Critique | [Explication] |
| **Integrity** | 🟢 Faible / 🟡 Moyen / 🟠 Élevé / 🔴 Critique | [Explication] |
| **Availability** | 🟢 Faible / 🟡 Moyen / 🟠 Élevé / 🔴 Critique | [Explication] |

### Analyse détaillée

**Utilisateurs affectés** :
- Total ciblés : [X] utilisateurs
- Ont cliqué sur le lien : [X] utilisateurs
- Ont saisi des credentials : [X] utilisateurs
- Ont ouvert la pièce jointe : [X] utilisateurs
- Compromissions confirmées : [X] utilisateurs

**Données potentiellement exposées** :
- [ ] Credentials (login/password)
- [ ] Informations personnelles (nom, email, téléphone)
- [ ] Données financières (CB, IBAN)
- [ ] Données métier sensibles
- [ ] Accès à des systèmes critiques
- [ ] Aucune (tentative bloquée)

**Contournement des contrôles** :
- [ ] Email gateway bypassé
- [ ] Filtres antispam contournés
- [ ] Antivirus non détecté (FP)
- [ ] EDR/XDR non alerté
- [ ] Contrôles navigateur contournés

**Impact métier** :
> *[Évaluer l'impact potentiel ou avéré sur les opérations]*

---

## ✅ Actions prises

### 🛡️ Containment (Confinement)

**Date/Heure** : YYYY-MM-DD HH:MM UTC

- [x] **Blocage réseau**
  - Firewall : Blocage des IPs [liste]
  - Proxy : Blocage des domaines/URLs [liste]
  - DNS : Sinkhole des domaines malveillants
  
- [x] **Email gateway**
  - Création de règles de blocage pour expéditeurs
  - Ajout de signatures pour détection future
  - Quarantaine des messages similaires non livrés
  
- [x] **Suppression/Quarantaine**
  - [X] e-mails supprimés des boîtes de réception
  - Utilisateurs notifiés : [X]

- [x] **Isolation des systèmes**
  - Postes compromis isolés du réseau : [X]
  - Sessions utilisateurs révoquées : [X]

### 🔧 Eradication (Éradication)

**Date/Heure** : YYYY-MM-DD HH:MM UTC

- [x] **Réinitialisation de credentials**
  - Comptes utilisateurs réinitialisés : [X]
  - MFA forcé sur comptes affectés
  - Sessions actives révoquées
  
- [x] **Scan antivirus/EDR**
  - Scan complet sur [X] postes
  - Malware supprimé : [Oui/Non]
  - Traces résiduelles nettoyées

- [x] **Restauration**
  - Restauration depuis backup : [Si nécessaire]
  - Vérification d'intégrité des systèmes

### 🔄 Recovery (Récupération)

**Date/Heure** : YYYY-MM-DD HH:MM UTC

- [x] **Remise en service**
  - Systèmes validés et remis en ligne
  - Surveillance renforcée activée
  
- [x] **Surveillance post-incident**
  - Monitoring actif des IoCs : [Durée]
  - Alertes SIEM configurées
  - Revue des logs à J+7, J+14, J+30

### 📢 Communication

- [x] **Utilisateurs ciblés**
  - E-mail de notification envoyé : [Date]
  - Conseils de sécurité fournis
  
- [x] **Management**
  - Direction informée : [Date]
  - Rapport d'incident partagé
  
- [x] **Équipes techniques**
  - IT/Infrastructure : Informés
  - Équipe sécurité : Briefing effectué
  
- [x] **Externe (si applicable)**
  - CERT national notifié : [Oui/Non]
  - Autorités contactées : [Oui/Non]
  - Partenaires informés : [Oui/Non]

---

## 📎 Annexes

### A. Headers complets de l'e-mail

```
[Copier les headers complets ici]
```

### B. Code source HTML (si pertinent)

```html
[Extrait du code HTML malveillant]
```

### C. Captures d'écran

1. E-mail original
2. Page de phishing
3. Résultats sandbox
4. Alertes SIEM/EDR

### D. Rapports externes

- [Lien VirusTotal]
- [Lien urlscan.io]
- [Lien Joe Sandbox / Any.Run]
- [Autres analyses]

### E. Timeline détaillée

| **Date/Heure** | **Événement** | **Acteur** |
|----------------|---------------|------------|
| YYYY-MM-DD HH:MM | E-mail envoyé | Attaquant |
| YYYY-MM-DD HH:MM | E-mail reçu par utilisateur X | Système |
| YYYY-MM-DD HH:MM | Utilisateur clique sur lien | Victime |
| YYYY-MM-DD HH:MM | Alerte email gateway | Système |
| YYYY-MM-DD HH:MM | Détection SOC | Analyste |
| YYYY-MM-DD HH:MM | Début de l'investigation | SOC |
| YYYY-MM-DD HH:MM | Blocage des IoCs | SOC |
| YYYY-MM-DD HH:MM | Quarantaine des e-mails | SOC |
| YYYY-MM-DD HH:MM | Réinitialisation credentials | IT |
| YYYY-MM-DD HH:MM | Notification utilisateurs | SOC/IT |
| YYYY-MM-DD HH:MM | Incident résolu | SOC |

---

## 📝 Notes additionnelles

> *[Ajouter ici toute information complémentaire, contexte particulier, ou observations importantes]*

---

*Document généré le : YYYY-MM-DD*  
*Dernière modification : YYYY-MM-DD*  
*Classification : [Interne / Confidentiel / Restreint]*
