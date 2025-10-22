# 🔍 Guide d'analyse d'e-mail de phishing

> 💡 Méthodologie structurée pour analyser un e-mail de phishing dans le cadre d'opérations SOC

---

## 📋 Table des matières

1. [Analyse des Headers SMTP](#1%EF%B8%8F⃣-analyse-des-headers-smtp--première-ligne-de-défense)
2. [Analyse du corps du message](#2%EF%B8%8F⃣-analyse-du-corps-du-message--décoder-la-manipulation)
3. [Analyse des liens et pièces jointes](#3%EF%B8%8F⃣-analyse-des-liens-et-pièces-jointes--vecteurs-dinfection)
4. [Investigation technique approfondie](#4%EF%B8%8F⃣-investigation-technique-approfondie)

---

## 1️⃣ Analyse des Headers SMTP : première ligne de défense

L'en-tête (header) contient les informations techniques sur la **PROVENANCE** du message : serveur d'envoi, adresses, protocoles d'authentification, etc.

> 🎯 **Objectif** : Valider l'authenticité du chemin d'envoi et détecter l'usurpation d'identité.

### 📋 Headers SMTP critiques à examiner

- **From/Return-Path** : Vérifier la correspondance entre l'expéditeur affiché et l'adresse réelle
- **Received** : Tracer le chemin complet de l'e-mail (serveurs relais) - du bas (src) vers le haut (dest)
- **SPF, DKIM, DMARC** : Vérifier les résultats d'authentification dans `Authentication-Results`
- **Message-ID** : Identifier la source originale et valider le format
- **X-Originating-IP** : Localiser l'origine géographique de l'envoi
- **Reply-To** : Détecter les redirections suspectes vers des adresses tierces
- **X-Mailer/User-Agent** : Identifier le client/service d'envoi utilisé

### ✨ Tips & Tricks

- **Extraire les hops `Received`**
  > 👉 Lire du bas (origine) vers le haut (destination) pour comprendre le chemin d'envoi et identifier les relais suspects.

- **Vérifier SPF/DKIM/DMARC**
  > 👉 Examiner `Authentication-Results` pour détecter des échecs/absences de validation.

- **Contraster les adresses email**
  > 👉 Comparer `From`, `Return-Path` et `Reply-To` pour repérer une usurpation ou incohérence.

- **Analyser l'IP de l'expéditeur**
  > 👉 Vérifier la géolocalisation, le reverse DNS et la réputation (AbuseIPDB, IPVoid).

- **Vérifier les timestamps**
  > 👉 Des délais anormaux entre hops ou des timestamps incohérents peuvent indiquer une manipulation.

### ⚠️ Indicateurs fréquents (Red Flags)

- 🚩 **Adresses email incohérentes**
  > L'adresse d'expéditeur ne correspond pas au nom/domaine affiché. Un écart entre `From` et `Return-Path` trahit souvent une usurpation.

- 🚩 **Adresses IP suspectes**
  > Le champ `Received from` révèle une IP appartenant à un fournisseur sans lien avec l'expéditeur légitime (VPS, cloud public, pays à risque).

- 🚩 **Adresse `Reply-To` différente**
  > Redirige les réponses vers un attaquant plutôt que vers l'expéditeur apparent.

- 🚩 **Échecs d'authentification (SPF, DKIM, DMARC)**
  > Ces mécanismes valident que le message provient du domaine revendiqué. Un échec = falsification probable.

- 🚩 **Faux en-têtes ajoutés**
  > Champs trompeurs comme `X-Virus-Scan: Clean` ou `X-Authenticated: Yes` pour créer une fausse légitimité.

- 🚩 **Reverse DNS incohérent**
  > L'IP d'envoi ne correspond pas au domaine prétendument expéditeur.

### ✅ Pourquoi c'est important

L'analyse des en-têtes constitue une **preuve technique robuste** : contrairement au corps du message, ces champs sont partiellement générés automatiquement par les serveurs SMTP et sont donc plus fiables pour retracer la route d'un e-mail. C'est votre première défense contre le spoofing.

---

## 2️⃣ Analyse du corps du message : décoder la manipulation

Le corps du message révèle les techniques de **social engineering (ingénierie sociale)** employées pour pousser la victime à agir.

> 🎯 **Objectif** : Détecter l'ingénierie sociale, repérer liens/pièces jointes et comprendre le vecteur psychologique.

### 📋 Éléments à analyser

**Indicateurs techniques**
- Version HTML vs texte brut (liens cachés, scripts)
- Liens hypertextes (texte affiché vs URL réelle)
- Images externes et pixels de tracking (`<img src=`)
- Formulaires intégrés demandant des credentials
- Cohérence du formatage (polices, logos, couleurs)

**Indicateurs psychologiques**
- Ton et registre linguistique utilisés
- Prétexte invoqué (IT, RH, finance, livraison, etc.)
- Niveau de personnalisation (nom, fonction, données internes)
- Qualité rédactionnelle (orthographe, grammaire, syntaxe)

### ✨ Tips & Tricks

- **Comparer HTML et texte**
  > 👉 Les liens cachés ou scripts malveillants sont souvent uniquement dans le HTML. Analyser le code source brut.

- **Survoler les liens sans cliquer**
  > 👉 Vérifier qu'ils correspondent au texte affiché. Utiliser l'inspection du code source.

- **Identifier les mots-clés d'urgence**
  > 👉 `urgent`, `verify`, `invoice`, `payment`, `account suspension`, `security alert`, `expire`.

- **Vérifier images externes/tracking**
  > 👉 `<img src=` peut révéler des pixels de suivi ou tentative d'exfiltration d'informations.

- **Analyser le prétexte**
  > 👉 Est-il cohérent avec le contexte de l'organisation ? Vérifier auprès du service concerné.

### ⚠️ Indicateurs fréquents (Red Flags)

- 🚩 **Langage urgent ou menaçant**
  > Messages créant un **sentiment d'urgence** - `Votre compte sera suspendu !!!` - pour provoquer une réaction impulsive.

- 🚩 **Demandes d'informations sensibles**
  > Les organisations légitimes ne demandent **jamais** de mots de passe, numéros de carte ou informations personnelles par e-mail.

- 🚩 **Liens trompeurs**
  > L'URL réelle ne correspond pas au texte affiché ou mène à un domaine suspect (typosquatting, homoglyphes).

- 🚩 **Fautes d'orthographe ou de grammaire**
  > Erreurs récurrentes, tournures maladroites, traductions automatiques approximatives.

- 🚩 **Formatage incohérent**
  > Polices différentes, logos flous/pixelisés, couleurs décalées, mise en page amateur.

- 🚩 **Salutations génériques et signatures floues**
  > `Cher client`, `Madame, Monsieur` au lieu du nom. Signatures vagues sans coordonnées vérifiables.

- 🚩 **Pièces jointes ou formulaires intégrés inattendus**
  > Formulaire demandant des identifiants ou pièce jointe non sollicitée = malveillant jusqu'à preuve du contraire.

- 🚩 **Contexte inadapté**
  > Message concernant un service que l'organisation n'utilise pas ou un processus qui n'existe pas.

### ✅ Pourquoi c'est important

Cette étape permet de **cartographier la stratégie d'ingénierie sociale** (ton, urgence, promesse, peur, curiosité). Les leviers psychologiques sont souvent plus révélateurs que la technique utilisée et permettent d'identifier des campagnes similaires.

---

## 3️⃣ Analyse des liens et pièces jointes : vecteurs d'infection

Les liens et les pièces jointes sont les deux principaux **vecteurs techniques** utilisés dans les campagnes de phishing. Ils permettent soit de rediriger la victime vers une page piégée, soit de lui faire exécuter directement un code malveillant.

> 🎯 **Objectif** : Identifier le payload et retracer les serveurs/infrastructure utilisés par l'attaquant.  
> ⚠️ **RAPPEL** : Toujours analyser ces éléments dans un environnement isolé (sandbox/VM déconnectée du réseau).

---

### 🔗 Analyse des liens

Un lien malveillant peut rediriger vers un faux site de connexion (credential harvesting), un téléchargement de malware ou une infrastructure C2.

> 💡 Les cybercriminels utilisent des domaines compromis, des raccourcisseurs d'URL, des adresses IP brutes ou du typosquatting.

#### ✨ Tips & Tricks

- **Analyser la réputation de l'URL**
  > 👉 Via `VirusTotal`, `URLhaus`, `urlscan.io` ou `PhishTool`. Noter le nombre de détections et la date de soumission.

- **Vérifier le certificat SSL/TLS**
  > 👉 Examiner le nom de domaine, la validité, l'autorité de certification. Les certificats auto-signés ou mismatched sont suspects.

- **Effectuer un WHOIS sur le domaine**
  > 👉 Date de création (domaines récents = suspect), registrar, informations de contact, historique.

- **Chercher des patterns suspects**
  > 👉 IP sans domaine, noms trompeurs (`login-update-secure.com`), redirections en chaîne, paramètres encodés.

- **Analyser la page de destination**
  > 👉 Capturer via `urlscan.io` pour examiner le contenu sans risque.

#### ⚠️ Indicateurs fréquents (Red Flags)

- 🚩 **URL raccourcie ou masquée** (`bit.ly`, `tinyurl`, `goo.gl`)
- 🚩 **Domaine récemment créé** (< 30 jours) ou sans enregistrement WHOIS valide
- 🚩 **Page hébergée sur IP brute** (`http://185.203.116[.]55/invoice`)
- 🚩 **Typosquatting** (`micros0ft-support.com`, `goog1e.com`)
- 🚩 **Présence d'un téléchargement automatique** ou redirection vers un exécutable
- 🚩 **Paramètres URL encodés** cachant la vraie destination
- 🚩 **Hébergement sur services gratuits** (000webhost, Freenom, etc.)

#### ✅ Pourquoi c'est important

L'analyse des liens permet de **cartographier la chaîne d'infection** et de remonter vers l'infrastructure malveillante (hébergeur, C2, campagnes similaires, autres victimes). C'est crucial pour le threat intelligence et la réponse à incident.

---

### 📎 Analyse des pièces jointes

Les pièces jointes servent souvent à livrer le payload : malware, script, macro ou installeur déguisé.

> 💡 Une analyse minutieuse de leur format et de leur comportement peut révéler la nature de l'attaque et le type de malware utilisé.

#### ✨ Tips & Tricks

- **Calculer le hash (SHA256, MD5) avant ouverture**
  > 👉 `sha256sum fichier` pour vérifier la réputation sur `VirusTotal`, `MalwareBazaar`, `Hybrid Analysis`.

- **Vérifier le type réel du fichier**
  > 👉 `file fichier` sous Linux ou `TrID` sous Windows (ex. un `.pdf` déguisé en `.exe`).

- **Tester en sandbox**
  > 👉 `Any.Run`, `Joe Sandbox`, `Hybrid Analysis` ou VM isolée pour observer le comportement dynamique.

- **Examiner les métadonnées**
  > 👉 `exiftool` pour révéler l'auteur, le logiciel utilisé, les timestamps (incohérences = suspect).

- **Méfiance avec archives protégées par mot de passe**
  > 👉 Souvent utilisées pour contourner les antivirus. Le mot de passe dans le mail = 🚩.


#### ⚠️ Indicateurs fréquents (Red Flags)

- 🚩 **Extensions multiples** : `Facture.pdf.exe`, `Reçu.docx.js`
- 🚩 **Formats dangereux** : `.exe`, `.scr`, `.vbs`, `.js`, `.bat`, `.cmd`, `.msi`, `.hta`
- 🚩 **Archives suspectes** : `.zip`, `.rar`, `.7z` protégées avec mot de passe fourni dans le mail
- 🚩 **Taille incohérente** avec le contexte (facture de 15 Mo, document de 2 Ko)
- 🚩 **Pièce jointe inattendue ou non sollicitée**
- 🚩 **Nom de fichier générique** : `document.doc`, `invoice.pdf`, `scan001.jpg`
- 🚩 **Détection antivirus** même partielle (1-2 moteurs sur VT)

#### ✅ Pourquoi c'est important

Les pièces jointes représentent la **porte d'entrée directe du malware** dans le SI. Une analyse complète permet de comprendre le vecteur initial de compromission, d'extraire les IoCs (hashes, C2, comportements) et de prévenir la propagation future.

---

## 4️⃣ Investigation technique approfondie

### 🛠️ Outils recommandés par catégorie

**Analyse d'e-mails**
- `PhishTool` : Analyse automatisée complète
- `MXToolbox` : Vérification DNS/headers/blacklists

**Analyse statique**
- `VirusTotal` : Réputation URLs/fichiers/domaines/IPs
- `AbuseIPDB` : Réputation d'adresses IP
- `URLhaus` : Base de données d'URLs malveillantes
- `exiftool` : Extraction de métadonnées

**Analyse dynamique**
- `urlscan.io` : Capture et analyse de pages web
- `ANY.RUN` : Sandbox interactive en temps réel
- `Joe Sandbox` : Analyse comportementale approfondie
- `Hybrid Analysis` : Sandbox multi-moteurs

**OSINT et domaines**
- `WHOIS` : Informations sur les domaines
- `Shodan` : Recherche sur l'infrastructure

### 🔄 Pivots d'investigation

- Rechercher d'autres campagnes utilisant les mêmes IoCs (hash, domaine, IP, techniques)
- Identifier l'infrastructure complète (hébergement, registrar, nameservers, réseaux associés)
- Corréler avec des alertes existantes dans le SIEM/EDR
- Rechercher des victimes similaires (même secteur, même région)
- Identifier des campagnes précédentes du même acteur (TTPs, infrastructure)


---

## ⚠️ Disclaimer

> **Avertissement légal** : Ce laboratoire est uniquement destiné à des fins éducatives et de formation. Ne reproduisez pas ces techniques sur des systèmes en production ou sans autorisation explicite. Tous les fichiers, liens et artefacts doivent être manipulés dans un environnement isolé et sécurisé.


*Dernière mise à jour : Octobre 2025*
