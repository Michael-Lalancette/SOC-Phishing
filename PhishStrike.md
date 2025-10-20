# 🐟 PhishStrike
Exercice d’investigation d’un e-mail suspect reçu par un membre du corps enseignant, affichant un **faux reçu/invoice** de $625,000.  
> 👨‍💻 Tâche : Déterminer si le message est légitime ou malveillant, et identifier la chaîne d’infection complète.  

**Date :** Octobre 2025  
**Source :** [PhishStrike - CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/phishstrike/)  

> ⚠️ **Disclaimer :** Ce document est à but éducatif. Ne manipulez pas d’artefacts malveillants sur des machines non isolées. Toutes les actions actives (HEAD, expansion d’URL, exécution de pièces jointes) doivent être faites dans une VM/sandbox isolée.




---

## 🔎 Étape 1 — Analyse des headers
- **SPF** : Soft fail (`~all`) → le domaine d’envoi n’est pas autorisé à utiliser cette adresse IP.  
- **IP source** : hébergée sur **Amazon AWS**, infrastructure fréquemment exploitée par des acteurs malveillants pour se fondre dans le trafic légitime.  
- **Return-Path** : non conforme au domaine d’expéditeur affiché.  
- **DKIM / DMARC** : signatures absentes ou invalides.  

➡️ **Hypothèse initiale :** usurpation d’identité via un serveur cloud ; probable campagne de phishing ciblée.




---

## 🌐 Étape 2 — Réputation du domaine et de l’adresse IP
Recoupement effectué via **VirusTotal**, **Abuse.ch (URLhaus)** et **AlienVault OTX** :  
- L’adresse IP d’origine est **signalée comme malveillante** par plusieurs moteurs.  
- Corrélation avec des **campagnes RAT** connues (AsyncRAT, BitRAT).  
- Activité réseau associée à des **serveurs C2** déjà répertoriés.  

➡️ **Confirmation :** infrastructure de malware active dissimulée derrière une apparence commerciale.





---

## 📎 Étape 3 — Analyse du contenu et des liens
Le courriel contient un lien intitulé **“Invoice #625000”** pointant vers **une adresse IP brute** sans domaine — pratique typique d’un phishing de masse.  

Analyse dynamique du lien :  
- Téléchargement d’un exécutable se présentant comme un **fichier PDF**.  
- Détection d’activités liées à **AsyncRAT**, **BitRAT** et un **module CoinMiner**.  
- Exécution → prise de contrôle distante et vol potentiel de données utilisateur.  

➡️**Risque :** compromission complète du poste par un simple clic.




---

## ☣️ Étape 4 — Analyse comportementale du malware
Les rapports **Any.Run** et **Hybrid Analysis** indiquent :  
- **Persistance** : ajout d’une clé registre  
  `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\{Random}`  
- **Délai d’exécution** (~50 s) pour contourner les environnements d’analyse automatisée.  
- **Communication C2** : utilisation de **Telegram Bot API** (identifiant AsyncRAT).  

➡️ **Comportement typique d’un RAT** cherchant à conserver un accès persistant et discret.




---

## 🏷️ Indicateurs de compromission (IoCs)

| Type | Valeur | Description |
|------|---------|-------------|
| **IP** | `54.176.127.197` | Serveur C2 hébergé sur AWS |
| **Domaine** | `invoice-payment[.]xyz` | Faux domaine d’expéditeur |
| **Hash (SHA256)** | `b1c9f47b6a0ef...` | Binaire AsyncRAT déguisé en PDF |
| **Telegram Bot ID** | `@AsyncBot_9812` | Canal C2 via Telegram |




---

## 🧬 MITRE ATT&CK — Techniques observées

| ID | Tactique | Technique |
|----|-----------|-----------|
| **T1566.002** | Initial Access | Phishing : lien malveillant |
| **T1059** | Execution | Command & Scripting Interpreter |
| **T1053** | Persistence | Scheduled Task / Run Key |
| **T1071.001** | Command & Control | Application Layer Protocol – Web Traffic |



---

## 🧰 Outils utilisés
- VMware Workstation Pro (environnements isolé)  
- Any.Run / Hybrid Analysis (sandbox interactive)  
- CyberChef (décodage)  
- MITRE ATT&CK (mapping TTPs)  
- OSINT (URLhaus, MalwareBazaar, VirusTotal, AbuseIPDB, WHOIS, Passive DNS, Shodan)




---

## ✨ Conclusion
Cette enquête confirme une **campagne de phishing avancée** utilisant un leurre financier pour distribuer un **RAT multifonctionnel**.   
Une simple ouverture du lien « invoice » aurait permis :  
- l’exécution d’un malware de contrôle à distance,  
- la persistance via registre Windows,  
- la communication chiffrée avec un serveur C2 externe.  




---

### 🧠 Compétences mises en œuvre
- Lecture et interprétation d’en-têtes SMTP  
- Analyse de réputation et recoupement OSINT  
- Extraction et documentation d’IoCs  
- Observation comportementale en sandbox  
- Cartographie des TTP via MITRE ATT&CK  


---
