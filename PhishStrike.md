# 🐟 PhishStrike
Exercice d’investigation d’un e-mail suspect reçu par un membre du corps enseignant, affichant un **faux reçu/invoice** de $625,000.  
> 👨‍💻 Tâche : Déterminer si le message est légitime ou malveillant, et identifier la chaîne d’infection complète.  

**Date :** Octobre 2025  
**Source :** [PhishStrike - CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/phishstrike/)  

> ⚠️ **Disclaimer :** Ce document est à but éducatif. Ne manipulez pas d’artefacts malveillants sur des machines non isolées. Toutes les actions actives (HEAD, expansion d’URL, exécution de pièces jointes) doivent être faites dans une VM/sandbox isolée.



![thunderbird-1](./images/thunderbird-1.png)



---

## 1️⃣ Analyse des headers

#### 🌐 Received Hops :  
- Message prétendument envoyé depuis `uptc[.]edu[.]co` (Google relay `209[.]85[.]221[.]65`).  
- Filtré par Trend Micro (AWS `18[.]208[.]22[.]104` – AS14618 Amazon-AES).  
- Relayé via Microsoft Exchange Online puis transféré à Google (`mail-wr1-f65[.]google[.]com`).  
- Livraison finale à `servicios[.]informaticos@fsfb[.]org[.]co` (Google Workspace).  

#### 📧 Alignement `Return-Path`/`From`
- From : `erikajohana[.]lopez@uptc[.]edu[.]co`  
- Return-Path : `erikajohana[.]lopez@uptc[.]edu[.]co`  
  > 💡 Alignement correct : même domaine, donnant l’apparence d’un message légitime.  

#### 🧪 Résultats d’authentification
- 🚩 SPF : `softfail` → le domaine d’envoi n’autorise pas l’adresse IP utilisée.  
- 🚩 DKIM : `none` → aucune signature valide détectée.     
- 🚩 DMARC : `none` → aucune politique publiée pour le domaine.  
![header-1](./images/header-1.png)  
> ⚠️ Forte probabilité de spoofing : absence totale d’authentification valide, origine réelle identifiée sur un serveur AWS non autorisé (AS14618).  





---

## 2️⃣ Analyse du contenu du message (body)

#### 🕵️‍♂️ Contenu observé
- Sujet : *Commercial Purchase Receipt*  
- Texte : annonce une transaction de 625,000 pesos, avec une invitation à "voir la facture".  
- Lien : `http[:]//107[.]175[.]247[.]199/loader/install[.]exe` → tous les éléments "cliquables" mènent à ce lien malveillant.  
- Code d’accès : `8657`  
  > 💡 Le message inclut un `ACCESS CODE` censé protéger le document, ce qui renforce artificiellement sa crédibilité. Cette pratique est typique des campagnes de phishing visant à pousser l’utilisateur à exécuter un fichier malveillant.  



---

## 3️⃣ Analyse des liens et pièces jointes
Le courriel contient un lien intitulé "Invoice #625000" pointant vers une adresse IP raw (sans domaine) : `107[.]175[.]247[.]199`.  
> 💡 Pratique typique d’un phishing de masse.




#### 🔎 Analyse Statique
- Analyse de l'adresse IP du lien dans VirusTotal :  
  ![osint-1](./images/osint-1.png)

- Analyse du lien complet dans URLhaus (Abuse.ch) :
  ![osint-2](./images/osint-2.png)

- URL observée : `http[:]//107[.]175[.]247[.]199/loader/install[.]exe` — listée sur **URLhaus**.  
- IP `107[.]175[.]247[.]199` : présence historique de domaines liés (ex. `ripley[.]studio`) ; plusieurs échantillons associés avec détections élevées sur VT.  
- Types identifiés : `BitRat`, `AsyncRAT`, `CoinMiner`  
  - `BitRAT` 
    > 💡 RAT commercialisé sur des forums clandestins ; permet exfiltration de données, keylogging, contrôle de la webcam et peut être utilisé pour lancer du minage de cryptomonnaie.  
  *[Source (Malpedia)](https://malpedia.caad.fkie.fraunhofer.de/details/win.bit_rat)*  

  - `AsyncRAT`  
    > 💡 Outil d’accès à distance open-source souvent détourné à des fins malveillantes ; offre contrôle à distance, exécution de commandes, keylogging et exfiltration via un canal C2 chiffré.  
  *[Source (Malpedia)](https://malpedia.caad.fkie.fraunhofer.de/details/win.asyncrat)*   

  - `CoinMiner`  
    > 💡 Malware qui utilise les ressources CPU/GPU de la machine infectée pour miner des cryptomonnaies (ex. Monero) à l’insu du propriétaire.  
  *[Source (Malpedia)](https://malpedia.caad.fkie.fraunhofer.de/details/win.coinminer)*  




#### 🔬 Analyse dynamique
- En sandbox : téléchargement de payloads supplémentaires, création de fichiers sous `%APPDATA%`, tentative de persistence (clé `Run`), connexions sortantes vers C2.
- Comportement : loader → download & exécution de RATs/miners. Risque élevé de compromission persistante ou minage illicit.






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
