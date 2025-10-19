# 🐟 SOC-Phishing
Dépôt personnel d'analyses d'e‑mails de phishing (cas pratiques, IOCs et méthodologies).  
> 💡 Chaque cas contient des notes détaillées, les artefacts collectés et un rapport d'analyse.  

---

## 🎯 Objectif
Simuler des enquêtes SOC centrées sur des **e‑mails de phishing** pour développer et documenter des compétences pratiques en :
- Analyse des headers/body (sender IP, Received hops, SPF/DKIM/DMARC)  
- Recherche de réputation (domaines, IPs, URLs)  
- Extraction et décodage des liens malveillants (expansion d’URL)  
- Traitement et hachage des pièces jointes (SHA256 / MD5)  
- Corrélation des observations avec **MITRE ATT&CK** pour identifier TTPs  
- Rédaction de rapports d’incident, listing d’IOCs et recommandations de mitigation


---

## 📧 Méthodologie d’analyse d’un e-mail de phishing

L’analyse d’un email potentiellement frauduleux repose sur trois axes principaux :  
- 1️⃣ Analyse des **headers**,  
- 2️⃣ Analyse du **body**,  
- 3️⃣ Analyse des **pièces jointes**.  

Chacun de ces éléments peut révéler des indices précieux sur l’origine, les intentions et la dangerosité du message.

*[Source](https://keepnetlabs.com/blog/step-by-step-phishing-email-analysis)*



---

### 1️⃣ Analyse des Headers, première ligne de défense

L’en-tête (header) contient les informations techniques sur la provenance du message : serveur d’envoi, adresses, protocoles d’authentification, etc.  
  > 💡 C’est souvent ici que les premiers red flags apparaissent.  




#### ⚠️ Indicateurs fréquents de phishing

- 🚩 Adresses email incohérentes :  
  > Vérifie que l’adresse d’expéditeur correspond au nom et au domaine affichés. Un écart entre ces deux éléments trahit souvent une usurpation.   

- 🚩 Adresses IP suspectes :  
  > Le champ `Received from` indique l’adresse IP du serveur d’envoi. Si elle appartient à un fournisseur sans lien avec l’expéditeur légitime, c’est un red flag.  
  
- 🚩 Adresse `Reply-To` différente : 
  > Une adresse de réponse différente de celle de l’expéditeur peut rediriger les réponses vers un attaquant.  
  
- 🚩 Échecs d’authentification (`SPF, DKIM, DMARC`) : 
  > Ces mécanismes valident que le message provient bien du domaine revendiqué. Un échec ou une absence de validation indique une possible falsification.  
  
- 🚩 Faux en-têtes : 
  > Certains attaquants ajoutent de faux champs comme `X-Virus-Scan: Clean` pour donner une impression de légitimité.  




#### ✅ Pourquoi c’est important  
L’analyse des en-têtes permet d’évaluer la fiabilité de la source avant même d’examiner le contenu du message. C’est la première étape de toute investigation.





---

### 2️⃣ Analyse du corps du message, décoder la manipulation

Le corps du message révèle les techniques de **social engineering** (ingénierie sociale) employées pour pousser la victime à agir.  
> 💡 Le ton, les formulations et la mise en page donnent souvent de précieux indices!  




#### ⚠️ Indicateurs fréquents de phishing

- 🚩 Langage urgent ou menaçant :
  > Les messages qui créent un **sentiment d’urgence** (`Votre compte sera suspendu !!!`) cherchent à provoquer une réaction impulsive. 

- 🚩 Demandes d’informations sensibles :
  > Les organisations sérieuses ne demandent **jamais** de mots de passe, numéros de carte ou informations personnelles par e-mail.  

- 🚩 Liens trompeurs :
  > Survole les liens sans cliquer : si l’URL réelle ne correspond pas au texte affiché ou mène à un domaine suspect, c’est une tentative de fraude.  

- 🚩 Fautes d’orthographe ou de grammaire :
  > Des erreurs récurrentes indiquent souvent un message rédigé par un acteur malveillant.  

- 🚩 Formatage incohérent :
  > Polices différentes, logos flous, couleurs décalées : des incohérences visuelles trahissent souvent un faux message.  

- 🚩 Salutations génériques et signatures floues :
  > `Cher client` ou `Madame, Monsieur` au lieu de ton nom : les fraudeurs utilisent souvent des formules impersonnelles. Les signatures vagues sont tout aussi suspectes.   

- 🚩 Pièces jointes ou formulaires intégrés :
  > Un email contenant un formulaire demandant des identifiants ou une pièce jointe inattendue doit être traité comme malveillant.  




#### ✅ Pourquoi c’est important  
Les signes linguistiques et visuels révèlent les intentions de l’attaquant et les leviers psychologiques utilisés.  
L’analyse du corps permet de détecter la tentative d’ingénierie sociale avant toute exécution technique.





---

### 3️⃣ Analyse des pièces jointes, le vecteur d’infection

Les pièces jointes sont souvent le **vecteur d’infection** : scripts, exécutables, macros ou archives contenant des malwares.  
> 💡 Elles doivent être examinées avec une extrême prudence (sandbox/environnement isolé).  




#### ⚠️ Indicateurs fréquents de phishing

- 🚩 Types de fichiers dangereux :  
  > Méfie-toi des extensions `.exe`, `.scr`, `.zip` ou `.rar`. Ces formats sont couramment utilisés pour propager des malwares.  

- 🚩 Noms de fichiers trompeurs :  
  > Des fichiers comme `Facture.pdf.exe` cherchent à duper la victime par double extension.  
  
- 🚩 Extensions multiples :  
  > Les fichiers à double extension sont une technique classique de dissimulation.  
  
- 🚩 Taille ou contenu incohérents :  
  > Un fichier volumineux ou sans rapport avec le sujet du message est suspect.  
  
- 🚩 Fichiers non sollicités :  
  > Une pièce jointe inattendue d’un expéditeur inconnu ou un message qui insiste pour qu’on l’ouvre sont des signaux d’alerte.  
  
- 🚩 Archives protégées par mot de passe :  
  > Les attaquants utilisent parfois des fichiers `.zip` protégés pour contourner les antivirus. Si le mot de passe est donné dans l’email, méfiance maximale.  





#### ✅ Pourquoi c’est important  
L’analyse des pièces jointes permet d’identifier la charge utile potentielle d’un phishing et d’éviter une compromission directe du poste de travail.






---


## 🧰 Outils Utilisés
- **[VMware Workstation Pro](https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion)** – Hyperviseur pour analyses isolées  
- **[Any.Run](https://any.run/)** – Sandbox interactive pour observer le comportement des fichiers et liens malveillants  
- **[CyberChef](https://gchq.github.io/CyberChef/)** – Outils de décodage, décompression et transformation pour extraire IOCs et analyser payloads  
- **[MITRE ATT&CK](https://attack.mitre.org/)** – Référentiel des tactiques, techniques et procédures (TTP) pour contextualiser les observables
- **[URLhaus](https://urlhaus.abuse.ch/)** – Vérification des URLs malveillantes et contexte des campagnes  
- **[MalwareBazaar](https://bazaar.abuse.ch/)** – Répertoire d’échantillons malware pour identifier des artefacts connus  
- **[VirusTotal](https://www.virustotal.com/gui/home/url)** – Réputation des fichiers et URLs (agrégateur multi-source)  
- **OSINT général** – Recherche d’informations publiques sur IP, domaines, URLs, emails et infrastructures (AbuseIPDB, WHOIS, Passive DNS, Shodan)



---

## 📂 Index des cas étudiés
1. [PhishStrike - OCT25](PhishStrike.md) – Analyse forensique d’un courriel de phishing (fausse facture)

*(Le catalogue s’enrichira régulièrement au fur et à mesure des analyses.)*


---

#### ⚠️ Disclaimer
> Ce laboratoire est uniquement destiné à des fins éducatives et de formation. Ne reproduisez pas ces techniques sur des systèmes en production ou sans autorisation explicite. Tous les fichiers, liens et artefacts doivent être manipulés dans un environnement isolé et sécurisé.

