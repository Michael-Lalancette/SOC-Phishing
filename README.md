# 🐟 SOC-Phishing
Dépôt personnel d'analyses d'e‑mails de phishing (cas pratiques, IOCs et méthodologies).  
> 💡 Chaque cas contient des notes détaillées, les artefacts collectés et un rapport d'analyse.  

---

## 🎯 Objectif
Simuler des enquêtes SOC centrées sur des **e‑mails de phishing** pour développer et documenter des compétences pratiques en :
- Analyse des headers/body (sender IP, Received hops, SPF/DKIM/DMARC)  
- Recherche de réputation (domaines, IPs, URLs)  
- Extraction et décodage des liens malveillants (expansion d’URL)  
- Traitement et hachage des pièces jointes (SHA256/MD5)  
- Corrélation des observations avec **MITRE ATT&CK** pour identifier TTPs  
- Rédaction de rapports d’incident, listing d’IOCs et recommandations de mitigation





---


## 🧰 Outils Utilisés
- **[VMware Workstation Pro](https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion)**
  > Hyperviseur pour analyses isolées  
- **[Any.Run](https://any.run/)**
  > Sandbox interactive pour observer le comportement des fichiers et liens malveillants  
- **[CyberChef](https://gchq.github.io/CyberChef/)**
  > Outils de décodage, décompression et transformation pour extraire IOCs et analyser payloads  
- **[MITRE ATT&CK](https://attack.mitre.org/)**
  > Référentiel des tactiques, techniques et procédures (TTP) pour contextualiser les observables  
- **[URLhaus](https://urlhaus.abuse.ch/)**
  > Vérification des URLs malveillantes et contexte des campagnes  
- **[MalwareBazaar](https://bazaar.abuse.ch/)**
  > Répertoire d’échantillons malware pour identifier des artefacts connus  
- **[VirusTotal](https://www.virustotal.com/gui/home/url)**
  > Réputation des fichiers et URLs  
- **[Malpedia](https://malpedia.caad.fkie.fraunhofer.de/)**
  > Base de données publique pour identifier les familles de malwares, leurs caractéristiques techniques et comportements  





---

## 📂 Index des cas étudiés
1. [PhishStrike - OCT25](PhishStrike.md) – Analyse forensique d’un courriel de phishing (fausse facture)

*(Le catalogue s’enrichira régulièrement au fur et à mesure des analyses.)*







---

## 📧 Méthodologie d’analyse d’un e-mail de phishing  
L’analyse d’un email potentiellement frauduleux repose sur trois axes principaux :  
- 1️⃣ Analyse des **headers**,  
- 2️⃣ Analyse du **body**,  
- 3️⃣ Analyse des **liens et pièces jointes**.  

Chacun de ces éléments peut révéler des indices précieux sur l’origine, les intentions et la dangerosité du message.

*[Source](https://keepnetlabs.com/blog/step-by-step-phishing-email-analysis)*



---

### 1️⃣ Analyse des Headers, première ligne de défense
L’en-tête (header) contient les informations techniques sur la **provenance du message** : serveur d’envoi, adresses, protocoles d’authentification, etc.  
  > 🎯 But : Valider l'authenticité du chemin d'envoi.  




#### ✨ Tips & Tricks
- Extraire les `Received` hops  
  > 👉 Du bas (origine) vers le haut (destination) pour comprendre le chemin d’envoi.    
- Vérifier **SPF/DKIM/DMARC**  
  > 👉 Examiner `Authentication-Results` pour détecter des échecs/absences.  
- Contraster les adresses email   
  > 👉 Comparer `From`, `Return-Path` et `Reply-To` pour repérer une usurpation.  
- Vérifier l’IP de l’expéditeur   
  > 👉 IP suspecte ou reverse DNS incohérent == 🚩.    





#### ⚠️ Indicateurs fréquents
- 🚩 Adresses email incohérentes :  
  > Vérifie que l’adresse d’expéditeur correspond au nom et au domaine affichés. Un écart entre ces deux éléments trahit souvent une usurpation.   

- 🚩 Adresses IP suspectes :  
  > Le champ `Received from` indique l’adresse IP du serveur d’envoi. Si elle appartient à un fournisseur sans lien avec l’expéditeur légitime, c’est un red flag.  
  
- 🚩 Adresse `Reply-To` différente : 
  > Une adresse de réponse différente de celle de l’expéditeur peut rediriger les réponses vers un attaquant.  
  
- 🚩 Échecs d’**authentification** (`SPF, DKIM, DMARC`) : 
  > Ces mécanismes valident que le message provient bien du domaine revendiqué. Un échec ou une absence de validation indique une possible falsification.  
  
- 🚩 Faux en-têtes : 
  > Certains attaquants ajoutent de faux champs comme `X-Virus-Scan: Clean` pour donner une impression de légitimité.  




#### ✅ Pourquoi c’est important  
L’analyse des en-têtes constitue une preuve technique robuste : contrairement au corps du message, ces champs sont partiellement générés automatiquement par les serveurs SMTP et sont donc plus fiables pour retracer la route d’un e-mail.  




---

### 2️⃣ Analyse du corps du message, décoder la manipulation
Le corps du message révèle les techniques de **social engineering** (ingénierie sociale) employées pour pousser la victime à agir.  
  > 🎯 But : détecter l’ingénierie sociale et repérer liens/pièces jointes.  
  > 💡 Le ton, les formulations et la mise en page donnent souvent de précieux indices!  




#### ✨ Tips & Tricks
- Comparer HTML et texte  
  > 👉 Les liens cachés ou scripts malveillants sont souvent dans le HTML.  
- Survoler les liens sans cliquer  
  > 👉 Pour vérifier qu’ils correspondent au texte affiché.  
- Identifier les mots-clés d’urgence  
  > 👉 `urgent`, `verify`, `invoice`, `payment`, `account suspension`.  
- Vérifier images externes/tracking  
  > 👉 `<img src=` peut révéler des pixels de suivi ou exfiltration.  
  




#### ⚠️ Indicateurs fréquents
- 🚩 Langage urgent ou menaçant :
  > Les messages qui créent un **sentiment d’urgence** - `Votre compte sera suspendu !!!` - cherchent à provoquer une réaction impulsive. 

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
Cette étape permet de cartographier la stratégie d’ingénierie sociale (ton, urgence, promesse, peur, curiosité). Les leviers psychologiques sont souvent plus révélateurs que la technique utilisée.  





---

### 3️⃣ Analyse des liens et pièces jointes, vecteurs d’infection

Les liens et les pièces jointes sont les deux principaux **vecteurs techniques** utilisés dans les campagnes de phishing.  
Ils permettent soit de rediriger la victime vers une page piégée, soit de lui faire exécuter directement un code malveillant.  
  > 🎯 But : Identifier le payload et retracer les serveurs/liens utilisés par l’attaquant pour l’attaque.  
  > ⚠️ Toujours analyser ces éléments dans un environnement isolé (sandbox/VM).  





---

### 🔗 Analyse des liens
Un lien malveillant peut rediriger vers un faux site de connexion, un téléchargement de malware ou une infrastructure C2.   
> 💡 Les cybercriminels utilisent souvent des domaines compromis, des raccourcisseurs d’URL ou des adresses IP brutes.  




#### ✨ Tips & Tricks
- Ne jamais cliquer directement  
  > 👉 Utiliser un service d’expansion d’URL (`unshorten.it`) ou ouvrir le lien dans une sandbox/VM isolée.   
- Analyser la réputation de l’URL  
  > 👉 Via `VirusTotal`, `URLhaus` ou `PhishTool` (noter le nombre de détections).  
- Vérifier le certificat SSL/TLS (nom de domaine, validité, autorité).
  > 👉 Les certificats auto-signés ou mismatched sont suspects.  
- Chercher des patterns suspects  
  > 👉 IP sans domaine, noms trompeurs (ex. `login-update-secure.com`), redirections en chaîne.    




#### ⚠️ Indicateurs fréquents
- 🚩 URL raccourcie ou masquée (`bit.ly`, `tinyurl`, etc.)  
- 🚩 Domaine récemment créé ou sans enregistrement WHOIS valide.  
- 🚩 Page hébergée sur IP brute (`http://185.203.116[.]55/invoice`).  
- 🚩 Domaine ressemblant à un vrai service (`micros0ft-support.com`).  
- 🚩 Présence d’un téléchargement automatique ou d’un fichier exécutable.





#### ✅ Pourquoi c’est important  
L’analyse des liens permet de **cartographier la chaîne d’infection** et de remonter vers l’infrastructure malveillante (hébergeur, C2, campagnes similaires).





---

### 📎 Analyse des pièces jointes  
Les pièces jointes servent souvent à **livrer la charge utile** (payload) : malware, script, macro ou installeur déguisé.  
> 💡 Une analyse minutieuse de leur format et de leur comportement peut révéler la nature de l’attaque.  






#### ✨ Tips & Tricks
- Calculer le hash (SHA256, MD5) du fichier avant ouverture  
  > 👉 `sha256sum fichier` pour vérifier sa réputation sur `VirusTotal` ou `MalwareBazaar`.  
- Vérifier le type réel du fichier  
  > 👉 `file fichier` (ex. un `.pdf` déguisé en `.exe`).  
- Analyser macros Office  
  > 👉 `olevba` ou `oledump` pour extraire et comprendre les macros malveillantes.  
- Tester en sandbox  
  > 👉 Any.Run, Hybrid Analysis ou VM isolée pour observer le comportement.  
- Méfiance avec archives protégées par mot de passe  
  > 👉 Souvent utilisées pour contourner les antivirus.   






#### ⚠️ Indicateurs fréquents
- 🚩 Extensions multiples : `Facture.pdf.exe`, `Reçu.docx.js`.  
- 🚩 Formats dangereux : `.exe`, `.scr`, `.vbs`, `.zip`, `.rar`.  
- 🚩 Taille ou contenu incohérents avec le contexte du mail.  
- 🚩 Pièce jointe inattendue ou non sollicitée.  
- 🚩 Archive protégée par mot de passe dont le code est donné dans le message.  






#### ✅ Pourquoi c’est important  
Les pièces jointes représentent la **porte d’entrée directe du malware**.  
Les analyser, c’est comprendre le vecteur initial de compromission et prévenir la propagation future dans le SI.  



---

#### ⚠️ Disclaimer
> Ce laboratoire est uniquement destiné à des fins éducatives et de formation. Ne reproduisez pas ces techniques sur des systèmes en production ou sans autorisation explicite. Tous les fichiers, liens et artefacts doivent être manipulés dans un environnement isolé et sécurisé.

