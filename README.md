## 🐟 SOC-Phishing-LAB 
Ce dépôt contient mes analyses personnelles d'e-mails de phishing.  

> 💡 Chaque cas inclut des notes détaillées, des indicateurs de compromission (IOCs) et la méthodologie utilisée.  

---

### 🎯 Objectif
Simuler une enquête SOC centrée sur un **email de phishing** pour pratiquer :  
- l’analyse d’en-têtes (SPF / DKIM / DMARC / Received),   
- l’enrichissement OSINT (réputation IP / domaine),    
- l’analyse des liens et pièces jointes,   
- l’extraction et le formatage d’IOCs pour le signalement et la mitigation,  
- la production de rapport.  

---


### 🧰 Outils
- **[VMware Workstation Pro](https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion)** – Hyperviseur pour analyses isolées  
- **[Any.Run](https://any.run/)** – Sandbox interactive pour observer le comportement des fichiers et liens malveillants  
- **[CyberChef](https://gchq.github.io/CyberChef/)** – Outils de décodage, décompression et transformation pour extraire IOCs et analyser payloads  
- **[MITRE ATT&CK](https://attack.mitre.org/)** – Référentiel des tactiques, techniques et procédures (TTP) pour contextualiser les observables
- **[URLhaus](https://urlhaus.abuse.ch/)** – Vérification des URLs malveillantes et contexte des campagnes  
- **[MalwareBazaar](https://bazaar.abuse.ch/)** – Répertoire d’échantillons malware pour identifier des artefacts connus  
- **[VirusTotal](https://www.virustotal.com/gui/home/url)** – Réputation des fichiers et URLs (agrégateur multi-source)  
- **OSINT général** – Recherche d’informations publiques sur IP, domaines, URLs, emails et infrastructures (AbuseIPDB, WHOIS, Passive DNS, Shodan)



---

### 📂 Index des cas étudiés
1. [PhishStrike - OCT25](SOC-Phishing/PhishStrike.md) – Analyse forensique d’un courriel de phishing (fausse facture)

*(La liste sera mise à jour au fur et à mesure que je progresse à travers les exercices)*


---

#### ⚠️ Disclaimer
> Ce laboratoire est uniquement destiné à des fins éducatives et de formation. Ne reproduisez pas ces techniques sur des systèmes en production ou sans autorisation explicite. Tous les fichiers, liens et artefacts doivent être manipulés dans un environnement isolé et sécurisé.

