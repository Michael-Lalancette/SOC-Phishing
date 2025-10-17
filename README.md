## 🐟 SOC-Phishing
Dépôt personnel d'analyses d'e‑mails de phishing (cas pratiques, IOCs et méthodologies).  
> 💡 Chaque cas contient des notes détaillées, les artefacts collectés et un rapport d'analyse.  

---

### 🎯 Objectif
Simuler des enquêtes SOC centrées sur des **e‑mails de phishing** pour développer et documenter des compétences pratiques en :
- Analyse des en‑têtes (sender IP, Received hops, SPF/DKIM/DMARC)  
- Recherche de réputation (domaines, IPs, URLs)  
- Extraction et décodage des liens malveillants (expansion d’URL)  
- Traitement et hachage des pièces jointes (SHA256 / MD5)  
- Corrélation des observations avec **MITRE ATT&CK** pour identifier TTPs  
- Rédaction de rapports d’incident, listing d’IOCs et recommandations de mitigation


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

*(Le catalogue s’enrichira régulièrement au fur et à mesure des analyses.)*


---

#### ⚠️ Disclaimer
> Ce laboratoire est uniquement destiné à des fins éducatives et de formation. Ne reproduisez pas ces techniques sur des systèmes en production ou sans autorisation explicite. Tous les fichiers, liens et artefacts doivent être manipulés dans un environnement isolé et sécurisé.

