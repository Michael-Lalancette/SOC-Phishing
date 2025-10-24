# 🐟 SOC-Phishing
Ce dépôt propose des exercices pratiques pour simuler des enquêtes SOC sur des e‑mails de phishing. 

> 💡 Chaque cas inclut des notes techniques, les artefacts collectés et un rapport reproductible pour faciliter l'apprentissage et le partage d'intelligence.

---

## 🎯 Objectif 

Simuler des enquêtes SOC centrées sur des e‑mails de phishing afin de développer et documenter des compétences opérationnelles en :  

#### **Analyse technique des e‑mails**
> Lecture des en‑têtes SMTP, identification des *received hops*, validation SPF/DKIM/DMARC, analyse des incohérences et interprétation des résultats d'authentification.  

#### **Détection via réputation et OSINT**
> Recherche et vérification de domaines, IPs et URLs via VirusTotal, AbuseIPDB, URLhaus, Passive DNS, WHOIS et analyse de l'infrastructure malveillante.  

#### **Analyse des vecteurs**
> Expansion des URLs (shorteners), inspection des redirections, analyse des pages de phishing, extraction des artefacts liés et cartographie de la chaîne d'attaque.  

#### **Gestion des pièces jointes**
> Identification du type réel (file signature), calcul des hashes (SHA256/MD5), analyse statique (macros, scripts) et dynamique en environnement isolé (sandbox).  

#### **Contextualisation tactique**
> Corrélation des observables avec le framework **MITRE ATT&CK** pour classifier les TTPs (Tactics, Techniques, Procedures).  

#### **Production opérationnelle**
> Rédaction de rapports d'incident structurés et actionnables, documentation des IOCs (Indicators of Compromise), recommandations de mitigation immédiates (blocage, règles EDR/SIEM, quarantaine).  

---

## 🧰 Outils Utilisés

#### Infrastructure d'analyse
- **[VMware Workstation Pro](https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion)**
  > Hyperviseur pour créer des environnements d'analyse isolés et sécurisés

#### Analyse dynamique
- **[Any.Run](https://any.run/)**
  > Sandbox interactive pour observer en temps réel le comportement des fichiers et liens malveillants  
- **[Joe Sandbox](https://www.joesandbox.com/)**
  > Plateforme d'analyse automatisée avancée avec détection comportementale approfondie et rapports détaillés
- **[Tria.ge](https://tria.ge/)**
  > Service cloud d’analyse rapide orienté détection de RATs, stealers et extraction automatique d’IOCs.  

#### Threat Intelligence et réputation
- **[VirusTotal](https://www.virustotal.com/gui/home/url)**
  > Analyse multi-moteurs pour réputation des fichiers, URLs, domaines et adresses IP  
- **[URLhaus](https://urlhaus.abuse.ch/)**
  > Base de données d'URLs malveillantes avec contexte des campagnes actives  
- **[MalwareBazaar](https://bazaar.abuse.ch/)**
  > Répertoire d'échantillons de malware pour identifier des artefacts connus et leur provenance  
- **[AbuseIPDB](https://www.abuseipdb.com/)**
  > Réputation et historique d'abus des adresses IP  
- **[PhishTank](https://phishtank.org/)**
  > Base de données collaborative de sites de phishing vérifiés  
- **[Malpedia](https://malpedia.caad.fkie.fraunhofer.de/)**
  > Base de connaissances pour identifier les familles de malwares, leurs caractéristiques techniques et comportements  
- **[CyberChef](https://gchq.github.io/CyberChef/)**
  > Suite d'outils de décodage, décompression et transformation pour extraire IoCs et analyser payloads encodés  

#### Frameworks et référentiels
- **[MITRE ATT&CK](https://attack.mitre.org/)**
  > Référentiel des tactiques, techniques et procédures (TTP) pour contextualiser les observables et mapper les attaques  

#### OSINT et investigation
+ **[DomainTools](https://whois.domaintools.com/)**
+   > WHOIS enrichi, historique DNS, identification ASN et géolocalisation IP
- **[urlscan.io](https://urlscan.io/)**
  > Capture et analyse automatisée de pages web suspectes  
- **[Shodan](https://www.shodan.io/)**
  > Recherche sur l'infrastructure exposée (serveurs, services)  


---

## 📂 Index des cas étudiés

| Cas | Date | Type | Vecteur | Statut |
|-----|------|------|---------|--------|
| [PhishStrike](Cas/PhishStrike/) | Oct 2025 | Multi-malware (BitRAT/AsyncRAT/CoinMiner) | Faux invoice (Lien malveillant - loader) | ✅ Complété |

*(Le catalogue s'enrichira régulièrement au fur et à mesure des analyses.)*



---

#### ⚠️ Disclaimer
> Ce dépôt est uniquement destiné à des fins éducatives et de formation. Ne reproduisez pas ces techniques sur des systèmes en production ou sans autorisation explicite. Tous les fichiers, liens et artefacts doivent être manipulés dans un environnement isolé et sécurisé.

---


*Dernière mise à jour : Octobre 2025*



