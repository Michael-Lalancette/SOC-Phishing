# 🐟 SOC-Phishing
Ce dépôt propose des exercices pratiques pour simuler des enquêtes SOC sur des e‑mails de phishing. 

> 💡 Chaque cas inclut des notes techniques, les artefacts collectés et un rapport reproductible pour faciliter l'apprentissage et le partage d'intelligence.

---

## 🎯 Objectif 

Simuler des enquêtes SOC centrées sur des e‑mails de phishing afin de développer et documenter des compétences opérationnelles en :  

#### 🔍 **Analyse technique des e‑mails**
> Lecture des en‑têtes SMTP, identification des *received hops*, validation SPF/DKIM/DMARC, analyse des incohérences et interprétation des résultats d'authentification.  

#### 🌐 **Détection via réputation et OSINT**
> Recherche et vérification de domaines, IPs et URLs via VirusTotal, AbuseIPDB, URLhaus, Passive DNS, WHOIS et analyse de l'infrastructure malveillante.  

#### 🔗 **Analyse des vecteurs**
> Expansion des URLs (shorteners), inspection des redirections, analyse des pages de phishing, extraction des artefacts liés et cartographie de la chaîne d'attaque.  

#### 📎 **Gestion des pièces jointes**
> Identification du type réel (file signature), calcul des hachages (SHA256/MD5), analyse statique (macros, scripts) et dynamique en environnement isolé (sandbox).  

#### 🎯 **Contextualisation tactique**
> Corrélation des observables avec le framework **MITRE ATT&CK** pour classifier les TTPs (Tactics, Techniques, Procedures) et prioriser les réponses incident.  

#### 📝 **Production opérationnelle**
> Rédaction de rapports d'incident structurés et actionnables, documentation des IoCs (Indicators of Compromise), recommandations de mitigation immédiates (blocage, règles EDR/SIEM, quarantaine) et partage de threat intelligence.  

---

## 🧰 Outils Utilisés

#### 🖥️ Infrastructure d'analyse
- **[VMware Workstation Pro](https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion)**
  > Hyperviseur pour créer des environnements d'analyse isolés et sécurisés

#### 🔬 Analyse dynamique
- **[Any.Run](https://any.run/)**
  > Sandbox interactive pour observer en temps réel le comportement des fichiers et liens malveillants  
- **[Hybrid Analysis](https://www.hybrid-analysis.com/)**
  > Sandbox multi-moteurs pour analyse comportementale approfondie  
- **[Joe Sandbox](https://www.joesandbox.com/)**
  > Plateforme d'analyse automatisée avancée avec détection comportementale approfondie et rapports détaillés  

#### 🧠 Threat Intelligence et réputation
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

#### 📊 Frameworks et référentiels
- **[MITRE ATT&CK](https://attack.mitre.org/)**
  > Référentiel des tactiques, techniques et procédures (TTP) pour contextualiser les observables et mapper les attaques  
- **[MISP](https://www.misp-project.org/)**
  > Plateforme de partage de threat intelligence (optionnel pour corrélation avancée)  

#### 🔎 OSINT et investigation
- **[MXToolbox](https://mxtoolbox.com/)**
  > Vérification DNS, headers SMTP, SPF/DKIM/DMARC et blacklists  
- **[urlscan.io](https://urlscan.io/)**
  > Capture et analyse automatisée de pages web suspectes  
- **[SecurityTrails](https://securitytrails.com/)**
  > Historique DNS et cartographie d'infrastructure  
- **[Shodan](https://www.shodan.io/)**
  > Recherche sur l'infrastructure exposée (serveurs, services)  

---

## 📂 Structure du dépôt

```
SOC-Phishing/
├── README.md                    # Ce fichier
├── Guide-Analyse-Phishing.md    # Méthodologie complète d'analyse
├── Templates/                   # Modèles de rapports et checklists
│   ├── Rapport-Template.md
├── Cas/                         # Études de cas
│   ├── PhishStrike/
│   │   ├── README.md            # Rapport d'analyse
│   │   ├── RAPPORT.md           # Rapport SOC
│   │   └── images/              # Répertoire d'images
│   └── [Futurs cas...]
```

---

## 📂 Index des cas étudiés

| Cas | Date | Type | Vecteur | Statut |
|-----|------|------|---------|--------|
| [PhishStrike](Cases/PhishStrike/) | Oct 2025 | RAT/CoinMiner | Faux invoice + lien | ✅ Complété |

*(Le catalogue s'enrichira régulièrement au fur et à mesure des analyses.)*



---

#### ⚠️ Disclaimer
> Ce laboratoire est uniquement destiné à des fins éducatives et de formation. Ne reproduisez pas ces techniques sur des systèmes en production ou sans autorisation explicite. Tous les fichiers, liens et artefacts doivent être manipulés dans un environnement isolé et sécurisé.

---

**⭐ Si ce projet vous aide dans votre apprentissage, n'hésitez pas à lui donner une étoile !**

*Dernière mise à jour : Octobre 2025*



