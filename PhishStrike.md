# PhishStrike — Analyse d’un e‑mail de phishing (fausse facture)
**Date :** Octobre 2025  
**Source :** [PhishStrike - CyberDefenders](https://cyberdefenders.org/blueteam-ctf-challenges/phishstrike/)  

> ⚠️ **Disclaimer :** Ce document est à but éducatif. Ne manipulez pas d’artefacts malveillants sur des machines non isolées. Toutes les actions actives (HEAD, expansion d’URL, exécution de pièces jointes) doivent être faites dans une VM/sandbox isolée.

---

## 1 — Résumé exécutif
Un e‑mail de type « facture » a été signalé. L’analyse a pour objectif d’identifier l’origine (sender IP / domaines), d’extraire et d’analyser tous les liens et pièces jointes, d’identifier les IOCs exploitables et de proposer des mesures de mitigation.
Résultats clés :  
- **Sender IP (last external hop) :** 
- **Domaines suspects :** 
- **URL malveillantes :** 
- **Pièce jointe :**  - **SHA256:** 
- **Conclusion provisoire :** courriel de phishing ciblé avec lien d’hameçonnage / pièce jointe potentiellement malveillante.

---

## 2 — Artefacts collectés
- Courriel original : 
- Pièce(s) jointe(s) extraites : 
- Liste des URLs extraites (non-cliquées) : 
- Hashes des pièces jointes : 
- Logs d’investigation (commande + horodatage) : 

---

## 3 — Analyse des en‑têtes (headers)
**Objectif :** trouver la sender IP, vérifier SPF/DKIM/DMARC et repérer les Received hops.
