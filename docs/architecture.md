# Architecture TRUSTED AI SOC LITE

## Vue d'ensemble

```
[ Réseau interne ]
       |
       v
[Nmap Scanner] --> [Pipeline IA + XAI] --> [Audit Log JSONL]
                                |
                                +--> [Actions Automatisées]
                                |
                                +--> [Wazuh SIEM]
                                |
                                +--> [Dashboard Streamlit]
```

## Flux de données

1. **Nmap Scanner** (ou générateur simulé) produit des `ScanObservation` persistés dans `data/scans/`.
2. **Moteur IA** transforme chaque observation en vecteur de caractéristiques puis applique Isolation Forest.
3. **XAI** génère des `AnomalyInsight` avec SHAP ou un fallback déterministe.
4. **Alerte** : un `AlertRecord` est enregistré dans `data/alerts/` et envoyé à la couche d'automatisation.
5. **Actions** : scripts Python simulant blocage IP, ticketing, email. Chaque action est loguée dans `data/audit_log.jsonl`.
6. **Dashboard** : Streamlit lit les artefacts pour construire la vue en temps réel.
7. **Wazuh** : via Docker Compose, le dossier `data/` peut être monté pour ingestion et corrélation.

## Sécurité

- Toutes les communications inter-services sont internes au réseau Docker.
- Les mots de passe Wazuh sont définis via variables d'environnement dans `docker-compose.yml` et doivent être personnalisés pour la production.

## Évolutions possibles

- Ajout d'un connecteur OpenVAS ou d'une base de threat intelligence (MISP/OTX).
- Génération automatique de rapports PDF hebdomadaires.
- Implémentation d'actions réseau réelles (iptables, UFW) conditionnées par un flag de configuration.
