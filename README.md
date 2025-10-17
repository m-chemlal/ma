# TRUSTED AI SOC LITE

Prototype local d'un SOC autonome et explicable combinant **scan Nmap**, **analyse IA** et **supervision en temps réel**. Le projet s'aligne avec le cahier des charges fourni et évite l'utilisation de Wazuh pour la couche d'explicabilité en privilégiant un tableau de bord Streamlit personnalisable.

## ✨ Fonctionnalités principales

- **Scan automatique** : script Python basé sur Nmap (avec mode simulé si Nmap n'est pas disponible).
- **Moteur IA + XAI** : détection statistique sans dépendances externes + explications heuristiques (compatibles SHAP en option).
- **Journalisation d'audit** : toutes les décisions IA et actions automatiques sont historisées en JSONL.
- **Réponses automatisées** : génération de tickets, blocage IP simulé, envoi d'alertes e-mail simulées.
- **Dashboard temps réel** : interface Streamlit reproduisant la maquette demandée.
- **Intégration Wazuh** : déploiement optionnel via Docker Compose pour collecter et corréler les logs enrichis.

## 🗂️ Structure

```
├── docker/
│   ├── dashboard.Dockerfile
│   └── pipeline.Dockerfile
├── docker-compose.yml
├── pyproject.toml
├── src/trusted_ai_soc_lite/
│   ├── ai/
│   │   ├── engine.py
│   │   └── xai.py
│   ├── audit/
│   │   └── logger.py
│   ├── dashboard/
│   │   └── app.py
│   ├── responder/
│   │   └── actions.py
│   ├── scanners/
│   │   └── nmap_scanner.py
│   ├── config.py
│   ├── data_models.py
│   ├── pipeline.py
│   └── __main__.py
└── data/
    └── .gitkeep
```

## 🚀 Démarrage rapide

### 1. Installation locale

```bash
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .
```

> ℹ️ Les dépendances lourdes (Streamlit, pandas, SHAP, python-nmap) sont désormais optionnelles.
> Installez-les selon vos besoins via `pip install -e .[dashboard]`, `pip install -e .[nmap]` ou `pip install -e .[explainability]`.

### 2. Exécuter un cycle complet

```bash
python -m trusted_ai_soc_lite
```

Un fichier d'alerte JSON est créé dans `data/alerts`, les scans sont historisés dans `data/scans` et l'audit dans `data/audit_log.jsonl`.

> 💡 En environnement isolé sans accès Internet, lancez simplement `PYTHONPATH=src python -m trusted_ai_soc_lite`.

### 3. Lancer le tableau de bord Streamlit

```bash
pip install -e .[dashboard]
streamlit run src/trusted_ai_soc_lite/dashboard/app.py
```

### 4. Déploiement Docker Compose

```bash
docker compose up --build
```

Services principaux :

- `pipeline` : exécute en boucle le pipeline d'IA toutes les 5 minutes.
- `dashboard` : interface Streamlit (port 8501).
- `wazuh` & `wazuh-dashboard` : stack Wazuh optionnelle pour corrélation SIEM (port 5601 pour l'UI).

## 🧠 Notes IA & XAI

- Le moteur IA s'appuie sur des moyennes mobiles et l'écart type des caractéristiques extraites pour détecter les dérives, sans dépendances externes.
- Les explications utilisent un différentiel par rapport à la baseline historique, avec un fallback normalisé. L'installation de `shap` reste possible en option pour des analyses plus fines.

## 🛡️ Audit et conformité

Chaque action automatique et chaque alerte est historisée via `data/audit_log.jsonl`. Ce format JSONL facilite l'ingestion par Wazuh ou tout autre SIEM.

## 📄 Livrables fournis

- Scripts de scan, moteur IA, actions automatiques et audit logging.
- Dashboard Streamlit inspiré de la maquette.
- Configuration Docker Compose incluant l'intégration Wazuh.
- Documentation de mise en route (ce README).

## 📚 Ressources complémentaires

- [Nmap](https://nmap.org)
- [Z-score anomaly detection](https://en.wikipedia.org/wiki/Standard_score)
- [Streamlit](https://streamlit.io)
- [Wazuh Docker](https://github.com/wazuh/wazuh-docker)
