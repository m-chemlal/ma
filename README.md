# TRUSTED AI SOC LITE

Prototype local d'un SOC autonome et explicable combinant **scan Nmap**, **analyse IA** et **supervision en temps réel**. Le projet s'aligne avec le cahier des charges fourni et évite l'utilisation de Wazuh pour la couche d'explicabilité en privilégiant un tableau de bord Streamlit personnalisable.

## ✨ Fonctionnalités principales

- **Scan automatique** : script Python basé sur Nmap (avec mode simulé si Nmap n'est pas disponible).
- **Moteur IA + XAI** : détection d'anomalies via Isolation Forest et explications via SHAP (ou une pondération fallback).
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

### 2. Exécuter un cycle complet

```bash
python -m trusted_ai_soc_lite
```

Un fichier d'alerte JSON est créé dans `data/alerts`, les scans sont historisés dans `data/scans` et l'audit dans `data/audit_log.jsonl`.

### 3. Lancer le tableau de bord Streamlit

```bash
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

- L'Isolation Forest apprend en continu à partir des scans précédents (persistés dans `data/model_state.json`).
- Les explications utilisent SHAP si la dépendance est disponible ; sinon, un fallback normalisé fournit une interprétation qualitative.

## 🛡️ Audit et conformité

Chaque action automatique et chaque alerte est historisée via `data/audit_log.jsonl`. Ce format JSONL facilite l'ingestion par Wazuh ou tout autre SIEM.

## 📄 Livrables fournis

- Scripts de scan, moteur IA, actions automatiques et audit logging.
- Dashboard Streamlit inspiré de la maquette.
- Configuration Docker Compose incluant l'intégration Wazuh.
- Documentation de mise en route (ce README).

## 📚 Ressources complémentaires

- [Nmap](https://nmap.org)
- [Scikit-learn - Isolation Forest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)
- [Streamlit](https://streamlit.io)
- [Wazuh Docker](https://github.com/wazuh/wazuh-docker)
