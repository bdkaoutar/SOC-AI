# README - Atelier D : Intégration de Mapping MITRE ATT&CK et Explicabilité IA (XAI)

Ce document explique comment exécuter les agents pour **l’Atelier D**, qui ajoute :
- le **mapping MITRE ATT&CK** (via `mitre_mapper.py`)
- l’**explicabilité IA (XAI)** (via `xai_explainer.py`)

Ces modules s’intègrent dans le pipeline principal de détection de sécurité :  
`log_tailer → collector → analyzer → mitre_mapper → xai_explainer → responder`

---

## Objectifs de l’Atelier D

L’Atelier D modifie le flux de traitement afin d’inclure :

- **MITRE Mapping** : association des événements de sécurité à des techniques MITRE ATT&CK.
- **XAI Explanation** : génération d’explications en langage naturel pour les décisions de détection, via un LLM.

---

## Prérequis

### Environnement
- **Python** : version **3.11.0** ou supérieure  
- **Système** : Linux (accès aux logs système)

### Dépendances
```bash
pip install -r requirements.txt
```

### LM Studio
- Exécuté sur l’hôte Windows
- IP configurée dans `config.py` :
```python
LM_HOST_IP = "192.168.56.1"
```
- API accessible :
```
http://<LM_HOST_IP>:1234/v1/chat/completions
```

### Fichiers requis
- `mitre_base.csv`
- Logs :
  - `/var/log/auth.log`
  - `/var/log/ufw.log`
  - `/var/log/nginx/access.log`

### Configuration UFW
```bash
sudo ufw enable
sudo ufw logging on
sudo ufw logging low
sudo chmod 644 /var/log/ufw.log
```

---

## Configuration `config.py`

```python
ENABLE_MITRE_MAPPING = True
ENABLE_XAI = True

RESPONDER_URL = "http://127.0.0.1:6005/mitre_map"

MITRE_MAPPER_PORT = 6007
XAI_EXPLAINER_PORT = 6008

DRY_RUN = False
EMAIL_ENABLED = True
```


## Résultat attendu

- Détection des événements de sécurité
- Mapping MITRE ATT&CK
- Explication XAI en langage naturel
- Actions de réponse (alertes, blocage IP)

---

## Dépannage

- Vérifier les ports
- Vérifier l’accès à LM Studio
- Vérifier les permissions des logs
- Consulter les logs des agents

---

✅ Atelier D prêt à être exécuté.
