# mitre_mapper.py
# Atelier D - Module de mapping MITRE ATT&CK
# Port : 6007
# Agit comme proxy entre analyzer et xai_explainer

from flask import Flask, request, jsonify
import requests
import pandas as pd
import re
from config import AUTH_TOKEN, XAI_EXPLAINER_URL, RESPONDER_PORT

app = Flask(__name__)

# Chargement de la base MITRE au démarrage
print("[MITRE Mapper] Chargement de mitre_base.csv...")
try:
    MITRE_BASE = pd.read_csv('mitre_base.csv')
    print(f"[MITRE Mapper] {len(MITRE_BASE)} règles MITRE chargées")
except FileNotFoundError:
    print("[MITRE Mapper] ERREUR : mitre_base.csv non trouvé !")
    MITRE_BASE = pd.DataFrame()

@app.route('/mitre_map', methods=['POST'])
def mitre_map():
    # Vérification du token
    if request.headers.get('Authorization') != f"Bearer {AUTH_TOKEN}":
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    if not data or 'event' not in data or 'analysis' not in data:
        return jsonify({"error": "Invalid payload"}), 400

    event = data['event']
    analysis = data['analysis']
    raw_log = event.get('raw', '')
    category = analysis.get('category', '').lower()

    print(f"[MITRE Mapper] Traitement événement {event.get('id', 'unknown')} - catégorie: {category}")

    mapped = None
    for _, row in MITRE_BASE.iterrows():
        match = False

        if row['match_type'] == 'category' and row['match_value'].lower() == category:
            match = True
        elif row['match_type'] == 'regex':
            pattern = row['match_value']
            if re.search(pattern, raw_log, re.IGNORECASE):
                match = True

        if match:
            mapped = {
                "tactique": row['tactique'],
                "technique_id": row['technique_id'],
                "technique_name": row['technique_name'],
                "description": row['description']
            }
            print(f"[MITRE Mapper] → Match trouvé : {row['technique_id']} - {row['technique_name']}")
            break  # Premier match uniquement

    # Ajout du mapping
    analysis['mitre_mapping'] = mapped if mapped else None
    if not mapped:
        print("[MITRE Mapper] Aucun mapping MITRE trouvé")

    # Forward vers xai_explainer (port 6008)
    next_url = XAI_EXPLAINER_URL  # Doit être http://127.0.0.1:6008/explain dans config.py

    try:
        response = requests.post(
            next_url,
            json=data,
            headers={"Authorization": f"Bearer {AUTH_TOKEN}", "Content-Type": "application/json"},
            timeout=15
        )
        print(f"[MITRE Mapper] Forward vers XAI Explainer réussi (status: {response.status_code})")
        return jsonify(response.json()), response.status_code
    except requests.Timeout:
        print("[MITRE Mapper] Timeout lors du forward vers XAI Explainer")
        return jsonify({"error": "XAI Explainer timeout"}), 504
    except Exception as e:
        print(f"[MITRE Mapper] Erreur lors du forward vers XAI : {e}")
        return jsonify({"error": "Forward to XAI failed", "details": str(e)}), 500


if __name__ == "__main__":
    print("[MITRE Mapper] Démarrage sur le port 6007...")
    app.run(host='0.0.0.0', port=6007, debug=True)
