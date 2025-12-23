# xai_explainer.py - Version finale corrigée et fonctionnelle
# Port : 6008

from flask import Flask, request, jsonify
import requests
from lm_client import query_lm
from config import AUTH_TOKEN, RESPONDER_PORT

app = Flask(__name__)

@app.route('/explain', methods=['POST'])
def explain():
    if request.headers.get('Authorization') != f"Bearer {AUTH_TOKEN}":
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    if not data or 'event' not in data or 'analysis' not in data:
        return jsonify({"error": "Invalid payload"}), 400

    event = data['event']
    analysis = data['analysis']
    mitre = analysis.get('mitre_mapping', {})

    print(f"[XAI Explainer] Traitement événement {event.get('id', 'unknown')} - catégorie: {analysis.get('category', 'inconnue')}")

    mitre_info = ""
    if mitre:
        mitre_info = f"""
[CONTEXTE MITRE ATT&CK]
Technique : {mitre.get('technique_id', 'inconnue')} - {mitre.get('technique_name', 'inconnue')}
Tactique : {mitre.get('tactique', 'inconnue')}
Description : {mitre.get('description', 'inconnue')}
Mentionne cette technique dans ta justification.
"""

    enhanced_raw = event.get('raw', '') + mitre_info

    enriched_event = {
        "id": event.get("id", "unknown"),
        "kind": event.get("kind", "unknown"),
        "src_ip": event.get("src_ip", "unknown"),
        "raw": enhanced_raw,
        "ts": event.get("ts", ""),
    }

    print("[XAI Explainer] Envoi au LLM pour analyse enrichie...")
    lm_response = query_lm(enriched_event)

    explanation = "Aucune explication disponible."
    if lm_response:
        if 'justification' in lm_response:
            explanation = lm_response['justification'].strip()
        elif isinstance(lm_response, str):
            explanation = lm_response.strip()
        else:
            explanation = str(lm_response).strip()

    analysis['xai_explanation'] = explanation
    print(f"[XAI Explainer] Explication générée :\n{explanation}")

    responder_url = f"http://127.0.0.1:{RESPONDER_PORT}/respond"

    try:
        response = requests.post(
            responder_url,
            json=data,
            headers={"Authorization": f"Bearer {AUTH_TOKEN}", "Content-Type": "application/json"},
            timeout=20
        )
        print(f"[XAI Explainer] Forward vers Responder réussi (status: {response.status_code})")
        return jsonify(response.json()), response.status_code
    except Exception as e:
        print(f"[XAI Explainer] Erreur forward : {e}")
        return jsonify({"error": "Forward failed"}), 500

if __name__ == "__main__":
    print("[XAI Explainer] Démarrage sur le port 6008...")
    app.run(host='0.0.0.0', port=6008, debug=True)
