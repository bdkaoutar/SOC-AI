# xai_explainer.py
# Atelier D - Module d'explicabilité IA (XAI) - VERSION CORRIGÉE
# Port : 6008

from flask import Flask, request, jsonify
import requests
from lm_client import query_lm
from config import AUTH_TOKEN, RESPONDER_PORT

app = Flask(__name__)

@app.route('/explain', methods=['POST'])
def explain():
    # Vérification du token
    if request.headers.get('Authorization') != f"Bearer {AUTH_TOKEN}":
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    if not data or 'event' not in data or 'analysis' not in data:
        return jsonify({"error": "Invalid payload"}), 400

    event = data['event']
    analysis = data['analysis']
    mitre = analysis.get('mitre_mapping', {})

    print(f"[XAI Explainer] Traitement événement {event.get('id', 'unknown')} - catégorie: {analysis.get('category', 'inconnue')}")

    # Construction d'un raw enrichi avec les infos MITRE pour que le LLM principal les utilise dans sa justification
    mitre_info = ""
    if mitre:
        mitre_info = f"""
[CONTEXTE MITRE ATT&CK]
Technique : {mitre.get('technique_id', 'inconnue')} - {mitre.get('technique_name', 'inconnue')}
Tactique : {mitre.get('tactique', 'inconnue')}
Description : {mitre.get('description', 'inconnue')}
Mentionne cette technique dans ta justification si pertinent.
"""

    enhanced_raw = event.get('raw', '') + mitre_info

    # Création d'un event enrichi pour le LLM
    enriched_event = {
        "id": event.get("id", "unknown"),
        "kind": event.get("kind", "unknown"),
        "src_ip": event.get("src_ip", "unknown"),
        "raw": enhanced_raw,
        "ts": event.get("ts", ""),
        # On peut ajouter d'autres champs si besoin
    }

    print("[XAI Explainer] Envoi au LLM pour analyse enrichie (justification inclura MITRE)...")
    lm_response = query_lm(enriched_event)  # Utilise le prompt système puissant de lm_client.py

    # Extraction de l'explication (justification du LLM)
    explanation = "Aucune explication disponible (erreur ou réponse incomplète du LLM)"
    
    if lm_response:
        # Le prompt de lm_client.py garantit un champ "justification"
        if 'justification' in lm_response:
            explanation = lm_response['justification'].strip()
        elif 'xai_explanation' in lm_response:
            explanation = lm_response['xai_explanation'].strip()
        else:
            # Fallback : on prend tout ce qui ressemble à du texte
            explanation = str(lm_response).strip()

    # Ajout de l'explication dans l'analyse
    analysis['xai_explanation'] = explanation
    print(f"[XAI Explainer] Explication générée :\n{explanation}")

    # Forward vers le vrai responder
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
    except requests.Timeout:
        print("[XAI Explainer] Timeout lors du forward vers Responder")
        return jsonify({"error": "Responder timeout"}), 504
    except Exception as e:
        print(f"[XAI Explainer] Erreur forward vers Responder : {e}")
        return jsonify({"error": "Forward failed", "details": str(e)}), 500


if __name__ == "__main__":
    print("[XAI Explainer] Démarrage sur le port 6008...")
    app.run(host='0.0.0.0', port=6008, debug=True)
