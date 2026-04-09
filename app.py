from __future__ import annotations

from pathlib import Path

from flask import Flask, jsonify, request

from predictor import MLPredictor


def create_app() -> Flask:
    app = Flask(__name__)
    predictor = MLPredictor(bundle_path=Path(__file__).with_name("ml_deployment_bundle.joblib"))

    @app.get("/")
    def root():
        return jsonify(
            {
                "service": "ddos-watch-ml-service",
                "status": "ok",
                "message": "Use GET /health or POST /predict",
            }
        )

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "service": "ddos-watch-ml-service"})

    @app.post("/predict")
    def predict():
        payload = request.get_json(silent=True) or {}
        ip = str(payload.get("ip", "")).strip()

        if not ip:
            return jsonify({"error": "Field 'ip' is required"}), 400

        try:
            result = predictor.predict_one(ip)
            return jsonify(result)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:  # pragma: no cover - defensive API boundary
            return jsonify({"error": f"Prediction failed: {exc}"}), 500

    return app


app = create_app()


if __name__ == "__main__":
    import os

    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=os.getenv("FLASK_DEBUG", "0") == "1")
