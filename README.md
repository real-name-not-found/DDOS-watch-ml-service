# DDoS Watch ML Service

This service exposes the trained XGBoost model through a small Flask API.

## What it does

- loads `ml_deployment_bundle.joblib`
- builds live features for one IP using the shared feature builder
- applies the saved preprocessor
- returns:
  - malicious probability
  - risk band
  - provider status
  - display context

## Local setup

Open a terminal in this folder and run:

```powershell
pip install -r requirements.txt
```

Important:

- the saved model bundle was created with `scikit-learn 1.6.1`
- so this service pins `scikit-learn==1.6.1`
- if you install a newer incompatible version first, reinstall from `requirements.txt`

## Local run

```powershell
python app.py
```

The API will start on:

- `http://localhost:8000`

## Test endpoints

### Health

```powershell
curl http://localhost:8000/health
```

### Predict

```powershell
curl -X POST http://localhost:8000/predict ^
  -H "Content-Type: application/json" ^
  -d "{\"ip\":\"8.8.8.8\"}"
```

## Important notes

- This ML API currently supports **public IPv4** input only.
- AbuseIPDB is not used inside this service during prediction.
- The Node backend will later call this service and merge its response with live AbuseIPDB + ipwho data.
