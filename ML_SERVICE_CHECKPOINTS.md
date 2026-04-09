# ML Service Checkpoints

## Checkpoint 1 - Service scaffold created

This folder was created to hold the Python ML API that will later be deployed to Render.

### Why this service exists

The trained model was built in Jupyter, but the live application needs a web API that can:

1. receive an IP address
2. build the same features used during training
3. run the trained XGBoost model
4. return:
   - malicious probability
   - risk band
   - basic display context

### Files currently in this folder

- `ml_deployment_bundle.joblib`
  - the saved trained model + preprocessor + thresholds bundle
- `feature_builder.py`
  - thin shared wrapper used by both dataset building and inference
- `ddos_shield_v2/`
  - provider clients and shared feature logic
- `predictor.py`
  - internal helper that loads the bundle and scores one IP
- `app.py`
  - Flask HTTP API entrypoint
- `requirements.txt`
  - Python packages needed by this service
- `.env.example`
  - sample local environment variable file
- `README.md`
  - local run instructions

### What this checkpoint does not do yet

- it is not integrated into the Node backend yet
- it is not deployed yet
- the frontend does not use it yet

### Next checkpoint

Checkpoint 2 will be:

1. install Python dependencies
2. run the Flask service locally
3. test `/health`
4. test `/predict`

### Important compatibility note discovered during first run

The first local run failed because:

- the saved `ml_deployment_bundle.joblib` was created with `scikit-learn 1.6.1`
- the local ML service environment was using `scikit-learn 1.8.0`

That mismatch caused:

- unpickle compatibility warnings
- a hard failure while loading the saved `ColumnTransformer`

Fix applied:

- `requirements.txt` now pins `scikit-learn==1.6.1`

So the next run must begin with reinstalling dependencies from the updated `requirements.txt`.
