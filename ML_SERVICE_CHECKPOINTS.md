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

## Checkpoint 2 - Service validation and provider normalization fixes

What changed:
- `ddos_shield_v2/providers/ipwho.py` was corrected so binary-style provider flags return `0` instead of empty strings when false.
- `app.py` now reads debug mode from environment instead of always starting Flask with `debug=True`.

Verification:
- Local `/predict` testing succeeded for public IPv4 input.
- Invalid and private IP checks behaved as expected.
- `py -m compileall .` completed successfully after the fixes.

Why this matters:
- Feature values sent into the saved preprocessor are more consistent with the training pipeline.
- The local/dev Flask entrypoint is safer and closer to a production deployment setup.

## Checkpoint 3 - Team Cymru DNS fallback restored live ASN lookups

Issue found:
- Team Cymru lookups had started failing for all tested IPs with `cymru_error = "timeout"`.

Root cause:
- The Python DNS resolver was using the local/system DNS server first, and that resolver was timing out on `*.cymru.com` TXT lookups even though the records themselves were valid.

Fix applied:
- `ddos_shield_v2/providers/team_cymru.py` now keeps the system resolver as the primary path but falls back to public DNS resolvers when the local resolver times out or has no nameserver response.
- The fallback nameservers default to `1.1.1.1,8.8.8.8` and can be overridden with `DDS_DNS_NAMESERVERS`.

Verification:
- A direct feature-build test for `8.8.8.8` now returns:
  - `cymru_success = 1`
  - ASN name populated
  - prefix populated

## Checkpoint 4 - Team Cymru latency reduced for live predictions

Issue found:
- Even after the fallback logic was added, the live service could still feel slow and occasionally return `cymru_success = 0` because the system DNS resolver was still being tried before the known-good public resolvers.

Fix applied:
- `ddos_shield_v2/providers/team_cymru.py` now prefers the configured public fallback resolvers first and only falls back to the system resolver afterward.

Verification:
- A direct `predict_one('8.8.8.8')` run completed in about 2.6 seconds.
- The returned provider status showed `cymru_success = 1`.
