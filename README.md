# CMEK Log Bucket Setup & Key Rotation

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Python scripts for automating Customer-Managed Encryption Key (CMEK) setup and key rotation on Google Cloud Logging log buckets using the official Google Cloud Python client libraries.

Reference: [Cloud Logging CMEK documentation](https://cloud.google.com/logging/docs/routing/managed-encryption-storage#manage-key)

---

## Scripts

| Script | Purpose |
|--------|---------|
| `cmek_log_bucket_setup.py` | One-time setup — grants KMS permissions and creates a CMEK-enabled log bucket |
| `cmek_log_bucket_rotate.py` | Key rotation — toggles the bucket's CMEK key to force Cloud Logging to bind to the latest primary key version |

---

## Prerequisites

### APIs

The following APIs must be enabled in your project:

```bash
gcloud services enable cloudkms.googleapis.com logging.googleapis.com
```

### Python dependencies

```bash
pip install google-cloud-logging google-cloud-kms
```

### Authentication

The scripts use Application Default Credentials. Authenticate with one of:

```bash
gcloud auth application-default login          # local development
# or
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa-key.json  # service account key
```

### Required IAM roles

The caller (user or service account) needs the following permissions:

**For setup (`cmek_log_bucket_setup.py`):**

| Permission | Scope |
|-----------|-------|
| `logging.settings.get` | Project |
| `cloudkms.cryptoKeys.getIamPolicy` | CryptoKey |
| `cloudkms.cryptoKeys.setIamPolicy` | CryptoKey |
| `logging.buckets.create` | Project |

Predefined roles that satisfy this: `roles/logging.admin` + `roles/cloudkms.admin`

**For rotation (`cmek_log_bucket_rotate.py`):**

| Permission | Scope |
|-----------|-------|
| `logging.buckets.get` | Project |
| `logging.buckets.update` | Project |
| `cloudkms.cryptoKeys.get` | Both CryptoKeys |
| `cloudkms.cryptoKeys.create` | Key ring (only if auto-creating the temp key) |
| `cloudkms.cryptoKeys.getIamPolicy` | Both CryptoKeys |
| `cloudkms.cryptoKeys.setIamPolicy` | Temp CryptoKey |

Predefined roles that satisfy this: `roles/logging.admin` + `roles/cloudkms.admin`

---

## Usage

### Step 0 — Create a KMS key ring and key

If you don't already have a CryptoKey, create one in the same region as your intended log bucket:

```bash
gcloud kms keyrings create KEY_RING \
  --location=LOCATION \
  --project=PROJECT_ID

gcloud kms keys create KEY_NAME \
  --keyring=KEY_RING \
  --location=LOCATION \
  --purpose=encryption \
  --project=PROJECT_ID
```

The full key resource name will be:
```
projects/PROJECT_ID/locations/LOCATION/keyRings/KEY_RING/cryptoKeys/KEY_NAME
```

> **Important:** The KMS key and the log bucket must be in the same region.

### Step 1 — Create the CMEK-enabled log bucket

```bash
python3 cmek_log_bucket_setup.py \
  --project-id PROJECT_ID \
  --location LOCATION \
  --bucket-id BUCKET_ID \
  --kms-key-name projects/PROJECT_ID/locations/LOCATION/keyRings/KEY_RING/cryptoKeys/KEY_NAME
```

The script performs three sequential operations:

1. **GetSettings** — retrieves the project's Cloud Logging CMEK service account (`kms_service_account_id`)
2. **SetIamPolicy** — grants `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the CryptoKey to that service account
3. **CreateBucket** — creates the log bucket with `cmek_settings.kms_key_name` configured

Both steps 2 and 3 are idempotent: if the IAM binding already exists it is skipped, and if the bucket already exists creation is skipped without error.

**Example output:**

```
[Step 1] Calling GetSettings for: projects/my-project
[Step 1] Cloud Logging CMEK service account: service-123456789@gcp-sa-logging.iam.gserviceaccount.com

[Step 2] Fetching IAM policy for KMS key: projects/my-project/locations/us-central1/keyRings/my-ring/cryptoKeys/my-key
[Step 2] Granting 'roles/cloudkms.cryptoKeyEncrypterDecrypter' to 'serviceAccount:service-123456789@gcp-sa-logging.iam.gserviceaccount.com' ...
[Step 2] IAM policy updated successfully.

[Step 3] Creating log bucket 'my-bucket' under projects/my-project/locations/us-central1
[Step 3] CMEK key: projects/my-project/locations/us-central1/keyRings/my-ring/cryptoKeys/my-key
[Step 3] Log bucket created: projects/my-project/locations/us-central1/buckets/my-bucket

Done. CMEK log bucket setup completed successfully.
```

### Step 2 — Rotate the key

Run this whenever you want the bucket to pick up the latest primary version of its CMEK key. If the KMS key material itself needs rotating, create a new key version and promote it first (see [KMS key rotation](#kms-key-rotation)), then run this script.

```bash
python3 cmek_log_bucket_rotate.py \
  --project-id PROJECT_ID \
  --location LOCATION \
  --bucket-id BUCKET_ID \
  --kms-key-name projects/PROJECT_ID/locations/LOCATION/keyRings/KEY_RING/cryptoKeys/KEY_NAME
```

A `--temp-kms-key-name` can optionally be supplied to use an existing key for the toggle step. If omitted, a key named `<original-key>-rotation-temp` is created automatically in the same key ring.

The script performs five operations:

1. **GetBucket** — reads the bucket's current CMEK key and logging service account
2. **GetCryptoKey / CreateCryptoKey + SetIamPolicy** — ensures a temporary key exists and the logging SA can use it
3. **UpdateBucket** — switches the bucket to the temporary key
4. **UpdateBucket** — switches the bucket back to the original key
5. **GetBucket + GetCryptoKey** — verifies `kmsKeyVersionName` now matches the current primary version

Steps 2, 3, and 4 implement the [documented toggle approach](https://cloud.google.com/logging/docs/routing/managed-encryption-storage#manage-key): switching away from a key and back forces Cloud Logging to re-bind to the current primary version.

**Example output:**

```
[Step 1] Fetching bucket: projects/my-project/locations/us-central1/buckets/my-bucket
[Step 1] Current CMEK key:        .../cryptoKeys/my-key
[Step 1] Logging service account: service-123456789@gcp-sa-logging.iam.gserviceaccount.com

[Step 2] Creating temporary key: .../cryptoKeys/my-key-rotation-temp
[Step 2] Temporary key created.
[Step 2] Granted 'roles/cloudkms.cryptoKeyEncrypterDecrypter' to 'serviceAccount:...' on temp key.

[Step 3] Updating bucket CMEK key to: .../cryptoKeys/my-key-rotation-temp
[Step 3] Bucket CMEK key is now: .../cryptoKeys/my-key-rotation-temp

[Step 4] Updating bucket CMEK key to: .../cryptoKeys/my-key
[Step 4] Bucket CMEK key is now: .../cryptoKeys/my-key

[Step 5] Verifying rotation for bucket: projects/my-project/locations/us-central1/buckets/my-bucket
[Step 5] Bucket kmsKeyVersionName: .../cryptoKeys/my-key/cryptoKeyVersions/3
[Step 5] Key current primary:      .../cryptoKeys/my-key/cryptoKeyVersions/3
[Step 5] Rotation verified — bucket is bound to the latest primary version.

Done. Key rotation completed successfully.
```

---

## How CMEK key rotation works

Cloud Logging tracks which specific key version a bucket is using via `kmsKeyVersionName`. This field is set at bucket creation time and does **not** update automatically when the KMS key's primary version changes — a bucket update is required to force Cloud Logging to re-evaluate the key.

The rotation script implements the documented toggle approach: switching the bucket to a temporary key and back causes Cloud Logging to re-bind to the current primary version of the original key, updating `kmsKeyVersionName` in the process.

### KMS key rotation

Before running the rotation script, rotate the underlying KMS key material if needed:

```bash
# Create a new key version
gcloud kms keys versions create \
  --key=KEY_NAME --keyring=KEY_RING --location=LOCATION --project=PROJECT_ID

# Promote it to primary (replace N with the new version number)
gcloud kms keys versions set-primary N \
  --key=KEY_NAME --keyring=KEY_RING --location=LOCATION --project=PROJECT_ID
```

Then run `cmek_log_bucket_rotate.py` to bind the bucket to the new version.

### Key version lifecycle

Old key versions remain `ENABLED` after rotation so that Cloud KMS can still decrypt previously written log data:

```
After rotation:   old version = ENABLED (readable), new version = ENABLED + primary (read/write)
After retention:  old version can be DISABLED then DESTROYED once no log data encrypted under it remains
```

> **Warning:** Destroying a key version before all log data encrypted under it has been purged will make that data permanently unreadable. Only destroy old versions after the bucket's retention period has elapsed.

### Automatic KMS key rotation

To have Cloud KMS rotate the key material automatically on a schedule:

```bash
gcloud kms keys update KEY_NAME \
  --keyring=KEY_RING \
  --location=LOCATION \
  --rotation-period=90d \
  --next-rotation-time=$(date -d '+90 days' --iso-8601=seconds) \
  --project=PROJECT_ID
```

Note that automatic KMS rotation only rotates the key material — you still need to run `cmek_log_bucket_rotate.py` afterwards to update the bucket's `kmsKeyVersionName` binding.

---

## CLI reference

### `cmek_log_bucket_setup.py`

```
usage: cmek_log_bucket_setup.py --project-id PROJECT_ID --location REGION
                                 --bucket-id BUCKET_ID --kms-key-name KMS_KEY_RESOURCE_NAME

arguments:
  --project-id      GCP project ID that owns the log bucket
  --location        Region for the log bucket (must match the KMS key location)
  --bucket-id       Short ID for the new log bucket
  --kms-key-name    Full CryptoKey resource name
                    Format: projects/[P]/locations/[L]/keyRings/[R]/cryptoKeys/[K]
```

### `cmek_log_bucket_rotate.py`

```
usage: cmek_log_bucket_rotate.py --project-id PROJECT_ID --location REGION
                                  --bucket-id BUCKET_ID --kms-key-name KMS_KEY_RESOURCE_NAME
                                  [--temp-kms-key-name TEMP_KMS_KEY_RESOURCE_NAME]

arguments:
  --project-id          GCP project ID that owns the log bucket
  --location            Region of the log bucket and KMS key
  --bucket-id           Short ID of the CMEK-protected log bucket
  --kms-key-name        Full resource name of the original CryptoKey
                        Format: projects/[P]/locations/[L]/keyRings/[R]/cryptoKeys/[K]
  --temp-kms-key-name   (optional) Full resource name of a temporary CryptoKey for the toggle step.
                        Must be in the same location. If omitted, a key named
                        <original-key>-rotation-temp is created automatically in the same key ring.
```
