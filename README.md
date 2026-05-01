# CMEK Log Bucket Setup & Key Rotation

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Python scripts for automating Customer-Managed Encryption Key (CMEK) setup and key rotation on Google Cloud Logging log buckets using the official Google Cloud Python client libraries.

Reference: [Cloud Logging CMEK documentation](https://cloud.google.com/logging/docs/routing/managed-encryption-storage#manage-key)

---

## Scripts

| Script | Purpose |
|--------|---------|
| `cmek_log_bucket_setup.py` | One-time setup — grants KMS permissions and creates a CMEK-enabled log bucket |
| `cmek_log_bucket_rotate.py` | Key rotation — creates a new key version and promotes it to primary |

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
| `cloudkms.cryptoKeyVersions.create` | CryptoKey |
| `cloudkms.cryptoKeys.update` | CryptoKey |
| `logging.buckets.get` | Project |

Predefined roles that satisfy this: `roles/cloudkms.admin` + `roles/logging.viewer`

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

Run this whenever you want to manually rotate the CryptoKey used by the bucket:

```bash
python3 cmek_log_bucket_rotate.py \
  --project-id PROJECT_ID \
  --location LOCATION \
  --bucket-id BUCKET_ID \
  --kms-key-name projects/PROJECT_ID/locations/LOCATION/keyRings/KEY_RING/cryptoKeys/KEY_NAME
```

The script performs three operations:

1. **CreateCryptoKeyVersion** — generates new key material as a new version
2. **UpdateCryptoKeyPrimaryVersion** — promotes the new version to primary; all subsequent log writes use it
3. **GetBucket + GetCryptoKey** — verifies the bucket's CMEK binding is intact and confirms the new primary version

**Example output:**

```
[Step 1] Creating new CryptoKeyVersion under: projects/my-project/locations/us-central1/keyRings/my-ring/cryptoKeys/my-key
[Step 1] New version created: .../cryptoKeys/my-key/cryptoKeyVersions/2
[Step 1] Version state: ENABLED

[Step 2] Promoting version '2' to primary on: .../cryptoKeys/my-key
[Step 2] New primary: .../cryptoKeys/my-key/cryptoKeyVersions/2
[Step 2] Primary state: ENABLED

[Step 3] Fetching log bucket: projects/my-project/locations/us-central1/buckets/my-bucket
[Step 3] Bucket CMEK key confirmed: .../cryptoKeys/my-key
[Step 3] Current primary version: .../cryptoKeys/my-key/cryptoKeyVersions/2
[Step 3] Primary version state:   ENABLED
[Step 3] Rotation verified — new log writes will be encrypted with the new primary version.

Done. Key rotation completed successfully.
```

---

## How CMEK key rotation works

Cloud Logging stores a reference to the **CryptoKey resource**, not to a specific version. When a new primary version is set on the key, Cloud Logging automatically uses it for all new log writes — no change to the bucket's `cmek_settings` is needed.

Old key versions remain `ENABLED` after rotation so that Cloud KMS can still decrypt previously written log data. The lifecycle is:

```
After rotation:   old version = ENABLED (readable), new version = ENABLED + primary (read/write)
After retention:  old version can be DISABLED then DESTROYED once no log data encrypted under it remains
```

> **Warning:** Destroying a key version before all log data encrypted under it has been purged will make that data permanently unreadable. Only destroy old versions after the bucket's retention period has elapsed.

To configure automatic rotation on the key itself (instead of using this script for manual rotation):

```bash
gcloud kms keys update KEY_NAME \
  --keyring=KEY_RING \
  --location=LOCATION \
  --rotation-period=90d \
  --next-rotation-time=$(date -d '+90 days' --iso-8601=seconds) \
  --project=PROJECT_ID
```

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

arguments:
  --project-id      GCP project ID that owns the log bucket
  --location        Region of the log bucket and KMS key
  --bucket-id       Short ID of the CMEK-protected log bucket
  --kms-key-name    Full CryptoKey resource name
                    Format: projects/[P]/locations/[L]/keyRings/[R]/cryptoKeys/[K]
```
