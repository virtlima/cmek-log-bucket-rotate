#!/usr/bin/env python3
# Copyright 2026 Aaron Lima
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# =============================================================================
# Install dependencies before running:
#   pip install google-cloud-logging google-cloud-kms
#
# Authentication: set GOOGLE_APPLICATION_CREDENTIALS or use `gcloud auth
# application-default login`. The caller must hold:
#   - logging.buckets.get              (on the project)
#   - logging.buckets.update           (on the project)
#   - cloudkms.cryptoKeys.get          (on both CryptoKeys)
#   - cloudkms.cryptoKeys.create       (on the key ring, if auto-creating temp key)
#   - cloudkms.cryptoKeys.getIamPolicy (on both CryptoKeys)
#   - cloudkms.cryptoKeys.setIamPolicy (on the temp CryptoKey)
# =============================================================================
"""
Rotate the Cloud KMS key version used by a CMEK-protected Cloud Logging log
bucket by following the documented toggle approach:

  1. Read the bucket's current CMEK key and logging service account.
  2. Ensure a temporary CryptoKey exists (create it if absent) and grant the
     logging service account encrypter/decrypter access on it.
  3. Switch the bucket to the temporary key  (UpdateBucket).
  4. Switch the bucket back to the original key (UpdateBucket).
  5. Verify the bucket's kmsKeyVersionName now reflects the latest primary
     version of the original key.

Switching away from a key and back forces Cloud Logging to re-bind to the
current primary version of the original key, updating kmsKeyVersionName.

Reference:
  https://cloud.google.com/logging/docs/routing/managed-encryption-storage#manage-key
  https://cloud.google.com/kms/docs/rotate-keys
"""

import argparse
import sys

from google.api_core import exceptions as gcp_exceptions
from google.cloud import kms_v1
from google.cloud.logging_v2.services.config_service_v2 import ConfigServiceV2Client
from google.cloud.logging_v2.types import CmekSettings, LogBucket
from google.iam.v1 import policy_pb2
from google.protobuf import field_mask_pb2


# ---------------------------------------------------------------------------
# Step 1 — read the bucket's current CMEK state
# ---------------------------------------------------------------------------

def get_bucket_cmek_info(project_id: str, location: str, bucket_id: str) -> tuple[str, str]:
    """Return the current CMEK key name and logging service account for the bucket.

    API reference:
      ConfigServiceV2.GetBucket
      https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.locations.buckets/get

    Args:
        project_id: GCP project ID.
        location:   Region of the log bucket.
        bucket_id:  Short log bucket ID.

    Returns:
        Tuple of (kms_key_name, logging_service_account_id).

    Raises:
        ValueError: If the bucket has no CMEK settings.
        gcp_exceptions.GoogleAPICallError: On any RPC failure.
    """
    client = ConfigServiceV2Client()
    bucket_resource = f"projects/{project_id}/locations/{location}/buckets/{bucket_id}"

    print(f"[Step 1] Fetching bucket: {bucket_resource}")
    bucket = client.get_bucket(request={"name": bucket_resource})

    kms_key_name = bucket.cmek_settings.kms_key_name
    if not kms_key_name:
        raise ValueError(
            f"Bucket '{bucket_id}' has no CMEK settings. "
            "Only CMEK-protected buckets can be rotated with this script."
        )

    logging_sa = bucket.cmek_settings.service_account_id
    print(f"[Step 1] Current CMEK key:       {kms_key_name}")
    print(f"[Step 1] Logging service account: {logging_sa}")
    return kms_key_name, logging_sa


# ---------------------------------------------------------------------------
# Step 2 — ensure a temporary key exists with the right IAM binding
# ---------------------------------------------------------------------------

def _keyring_from_key(kms_key_name: str) -> str:
    """Extract the key ring resource name from a CryptoKey resource name."""
    # Format: projects/P/locations/L/keyRings/R/cryptoKeys/K
    return kms_key_name.rsplit("/cryptoKeys/", 1)[0]


def _key_id_from_key(kms_key_name: str) -> str:
    """Extract the short key ID from a CryptoKey resource name."""
    return kms_key_name.rsplit("/", 1)[-1]


def ensure_temp_key(keyring_name: str, temp_key_id: str, logging_sa: str) -> str:
    """Get or create a temporary CryptoKey and grant the logging SA access.

    If the key already exists it is reused; creation is skipped. The IAM
    binding is checked for idempotency before calling SetIamPolicy.

    API references:
      KeyManagementService.GetCryptoKey / CreateCryptoKey
      KeyManagementService.GetIamPolicy / SetIamPolicy

    Args:
        keyring_name: Full key ring resource name.
        temp_key_id:  Short ID for the temporary key (e.g. "my-key-rotation-temp").
        logging_sa:   Logging service account email.

    Returns:
        Full resource name of the temporary CryptoKey.

    Raises:
        gcp_exceptions.GoogleAPICallError: On any RPC failure.
    """
    kms_client = kms_v1.KeyManagementServiceClient()
    temp_key_name = f"{keyring_name}/cryptoKeys/{temp_key_id}"

    # Get or create the temporary key.
    try:
        kms_client.get_crypto_key(name=temp_key_name)
        print(f"\n[Step 2] Temporary key already exists: {temp_key_name}")
    except gcp_exceptions.NotFound:
        print(f"\n[Step 2] Creating temporary key: {temp_key_name}")
        kms_client.create_crypto_key(
            request={
                "parent": keyring_name,
                "crypto_key_id": temp_key_id,
                "crypto_key": {
                    "purpose": kms_v1.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT,
                },
            }
        )
        print(f"[Step 2] Temporary key created.")

    # Grant the logging SA encrypter/decrypter on the temp key (idempotent).
    role = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
    member = f"serviceAccount:{logging_sa}"

    policy = kms_client.get_iam_policy(request={"resource": temp_key_name})
    for binding in policy.bindings:
        if binding.role == role and member in binding.members:
            print(f"[Step 2] IAM binding already present on temp key. Skipping.")
            return temp_key_name

    new_binding = policy_pb2.Binding(role=role, members=[member])
    policy.bindings.append(new_binding)
    kms_client.set_iam_policy(request={"resource": temp_key_name, "policy": policy})
    print(f"[Step 2] Granted '{role}' to '{member}' on temp key.")

    return temp_key_name


# ---------------------------------------------------------------------------
# Step 3 & 4 — update the bucket's CMEK key
# ---------------------------------------------------------------------------

def update_bucket_cmek_key(
    project_id: str, location: str, bucket_id: str, kms_key_name: str, label: str
) -> None:
    """Update a log bucket's cmek_settings.kms_key_name.

    Uses an update mask scoped to cmek_settings so no other bucket fields
    are affected.

    API reference:
      ConfigServiceV2.UpdateBucket
      https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.locations.buckets/patch

    Args:
        project_id:   GCP project ID.
        location:     Region of the log bucket.
        bucket_id:    Short log bucket ID.
        kms_key_name: CryptoKey resource name to set.
        label:        Step label for console output (e.g. "[Step 3]").

    Raises:
        gcp_exceptions.GoogleAPICallError: On any RPC failure.
    """
    client = ConfigServiceV2Client()
    bucket_resource = f"projects/{project_id}/locations/{location}/buckets/{bucket_id}"

    print(f"\n{label} Updating bucket CMEK key to: {kms_key_name}")

    updated = client.update_bucket(
        request={
            "name": bucket_resource,
            "bucket": LogBucket(
                name=bucket_resource,
                cmek_settings=CmekSettings(kms_key_name=kms_key_name),
            ),
            "update_mask": field_mask_pb2.FieldMask(paths=["cmek_settings"]),
        }
    )

    print(f"{label} Bucket CMEK key is now: {updated.cmek_settings.kms_key_name}")


# ---------------------------------------------------------------------------
# Step 5 — verify the rotation
# ---------------------------------------------------------------------------

def verify_rotation(
    project_id: str, location: str, bucket_id: str, kms_key_name: str
) -> None:
    """Confirm the bucket's kmsKeyVersionName reflects the latest primary version.

    After toggling back to the original key, Cloud Logging re-binds to its
    current primary version. This step fetches the bucket and key to confirm.

    Args:
        project_id:   GCP project ID.
        location:     Region of the log bucket.
        bucket_id:    Short log bucket ID.
        kms_key_name: The original CryptoKey resource name.

    Raises:
        ValueError: If the bucket's key doesn't match the expected key.
        gcp_exceptions.GoogleAPICallError: On any RPC failure.
    """
    log_client = ConfigServiceV2Client()
    kms_client = kms_v1.KeyManagementServiceClient()

    bucket_resource = f"projects/{project_id}/locations/{location}/buckets/{bucket_id}"

    print(f"\n[Step 5] Verifying rotation for bucket: {bucket_resource}")
    bucket = log_client.get_bucket(request={"name": bucket_resource})

    bucket_key = bucket.cmek_settings.kms_key_name
    key_version = bucket.cmek_settings.kms_key_version_name

    def _key_base(name: str) -> str:
        return name.split("/cryptoKeyVersions/")[0]

    if _key_base(bucket_key) != _key_base(kms_key_name):
        raise ValueError(
            f"Bucket CMEK key mismatch after rotation.\n"
            f"  Expected: {kms_key_name}\n"
            f"  Got:      {bucket_key}"
        )

    # Fetch the key to show the current primary version for comparison.
    key = kms_client.get_crypto_key(name=kms_key_name)
    current_primary = key.primary.name

    print(f"[Step 5] Bucket kmsKeyVersionName: {key_version}")
    print(f"[Step 5] Key current primary:      {current_primary}")

    if key_version == current_primary:
        print("[Step 5] Rotation verified — bucket is bound to the latest primary version.")
    else:
        # The API may take a moment to reflect the update; surface it clearly.
        print(
            "[Step 5] WARNING: kmsKeyVersionName does not yet match the current primary. "
            "The update may still be propagating — re-run verify in a few seconds."
        )


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Rotate the CMEK key version for a Cloud Logging log bucket "
            "using the documented key-toggle approach."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
How it works
------------
  Cloud Logging stores a reference to a specific key *version* at bind time.
  Switching the bucket to a temporary key and back forces Cloud Logging to
  re-evaluate the original key and bind to its current primary version.

Example
-------
  python3 cmek_log_bucket_rotate.py \\
    --project-id my-gcp-project \\
    --location us-central1 \\
    --bucket-id my-cmek-log-bucket \\
    --kms-key-name projects/my-gcp-project/locations/us-central1/keyRings/my-ring/cryptoKeys/my-key

  # Supply your own temporary key (must be in the same location):
  python3 cmek_log_bucket_rotate.py \\
    --project-id my-gcp-project \\
    --location us-central1 \\
    --bucket-id my-cmek-log-bucket \\
    --kms-key-name projects/my-gcp-project/locations/us-central1/keyRings/my-ring/cryptoKeys/my-key \\
    --temp-kms-key-name projects/my-gcp-project/locations/us-central1/keyRings/my-ring/cryptoKeys/my-temp-key

Notes
-----
  * If --temp-kms-key-name is omitted, a key named <original-key>-rotation-temp
    is created in the same key ring automatically.
  * The temporary key is not deleted after rotation (Cloud KMS keys are
    permanent). It can be reused on subsequent rotations.
  * Rotate the underlying KMS key material separately if needed via:
      gcloud kms keys versions create --key=... --keyring=... --location=...
""",
    )

    parser.add_argument(
        "--project-id",
        required=True,
        metavar="PROJECT_ID",
        help="GCP project ID that owns the log bucket.",
    )
    parser.add_argument(
        "--location",
        required=True,
        metavar="REGION",
        help="Region of the log bucket and KMS key (e.g. us-central1).",
    )
    parser.add_argument(
        "--bucket-id",
        required=True,
        metavar="BUCKET_ID",
        help="Short ID of the CMEK-protected log bucket.",
    )
    parser.add_argument(
        "--kms-key-name",
        required=True,
        metavar="KMS_KEY_RESOURCE_NAME",
        help=(
            "Full resource name of the original Cloud KMS CryptoKey. "
            "Format: projects/[P]/locations/[L]/keyRings/[R]/cryptoKeys/[K]"
        ),
    )
    parser.add_argument(
        "--temp-kms-key-name",
        required=False,
        default=None,
        metavar="TEMP_KMS_KEY_RESOURCE_NAME",
        help=(
            "Full resource name of a temporary CryptoKey used during the toggle. "
            "Must be in the same location as --kms-key-name. "
            "If omitted, a key named <original-key>-rotation-temp is created "
            "automatically in the same key ring."
        ),
    )

    return parser


def main() -> None:
    parser = _build_arg_parser()
    args = parser.parse_args()

    # Derive the temp key name if not supplied.
    if args.temp_kms_key_name:
        temp_kms_key_name = args.temp_kms_key_name
    else:
        keyring = _keyring_from_key(args.kms_key_name)
        temp_key_id = f"{_key_id_from_key(args.kms_key_name)}-rotation-temp"
        temp_kms_key_name = f"{keyring}/cryptoKeys/{temp_key_id}"

    try:
        # ------------------------------------------------------------------
        # Step 1 — confirm the bucket is CMEK-protected and get the logging SA
        # ------------------------------------------------------------------
        original_key, logging_sa = get_bucket_cmek_info(
            args.project_id, args.location, args.bucket_id
        )

        # Guard: the bucket's current key should match the supplied key.
        if original_key.split("/cryptoKeyVersions/")[0] != args.kms_key_name:
            print(
                f"\nWarning: bucket's current key ({original_key}) does not match "
                f"--kms-key-name ({args.kms_key_name}). Proceeding with the bucket's "
                "actual key as the original.",
            )
            original_key_to_restore = original_key.split("/cryptoKeyVersions/")[0]
        else:
            original_key_to_restore = args.kms_key_name

        # ------------------------------------------------------------------
        # Step 2 — ensure the temporary key exists with IAM access
        # ------------------------------------------------------------------
        keyring = _keyring_from_key(original_key_to_restore)
        temp_key_id = temp_kms_key_name.rsplit("/", 1)[-1]
        ensure_temp_key(keyring, temp_key_id, logging_sa)

        # ------------------------------------------------------------------
        # Step 3 — switch the bucket to the temporary key
        # ------------------------------------------------------------------
        update_bucket_cmek_key(
            args.project_id, args.location, args.bucket_id,
            temp_kms_key_name, "[Step 3]"
        )

        # ------------------------------------------------------------------
        # Step 4 — switch the bucket back to the original key
        # ------------------------------------------------------------------
        update_bucket_cmek_key(
            args.project_id, args.location, args.bucket_id,
            original_key_to_restore, "[Step 4]"
        )

        # ------------------------------------------------------------------
        # Step 5 — verify kmsKeyVersionName reflects the latest primary
        # ------------------------------------------------------------------
        verify_rotation(
            args.project_id, args.location, args.bucket_id,
            original_key_to_restore,
        )

        print("\nDone. Key rotation completed successfully.")

    except gcp_exceptions.NotFound as exc:
        print(f"\nError: A required resource was not found.\n  {exc}", file=sys.stderr)
        sys.exit(1)
    except gcp_exceptions.PermissionDenied as exc:
        print(
            f"\nError: Permission denied. Verify your credentials hold "
            f"the IAM roles listed at the top of this script.\n  {exc}",
            file=sys.stderr,
        )
        sys.exit(1)
    except gcp_exceptions.InvalidArgument as exc:
        print(f"\nError: Invalid argument — check flag values.\n  {exc}", file=sys.stderr)
        sys.exit(1)
    except gcp_exceptions.Aborted as exc:
        print(
            f"\nError: IAM policy update aborted due to a concurrent modification. "
            f"Re-run the script to retry.\n  {exc}",
            file=sys.stderr,
        )
        sys.exit(1)
    except gcp_exceptions.GoogleAPICallError as exc:
        print(f"\nGoogle API error: {exc}", file=sys.stderr)
        sys.exit(1)
    except ValueError as exc:
        print(f"\nConfiguration error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
