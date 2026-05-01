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
#   - cloudkms.cryptoKeyVersions.create  (on the CryptoKey)
#   - cloudkms.cryptoKeys.update         (on the CryptoKey, to set primary)
#   - logging.buckets.get                (on the project)
# =============================================================================
"""
Rotate the Cloud KMS CryptoKey used by a CMEK-protected Cloud Logging log
bucket.

Steps
-----
1. Create a new CryptoKeyVersion — the new ciphertext material.
2. Promote the new version to primary — all subsequent log writes use it.
3. Verify the log bucket's CMEK binding still points to the same key and
   confirm the key's new primary version.

Key rotation does NOT require updating the log bucket's cmek_settings because
Cloud Logging stores a reference to the CryptoKey resource (not a specific
version).  Once a new primary version exists, Cloud Logging automatically uses
it for new writes.  Older log data remains readable because Cloud KMS keeps the
old version enabled until you explicitly disable or destroy it.

Reference:
  https://cloud.google.com/kms/docs/rotate-keys
  https://cloud.google.com/logging/docs/routing/managed-encryption-storage
"""

import argparse
import sys

from google.api_core import exceptions as gcp_exceptions
from google.cloud import kms_v1
from google.cloud.logging_v2.services.config_service_v2 import ConfigServiceV2Client


# ---------------------------------------------------------------------------
# Step 1
# ---------------------------------------------------------------------------

def create_new_key_version(kms_key_name: str) -> str:
    """Create a new CryptoKeyVersion for the given CryptoKey.

    Cloud KMS generates a fresh key material and stores it as a new version.
    The version starts in PENDING_GENERATION state and moves to ENABLED once
    Cloud KMS has generated the ciphertext material (usually within seconds).

    API reference:
      KeyManagementService.CreateCryptoKeyVersion
      https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/create

    Args:
        kms_key_name: Full CryptoKey resource name, e.g.
            projects/P/locations/L/keyRings/R/cryptoKeys/K

    Returns:
        Full resource name of the newly created CryptoKeyVersion.

    Raises:
        gcp_exceptions.GoogleAPICallError: On any RPC failure.
    """
    kms_client = kms_v1.KeyManagementServiceClient()

    print(f"[Step 1] Creating new CryptoKeyVersion under: {kms_key_name}")
    new_version = kms_client.create_crypto_key_version(
        request={
            "parent": kms_key_name,
            "crypto_key_version": {},  # algorithm / protection level inherited from key
        }
    )

    print(f"[Step 1] New version created: {new_version.name}")
    print(f"[Step 1] Version state: {new_version.state.name}")
    return new_version.name


# ---------------------------------------------------------------------------
# Step 2
# ---------------------------------------------------------------------------

def promote_to_primary(kms_key_name: str, version_resource_name: str) -> None:
    """Promote a CryptoKeyVersion to primary for the given CryptoKey.

    After promotion all new Cloud KMS encrypt calls (and therefore all new
    log writes) use this version.  The previously-primary version remains
    ENABLED so that existing log data can still be decrypted.

    API reference:
      KeyManagementService.UpdateCryptoKeyPrimaryVersion
      https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/updatePrimaryVersion

    Args:
        kms_key_name: Full CryptoKey resource name.
        version_resource_name: Full resource name of the version to promote,
            e.g. projects/P/.../cryptoKeys/K/cryptoKeyVersions/2

    Raises:
        gcp_exceptions.GoogleAPICallError: On any RPC failure.
    """
    kms_client = kms_v1.KeyManagementServiceClient()

    # The API only needs the short version ID ("2"), not the full resource name.
    version_id = version_resource_name.split("/")[-1]

    print(f"\n[Step 2] Promoting version '{version_id}' to primary on: {kms_key_name}")
    updated_key = kms_client.update_crypto_key_primary_version(
        request={
            "name": kms_key_name,
            "crypto_key_version_id": version_id,
        }
    )

    primary = updated_key.primary
    print(f"[Step 2] New primary: {primary.name}")
    print(f"[Step 2] Primary state: {primary.state.name}")


# ---------------------------------------------------------------------------
# Step 3
# ---------------------------------------------------------------------------

def verify_bucket_cmek(project_id: str, location: str, bucket_id: str, kms_key_name: str) -> None:
    """Confirm the log bucket still references the expected CryptoKey.

    Also retrieves and prints the key's current primary version to show that
    the rotation took effect from the bucket's perspective.

    API references:
      ConfigServiceV2.GetBucket
        https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.locations.buckets/get
      KeyManagementService.GetCryptoKey
        https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/get

    Args:
        project_id: GCP project ID.
        location:   Region of the log bucket.
        bucket_id:  Short log bucket ID.
        kms_key_name: Expected CryptoKey resource name.

    Raises:
        ValueError: If the bucket's CMEK key does not match kms_key_name.
        gcp_exceptions.GoogleAPICallError: On any RPC failure.
    """
    log_client = ConfigServiceV2Client()
    kms_client = kms_v1.KeyManagementServiceClient()

    bucket_resource = (
        f"projects/{project_id}/locations/{location}/buckets/{bucket_id}"
    )

    print(f"\n[Step 3] Fetching log bucket: {bucket_resource}")
    bucket = log_client.get_bucket(request={"name": bucket_resource})

    bucket_key = bucket.cmek_settings.kms_key_name
    if not bucket_key:
        raise ValueError(
            f"Bucket '{bucket_id}' has no CMEK settings — it may not be "
            "CMEK-protected, or was created without a KMS key."
        )

    # Normalise for comparison: strip any trailing version suffix the bucket
    # may or may not include (e.g. .../cryptoKeys/K/cryptoKeyVersions/1).
    def _key_base(name: str) -> str:
        return name.split("/cryptoKeyVersions/")[0]

    if _key_base(bucket_key) != _key_base(kms_key_name):
        raise ValueError(
            f"Bucket CMEK key mismatch.\n"
            f"  Expected: {kms_key_name}\n"
            f"  Got:      {bucket_key}"
        )

    print(f"[Step 3] Bucket CMEK key confirmed: {bucket_key}")

    # Fetch the CryptoKey to show which version is now primary.
    key = kms_client.get_crypto_key(name=kms_key_name)
    print(f"[Step 3] Current primary version: {key.primary.name}")
    print(f"[Step 3] Primary version state:   {key.primary.state.name}")
    print(
        "[Step 3] Rotation verified — new log writes will be encrypted "
        "with the new primary version."
    )


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Rotate the CMEK key version for a Cloud Logging log bucket.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example
-------
  python cmek_log_bucket_rotate.py \\
    --project-id my-gcp-project \\
    --location us-central1 \\
    --bucket-id my-cmek-log-bucket \\
    --kms-key-name projects/my-gcp-project/locations/us-central1/keyRings/my-ring/cryptoKeys/my-key

Notes
-----
  * Old key versions remain ENABLED after rotation so existing encrypted
    log data stays readable.  Disable or destroy old versions only after
    all log data encrypted under them has been purged (i.e. after the
    bucket retention period expires).
  * Automatic rotation can be configured on the CryptoKey itself via
    --rotation-period in gcloud or rotationPeriod in the API; this script
    performs a one-shot manual rotation.
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
            "Full resource name of the Cloud KMS CryptoKey. "
            "Format: projects/[P]/locations/[L]/keyRings/[R]/cryptoKeys/[K]"
        ),
    )

    return parser


def main() -> None:
    parser = _build_arg_parser()
    args = parser.parse_args()

    try:
        # ------------------------------------------------------------------
        # Step 1 — generate fresh key material as a new version
        # ------------------------------------------------------------------
        new_version_name = create_new_key_version(args.kms_key_name)

        # ------------------------------------------------------------------
        # Step 2 — make the new version the primary (active) version
        # ------------------------------------------------------------------
        promote_to_primary(args.kms_key_name, new_version_name)

        # ------------------------------------------------------------------
        # Step 3 — verify the log bucket still points to the correct key
        # ------------------------------------------------------------------
        verify_bucket_cmek(
            project_id=args.project_id,
            location=args.location,
            bucket_id=args.bucket_id,
            kms_key_name=args.kms_key_name,
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
    except gcp_exceptions.FailedPrecondition as exc:
        # Raised when trying to promote a version that is not yet ENABLED.
        print(
            f"\nError: Key version is not yet ready. "
            f"Wait a moment and re-run.\n  {exc}",
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
