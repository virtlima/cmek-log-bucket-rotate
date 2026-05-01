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
#   - logging.settings.get        (on the project)
#   - cloudkms.cryptoKeys.getIamPolicy  (on the CryptoKey)
#   - cloudkms.cryptoKeys.setIamPolicy  (on the CryptoKey)
#   - logging.buckets.create      (on the project)
# =============================================================================
"""
Automate Customer-Managed Encryption Key (CMEK) setup for a Cloud Logging
log bucket in three sequential steps:

  1. Retrieve the Cloud Logging CMEK service account for the project.
  2. Grant roles/cloudkms.cryptoKeyEncrypterDecrypter on the KMS key to that SA.
  3. Create the log bucket with CMEK enabled.

Reference:
  https://cloud.google.com/logging/docs/routing/managed-encryption-storage#manage-key
"""

import argparse
import sys

from google.api_core import exceptions as gcp_exceptions
from google.cloud import kms_v1
from google.cloud.logging_v2.services.config_service_v2 import ConfigServiceV2Client
from google.cloud.logging_v2.types import CmekSettings, LogBucket
from google.iam.v1 import policy_pb2


# ---------------------------------------------------------------------------
# Step 1
# ---------------------------------------------------------------------------

def get_logging_service_account(project_id: str) -> str:
    """Return the kms_service_account_id from the project's logging settings.

    Cloud Logging provisions a per-project service account that it uses to
    call Cloud KMS when reading or writing CMEK-protected log data.  We must
    grant that SA access to the CryptoKey *before* creating the bucket, or
    the bucket creation will be rejected by the API.

    API reference:
      ConfigServiceV2.GetSettings
      https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects/getSettings

    Args:
        project_id: GCP project ID (not project number).

    Returns:
        The service account email string stored in kms_service_account_id.

    Raises:
        ValueError: If the field is empty (API not enabled / project not set up).
        gcp_exceptions.GoogleAPICallError: On any RPC failure.
    """
    client = ConfigServiceV2Client()

    # Resource name format: "projects/{project_id}"
    name = f"projects/{project_id}"

    print(f"[Step 1] Calling GetSettings for: {name}")
    settings = client.get_settings(name=name)

    sa_id = settings.kms_service_account_id
    if not sa_id:
        raise ValueError(
            f"kms_service_account_id is empty for project '{project_id}'. "
            "Verify that the Cloud Logging API is enabled and the project "
            "has been initialized with at least one logging write."
        )

    print(f"[Step 1] Cloud Logging CMEK service account: {sa_id}")
    return sa_id


# ---------------------------------------------------------------------------
# Step 2
# ---------------------------------------------------------------------------

def grant_kms_encrypter_decrypter(kms_key_name: str, service_account_id: str) -> None:
    """Grant roles/cloudkms.cryptoKeyEncrypterDecrypter on *kms_key_name*.

    Fetches the current IAM policy for the CryptoKey, checks whether the
    binding already exists (idempotent), and calls SetIamPolicy only when a
    change is required.

    The etag returned by GetIamPolicy is forwarded to SetIamPolicy to guard
    against concurrent modifications (optimistic concurrency).

    API reference:
      KeyManagementService.GetIamPolicy / SetIamPolicy
      https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/setIamPolicy

    Args:
        kms_key_name: Full CryptoKey resource name, e.g.
            projects/P/locations/L/keyRings/R/cryptoKeys/K
        service_account_id: Email of the Cloud Logging CMEK service account.

    Raises:
        gcp_exceptions.GoogleAPICallError: On any RPC failure.
    """
    kms_client = kms_v1.KeyManagementServiceClient()

    role = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
    member = f"serviceAccount:{service_account_id}"

    print(f"\n[Step 2] Fetching IAM policy for KMS key: {kms_key_name}")
    policy = kms_client.get_iam_policy(request={"resource": kms_key_name})

    # Check whether the exact binding already exists to keep this idempotent.
    for binding in policy.bindings:
        if binding.role == role and member in binding.members:
            print(
                f"[Step 2] Binding already present — "
                f"'{member}' already has '{role}'. No update needed."
            )
            return

    # Append the new binding; the existing etag travels with the policy object
    # so SetIamPolicy can detect a race condition and return ABORTED.
    new_binding = policy_pb2.Binding(role=role, members=[member])
    policy.bindings.append(new_binding)

    print(f"[Step 2] Granting '{role}' to '{member}' ...")
    kms_client.set_iam_policy(request={"resource": kms_key_name, "policy": policy})
    print("[Step 2] IAM policy updated successfully.")


# ---------------------------------------------------------------------------
# Step 3
# ---------------------------------------------------------------------------

def create_cmek_log_bucket(
    project_id: str,
    location: str,
    bucket_id: str,
    kms_key_name: str,
) -> None:
    """Create a Cloud Logging log bucket configured with CMEK.

    The bucket's cmek_settings.kms_key_name field wires the CryptoKey to the
    bucket at creation time.  The Cloud Logging backend validates that the
    CMEK service account already has the encrypter/decrypter role before
    accepting the request, which is why Step 2 must precede Step 3.

    If a bucket with the same ID already exists in the specified location this
    function prints a notice and returns without error so the overall script
    remains idempotent.

    API reference:
      ConfigServiceV2.CreateBucket
      https://cloud.google.com/logging/docs/reference/v2/rest/v2/projects.locations.buckets/create

    Args:
        project_id: GCP project ID.
        location:   Region that will host the bucket (e.g. "us-central1").
                    Must match the location embedded in kms_key_name.
        bucket_id:  Desired short ID for the new bucket (e.g. "my-cmek-bucket").
        kms_key_name: Full CryptoKey resource name used for encryption.

    Raises:
        gcp_exceptions.GoogleAPICallError: On any non-AlreadyExists RPC failure.
    """
    client = ConfigServiceV2Client()

    # Parent format: "projects/{project_id}/locations/{location}"
    parent = f"projects/{project_id}/locations/{location}"

    # Build the LogBucket with CMEK settings.
    bucket = LogBucket(
        cmek_settings=CmekSettings(
            kms_key_name=kms_key_name,
        ),
    )

    print(f"\n[Step 3] Creating log bucket '{bucket_id}' under {parent}")
    print(f"[Step 3] CMEK key: {kms_key_name}")

    try:
        created = client.create_bucket(
            request={
                "parent": parent,
                "bucket_id": bucket_id,
                "bucket": bucket,
            }
        )
        print(f"[Step 3] Log bucket created: {created.name}")
    except gcp_exceptions.AlreadyExists:
        # Treat as a no-op so the script is safe to re-run.
        print(
            f"[Step 3] Log bucket '{bucket_id}' already exists in {parent}. "
            "Skipping creation."
        )


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Configure CMEK for a new Cloud Logging log bucket.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example
-------
  python cmek_log_bucket_setup.py \\
    --project-id my-gcp-project \\
    --location us-central1 \\
    --bucket-id my-cmek-log-bucket \\
    --kms-key-name projects/my-gcp-project/locations/us-central1/keyRings/my-ring/cryptoKeys/my-key

Notes
-----
  * The KMS key location must match --location.
  * The caller's credentials must have the IAM roles listed at the top of
    this file.  Use GOOGLE_APPLICATION_CREDENTIALS or
    `gcloud auth application-default login`.
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
        help="Region for the log bucket, e.g. us-central1.  Must match the "
             "KMS key location.",
    )
    parser.add_argument(
        "--bucket-id",
        required=True,
        metavar="BUCKET_ID",
        help="Short ID for the new log bucket (alphanumeric and hyphens).",
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


def _validate_kms_key_location(kms_key_name: str, location: str) -> None:
    """Warn (not fail) if the KMS key location differs from --location."""
    # Expected fragment: .../locations/{location}/...
    fragment = f"/locations/{location}/"
    if fragment not in kms_key_name:
        print(
            f"WARNING: The KMS key name does not contain '/locations/{location}/'. "
            "Cloud Logging requires the KMS key to be in the same region as the "
            "log bucket. Proceeding, but the API may reject the request.",
            file=sys.stderr,
        )


def main() -> None:
    parser = _build_arg_parser()
    args = parser.parse_args()

    _validate_kms_key_location(args.kms_key_name, args.location)

    try:
        # ------------------------------------------------------------------
        # Step 1 — discover the Cloud Logging CMEK service account
        # ------------------------------------------------------------------
        sa_id = get_logging_service_account(args.project_id)

        # ------------------------------------------------------------------
        # Step 2 — authorize the service account on the CryptoKey
        # ------------------------------------------------------------------
        grant_kms_encrypter_decrypter(args.kms_key_name, sa_id)

        # ------------------------------------------------------------------
        # Step 3 — create the CMEK-enabled log bucket
        # ------------------------------------------------------------------
        create_cmek_log_bucket(
            project_id=args.project_id,
            location=args.location,
            bucket_id=args.bucket_id,
            kms_key_name=args.kms_key_name,
        )

        print("\nDone. CMEK log bucket setup completed successfully.")

    except gcp_exceptions.NotFound as exc:
        print(f"\nError: A required resource was not found.\n  {exc}", file=sys.stderr)
        sys.exit(1)
    except gcp_exceptions.PermissionDenied as exc:
        print(
            f"\nError: Permission denied. Verify that your credentials hold "
            f"the IAM roles listed at the top of this script.\n  {exc}",
            file=sys.stderr,
        )
        sys.exit(1)
    except gcp_exceptions.InvalidArgument as exc:
        print(f"\nError: Invalid argument — check flag values.\n  {exc}", file=sys.stderr)
        sys.exit(1)
    except gcp_exceptions.Aborted as exc:
        # Raised by SetIamPolicy when the etag check fails (concurrent update).
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
