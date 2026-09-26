"""Storage verification clients for backup file checks (S3 / GCS)."""
from __future__ import annotations

import base64
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from kubernetes import client as k8s

from src import config

logger = logging.getLogger(__name__)


@dataclass
class ObjectInfo:
    key: str
    size: int  # bytes
    last_modified: datetime


class StorageClient(Protocol):
    def list_objects(self, bucket: str, prefix: str, max_keys: int = 10) -> list[ObjectInfo]: ...
    def list_prefixes(self, bucket: str, prefix: str) -> list[str]: ...
    def head_object(self, bucket: str, key: str) -> ObjectInfo: ...
    def download_bytes(self, bucket: str, key: str, byte_range: tuple[int, int]) -> bytes: ...


class S3Client:
    """S3-compatible client (Hetzner Object Storage). Reads credentials + bucket from K8s secret."""

    def __init__(self) -> None:
        self._client = None
        self._bucket: str = ""
        self._initialized = False

    @property
    def bucket(self) -> str:
        """Bucket name from the S3 secret (S3_BACKUP_BUCKET key)."""
        if not self._initialized:
            self._get_client()
        return self._bucket

    def _get_client(self):
        if self._client is not None:
            return self._client
        if self._initialized:
            return None  # Already tried and failed
        self._initialized = True

        try:
            import boto3
        except ImportError:
            logger.warning("boto3 not installed, S3 storage verification disabled")
            return None

        secret_name = config.BACKUP_S3_SECRET_NAME
        secret_ns = config.BACKUP_S3_SECRET_NAMESPACE

        core = k8s.CoreV1Api()
        if not secret_ns:
            # Find the secret in watched namespaces
            for ns in config.get_namespaces():
                try:
                    core.read_namespaced_secret(secret_name, ns)
                    secret_ns = ns
                    break
                except k8s.ApiException as e:
                    if e.status == 403:
                        logger.warning(
                            "No access to secret %s in %s. The monitor has no general Secret access by design: "
                            "set BACKUP_S3_SECRET_NAMESPACE and grant get on exactly this secret "
                            "(Role with resourceNames: [%s]) in that namespace.", secret_name, ns, secret_name)
                    elif e.status != 404:
                        logger.warning("Error reading secret %s in %s: %s", secret_name, ns, e.reason)
                    continue
            if not secret_ns:
                logger.warning("S3 secret %s not found in any watched namespace", secret_name)
                return None

        try:
            secret = core.read_namespaced_secret(secret_name, secret_ns)
            data = secret.data or {}

            def _decode(key: str) -> str:
                val = data.get(key, "")
                return base64.b64decode(val).decode() if val else ""

            endpoint = _decode("S3_BACKUP_ENDPOINT")
            access_key = _decode("S3_ACCESS_KEY")
            secret_key = _decode("S3_SECRET_KEY")
            self._bucket = _decode("S3_BACKUP_BUCKET")

            if not all([endpoint, access_key, secret_key]):
                logger.warning("S3 secret %s/%s missing required keys", secret_ns, secret_name)
                return None

            self._client = boto3.client(
                "s3",
                endpoint_url=endpoint,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
            return self._client
        except Exception:
            logger.warning("Failed to read S3 credentials from secret %s/%s", secret_ns, secret_name, exc_info=True)
            return None

    def list_objects(self, bucket: str, prefix: str, max_keys: int = 10) -> list[ObjectInfo]:
        client = self._get_client()
        if not client:
            return []
        resp = client.list_objects_v2(Bucket=bucket, Prefix=prefix, MaxKeys=max_keys * 5)
        objects = []
        for obj in resp.get("Contents", []):
            objects.append(ObjectInfo(
                key=obj["Key"],
                size=obj["Size"],
                last_modified=obj["LastModified"].replace(tzinfo=timezone.utc) if obj["LastModified"].tzinfo is None else obj["LastModified"],
            ))
        objects.sort(key=lambda o: o.last_modified, reverse=True)
        return objects[:max_keys]

    def list_prefixes(self, bucket: str, prefix: str) -> list[str]:
        """List immediate subdirectory names under a prefix (uses S3 Delimiter)."""
        client = self._get_client()
        if not client:
            return []
        resp = client.list_objects_v2(Bucket=bucket, Prefix=prefix, Delimiter="/")
        result = []
        for cp in resp.get("CommonPrefixes", []):
            # cp["Prefix"] is like "postgres-dump/production/core-service/"
            # Strip the parent prefix and trailing slash to get just "core-service"
            sub = cp["Prefix"][len(prefix):].rstrip("/")
            if sub:
                result.append(sub)
        return result

    def head_object(self, bucket: str, key: str) -> ObjectInfo:
        client = self._get_client()
        if not client:
            raise RuntimeError("S3 client not available")
        resp = client.head_object(Bucket=bucket, Key=key)
        lm = resp["LastModified"]
        return ObjectInfo(
            key=key,
            size=resp["ContentLength"],
            last_modified=lm.replace(tzinfo=timezone.utc) if lm.tzinfo is None else lm,
        )

    def download_bytes(self, bucket: str, key: str, byte_range: tuple[int, int]) -> bytes:
        client = self._get_client()
        if not client:
            raise RuntimeError("S3 client not available")
        resp = client.get_object(
            Bucket=bucket, Key=key,
            Range=f"bytes={byte_range[0]}-{byte_range[1]}",
        )
        return resp["Body"].read()


class GCSClient:
    """Google Cloud Storage client. Uses workload identity (no credentials needed)."""

    def __init__(self) -> None:
        self._client = None

    def _get_client(self):
        if self._client is not None:
            return self._client
        try:
            from google.cloud import storage
            self._client = storage.Client()
            return self._client
        except ImportError:
            logger.warning("google-cloud-storage not installed, GCS storage verification disabled")
            return None
        except Exception:
            logger.warning("Failed to create GCS client", exc_info=True)
            return None

    def list_objects(self, bucket: str, prefix: str, max_keys: int = 10) -> list[ObjectInfo]:
        client = self._get_client()
        if not client:
            return []
        bucket_obj = client.bucket(bucket)
        blobs = list(bucket_obj.list_blobs(prefix=prefix, max_results=max_keys * 5))
        objects = []
        for blob in blobs:
            lm = blob.updated or blob.time_created
            if lm and lm.tzinfo is None:
                lm = lm.replace(tzinfo=timezone.utc)
            objects.append(ObjectInfo(
                key=blob.name,
                size=blob.size or 0,
                last_modified=lm or datetime.now(timezone.utc),
            ))
        objects.sort(key=lambda o: o.last_modified, reverse=True)
        return objects[:max_keys]

    def list_prefixes(self, bucket: str, prefix: str) -> list[str]:
        """List immediate subdirectory names under a prefix."""
        client = self._get_client()
        if not client:
            return []
        bucket_obj = client.bucket(bucket)
        iterator = bucket_obj.list_blobs(prefix=prefix, delimiter="/")
        # Must consume the iterator to populate prefixes
        list(iterator)
        result = []
        for p in iterator.prefixes:
            sub = p[len(prefix):].rstrip("/")
            if sub:
                result.append(sub)
        return result

    def head_object(self, bucket: str, key: str) -> ObjectInfo:
        client = self._get_client()
        if not client:
            raise RuntimeError("GCS client not available")
        blob = client.bucket(bucket).blob(key)
        blob.reload()
        lm = blob.updated or blob.time_created
        if lm and lm.tzinfo is None:
            lm = lm.replace(tzinfo=timezone.utc)
        return ObjectInfo(
            key=key,
            size=blob.size or 0,
            last_modified=lm or datetime.now(timezone.utc),
        )

    def download_bytes(self, bucket: str, key: str, byte_range: tuple[int, int]) -> bytes:
        client = self._get_client()
        if not client:
            raise RuntimeError("GCS client not available")
        blob = client.bucket(bucket).blob(key)
        return blob.download_as_bytes(start=byte_range[0], end=byte_range[1])


def get_storage_client() -> StorageClient | None:
    """Create a storage client based on BACKUP_STORAGE_PROVIDER config."""
    provider = config.BACKUP_STORAGE_PROVIDER
    if provider == "s3":
        return S3Client()
    elif provider == "gcs":
        return GCSClient()
    if provider:
        logger.warning("Unknown BACKUP_STORAGE_PROVIDER: %s", provider)
    return None
