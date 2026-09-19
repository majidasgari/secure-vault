"""S3 client used by the folder sync (docs/SYNC.md).

The client has **two interchangeable backends**:

* `boto3` (in ``requirements-s3.txt``) when it is installed; and
* a dependency-free **stdlib** backend (``http.client`` + AWS SigV4) that works for the
  four operations the sync needs — ``get``/``put``/``delete``/``list``.

The stdlib backend exists because a machine may not be able to install boto3 at all
(no PyPI access, locked-down host). It signs requests with SigV4 over
``urllib``/``http.client`` and speaks the S3 REST API directly, so sync works out of the
box. The two backends expose the same duck-typed surface as the in-memory fake used by
the tests.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import ssl
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ..errors import SyncError

#: Connection/read timeouts (seconds): a dead endpoint must never hang the UI.
_CONNECT_TIMEOUT = 5
_READ_TIMEOUT = 15

_SIGV4_ALGORITHM = "AWS4-HMAC-SHA256"
_SERVICE = "s3"


@dataclass
class S3Config:
    """Everything needed to reach one bucket: coordinates from the vault, keys locally."""

    enabled: bool = False
    bucket: str = ""
    prefix: str = ""
    endpoint: str = ""
    region: str = ""
    access_key: str = ""
    secret_key: str = ""

    @property
    def configured(self) -> bool:
        """True when sync is switched on and the bucket + credentials are present."""
        return bool(
            self.enabled
            and self.bucket.strip()
            and self.access_key.strip()
            and self.secret_key.strip()
        )

    def normalized_prefix(self) -> str:
        """Return the key prefix with a trailing slash (``""`` for the bucket root)."""
        prefix = self.prefix.strip().strip("/")
        return f"{prefix}/" if prefix else ""

    @classmethod
    def from_session(cls, session: Any) -> "S3Config":
        """Build a config from the vault settings plus the machine-local credentials."""
        from ..config import load_sync_config

        settings = (session.meta.settings.get("sync") or {}) if session.meta else {}
        credentials = load_sync_config()
        return cls(
            enabled=bool(settings.get("enabled")),
            bucket=str(settings.get("bucket") or ""),
            prefix=str(settings.get("prefix") or ""),
            endpoint=str(settings.get("endpoint") or ""),
            region=str(settings.get("region") or ""),
            access_key=str(credentials.get("access_key") or ""),
            secret_key=str(credentials.get("secret_key") or ""),
        )


def _md5_hex(data: bytes) -> str:
    """Return the hex MD5 of ``data`` (matches a single-PUT S3 ETag)."""
    return hashlib.md5(data).hexdigest()  # noqa: S324 - ETag comparison, not security


def _sha256_hex(data: bytes) -> str:
    """Return the lowercase hex SHA-256 of ``data``."""
    return hashlib.sha256(data).hexdigest()


def _hmac_sha256(key: bytes, message: str) -> bytes:
    """Return ``HMAC-SHA256(key, message)``."""
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def _to_ms(value: Any) -> int:
    """Convert a ``datetime``/string S3 timestamp into epoch milliseconds."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return int(value.timestamp() * 1000)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return int(parsed.timestamp() * 1000)
        except ValueError:
            return 0
    return 0


# --------------------------------------------------------------------------- backends
class _BotoBackend:
    """S3 through ``boto3`` (used whenever it is importable)."""

    def __init__(self, config: S3Config) -> None:
        """Create the boto3 client for ``config``."""
        import boto3  # noqa: PLC0415
        from botocore.config import Config as BotoConfig  # noqa: PLC0415

        kwargs: dict[str, Any] = {
            "aws_access_key_id": config.access_key,
            "aws_secret_access_key": config.secret_key,
            "config": BotoConfig(
                connect_timeout=_CONNECT_TIMEOUT,
                read_timeout=_READ_TIMEOUT,
                retries={"max_attempts": 2, "mode": "standard"},
                signature_version="s3v4",
            ),
        }
        if config.region:
            kwargs["region_name"] = config.region
        if config.endpoint:
            kwargs["endpoint_url"] = config.endpoint
        self.config = config
        self.name = "boto3"
        self._client = boto3.client("s3", **kwargs)

    def get(self, key: str) -> bytes | None:
        """Return the object bytes or ``None`` when missing."""
        try:
            response = self._client.get_object(Bucket=self.config.bucket, Key=key)
            return response["Body"].read()
        except Exception as exc:  # noqa: BLE001
            if _error_code(exc) in ("NoSuchKey", "404", "NoSuchBucket"):
                return None
            raise SyncError("s3_get_failed", details={"key": key, "reason": str(exc)}) from exc

    def put(self, key: str, data: bytes, *, if_none_match: bool = False) -> bool:
        """Store the object; with ``if_none_match`` do not overwrite."""
        kwargs: dict[str, Any] = {"Bucket": self.config.bucket, "Key": key, "Body": data}
        if if_none_match:
            kwargs["IfNoneMatch"] = "*"
        try:
            self._client.put_object(**kwargs)
        except Exception as exc:  # noqa: BLE001
            if if_none_match and _error_code(exc) in ("PreconditionFailed", "412"):
                return False
            raise SyncError("s3_put_failed", details={"key": key, "reason": str(exc)}) from exc
        return True

    def delete(self, key: str) -> None:
        """Delete the object (missing keys are ignored)."""
        try:
            self._client.delete_object(Bucket=self.config.bucket, Key=key)
        except Exception as exc:  # noqa: BLE001
            raise SyncError("s3_delete_failed", details={"key": key, "reason": str(exc)}) from exc

    def list(self, prefix: str) -> list[dict[str, Any]]:
        """List objects under ``prefix`` with size, ETag and modified time."""
        entries: list[dict[str, Any]] = []
        marker: str | None = None
        while True:
            kwargs: dict[str, Any] = {"Bucket": self.config.bucket, "Prefix": prefix}
            if marker:
                kwargs["ContinuationToken"] = marker
            response = self._client.list_objects_v2(**kwargs)
            for item in response.get("Contents", []) or []:
                etag = str(item.get("ETag") or "").strip('"')
                entries.append(
                    {
                        "key": str(item.get("Key")),
                        "size": int(item.get("Size") or 0),
                        "etag": etag or None,
                        "modified": _to_ms(item.get("LastModified")),
                    }
                )
            if not response.get("IsTruncated"):
                return entries
            marker = response.get("NextContinuationToken")


class _StdlibBackend:
    """S3 over ``http.client`` with hand-rolled AWS SigV4 (no third-party dependency)."""

    def __init__(self, config: S3Config) -> None:
        """Compute the endpoint, host and addressing style from ``config``."""
        self.config = config
        self.name = "stdlib"
        self.region = config.region.strip() or "us-east-1"
        endpoint = config.endpoint.strip()
        if endpoint:
            parsed = urllib.parse.urlsplit(
                endpoint if "://" in endpoint else f"https://{endpoint}"
            )
            self.scheme = parsed.scheme or "https"
            self.host = parsed.netloc
            self.base_path = parsed.path.rstrip("/")
            self._virtual = False
        else:
            self.scheme = "https"
            self.host = f"{config.bucket.strip()}.s3.{self.region}.amazonaws.com"
            self.base_path = ""
            self._virtual = True

    # ------------------------------------------------------------------ signing
    def _object_path(self, key: str | None, query: dict[str, str]) -> tuple[str, str]:
        """Return ``(path, canonical_query)`` for an object or bucket request."""
        encoded_key = urllib.parse.quote(key or "", safe="/-_.~")
        if self._virtual:
            path = f"{self.base_path}/{encoded_key}" if encoded_key else f"{self.base_path}/"
        else:
            bucket = urllib.parse.quote(self.config.bucket.strip(), safe="-_.~")
            path = f"{self.base_path}/{bucket}/{encoded_key}" if encoded_key else (
                f"{self.base_path}/{bucket}"
            )
        canonical_query = "&".join(
            f"{urllib.parse.quote(k, safe='-_.~')}={urllib.parse.quote(v, safe='-_.~')}"
            for k, v in sorted(query.items())
        )
        return path, canonical_query

    def _request(
        self,
        method: str,
        key: str | None,
        *,
        query: dict[str, str] | None = None,
        body: bytes = b"",
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        """Sign and send one request; return ``(status, headers, body)``."""
        query = query or {}
        path, canonical_query = self._object_path(key, query)
        target = f"{path}?{canonical_query}" if canonical_query else path

        now = datetime.now(timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        datestamp = now.strftime("%Y%m%d")
        payload_hash = _sha256_hex(body)

        headers: dict[str, str] = {
            "Host": self.host,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz_date,
        }
        for name, value in (extra_headers or {}).items():
            headers[name] = value

        signed_names = sorted(name.lower() for name in headers)
        canonical_headers = "".join(
            f"{name.lower()}:{headers[name].strip()}\n"
            for name in sorted(headers, key=str.lower)
        )
        signed_headers = ";".join(signed_names)
        canonical_request = "\n".join(
            [method, path, canonical_query, canonical_headers, signed_headers, payload_hash]
        )
        scope = f"{datestamp}/{self.region}/{_SERVICE}/aws4_request"
        string_to_sign = "\n".join(
            [
                _SIGV4_ALGORITHM,
                amz_date,
                scope,
                _sha256_hex(canonical_request.encode("utf-8")),
            ]
        )
        signing_key = self._signing_key(datestamp)
        signature = hmac.new(
            signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        headers["Authorization"] = (
            f"{_SIGV4_ALGORITHM} Credential={self.config.access_key}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )

        parsed = urllib.parse.urlsplit(f"{self.scheme}://{self.host}")
        if self.scheme == "https":
            conn: Any = http.client.HTTPSConnection(
                parsed.hostname,
                parsed.port,
                timeout=_READ_TIMEOUT,
                context=ssl.create_default_context(),
            )
        else:
            conn = http.client.HTTPConnection(
                parsed.hostname, parsed.port, timeout=_READ_TIMEOUT
            )
        try:
            conn.request(method, target, body=body or None, headers=headers)
            response = conn.getresponse()
            data = response.read()
            response_headers = {k.lower(): v for k, v in response.getheaders()}
            return int(response.status), response_headers, data
        except SyncError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise SyncError(
                "s3_request_failed", details={"key": key, "reason": str(exc)}
            ) from exc
        finally:
            conn.close()

    def _signing_key(self, datestamp: str) -> bytes:
        """Derive the SigV4 signing key for the configured region."""
        date_key = _hmac_sha256(
            f"AWS4{self.config.secret_key}".encode("utf-8"), datestamp
        )
        region_key = _hmac_sha256(date_key, self.region)
        service_key = _hmac_sha256(region_key, _SERVICE)
        return _hmac_sha256(service_key, "aws4_request")

    # ------------------------------------------------------------------ operations
    def get(self, key: str) -> bytes | None:
        """Return the object bytes or ``None`` when missing."""
        status, _headers, body = self._request("GET", key)
        if status == 200:
            return body
        if status in (403, 404):  # 403 also covers a missing key on some backends
            return None
        raise SyncError("s3_get_failed", details={"key": key, "status": status})

    def put(self, key: str, data: bytes, *, if_none_match: bool = False) -> bool:
        """Store the object; with ``if_none_match`` do not overwrite."""
        extra = {"If-None-Match": "*"} if if_none_match else None
        status, _headers, _body = self._request(
            "PUT", key, body=data, extra_headers=extra
        )
        if status in (200, 201):
            return True
        if if_none_match and status == 412:
            return False
        raise SyncError("s3_put_failed", details={"key": key, "status": status})

    def delete(self, key: str) -> None:
        """Delete the object (missing keys are ignored)."""
        status, _headers, _body = self._request("DELETE", key)
        if status not in (200, 202, 204, 404):
            raise SyncError("s3_delete_failed", details={"key": key, "status": status})

    def list(self, prefix: str) -> list[dict[str, Any]]:
        """List objects under ``prefix`` with size, ETag and modified time."""
        entries: list[dict[str, Any]] = []
        token: str | None = None
        while True:
            query = {"list-type": "2"}
            if prefix:
                query["prefix"] = prefix
            if token:
                query["continuation-token"] = token
            status, _headers, body = self._request("GET", None, query=query)
            if status != 200:
                raise SyncError(
                    "s3_list_failed", details={"prefix": prefix, "status": status}
                )
            page, truncated, token = _parse_list_xml(body)
            entries.extend(page)
            if not truncated or not token:
                return entries


def _parse_list_xml(body: bytes) -> tuple[list[dict[str, Any]], bool, str | None]:
    """Parse a ListObjectsV2 response (namespace-agnostic)."""
    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:
        raise SyncError("s3_list_failed", details={"reason": f"bad_xml: {exc}"}) from exc
    entries: list[dict[str, Any]] = []
    truncated = False
    token: str | None = None
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        if tag == "Contents":
            key: str | None = None
            size = 0
            etag: str | None = None
            modified: Any = None
            for child in element:
                child_tag = child.tag.rsplit("}", 1)[-1]
                if child_tag == "Key":
                    key = child.text
                elif child_tag == "Size":
                    size = int(child.text or 0)
                elif child_tag == "ETag":
                    etag = (child.text or "").strip('"') or None
                elif child_tag == "LastModified":
                    modified = child.text
            if key:
                entries.append(
                    {
                        "key": key,
                        "size": size,
                        "etag": etag,
                        "modified": _to_ms(modified),
                    }
                )
        elif tag == "IsTruncated":
            truncated = (element.text or "").strip().lower() == "true"
        elif tag == "NextContinuationToken":
            token = element.text
    return entries, truncated, token


# ---------------------------------------------------------------------------- client
class S3Client:
    """The sync's S3 facade: boto3 when available, otherwise the stdlib backend."""

    def __init__(self, config: S3Config) -> None:
        """Bind the client to ``config`` (the backend is created lazily)."""
        self.config = config
        self._backend: Any | None = None

    def _ensure(self) -> Any:
        """Create (once) and return the chosen backend."""
        if self._backend is not None:
            return self._backend
        try:
            import boto3  # noqa: F401,PLC0415
        except ImportError:
            self._backend = _StdlibBackend(self.config)
        else:
            self._backend = _BotoBackend(self.config)
        return self._backend

    @property
    def available(self) -> bool:
        """Always true: the stdlib backend needs no optional package."""
        return True

    @property
    def backend_name(self) -> str:
        """Return the backend that will be used (``boto3`` or ``stdlib``)."""
        if self._backend is not None:
            return str(self._backend.name)
        return backend_kind()

    @property
    def backend(self) -> Any:
        """The underlying backend object (used by tests/diagnostics)."""
        return self._ensure()

    # ------------------------------------------------------------------ operations
    def get(self, key: str) -> bytes | None:
        """Return an object's bytes, or ``None`` when the key does not exist."""
        return self._ensure().get(key)

    def put(self, key: str, data: bytes, *, if_none_match: bool = False) -> bool:
        """Upload ``data`` under ``key`` (create-only when ``if_none_match``)."""
        return self._ensure().put(key, data, if_none_match=if_none_match)

    def delete(self, key: str) -> None:
        """Delete ``key`` (missing keys are ignored)."""
        self._ensure().delete(key)

    def list(self, prefix: str) -> list[dict[str, Any]]:
        """Return every object under ``prefix`` with size, ETag and modified time."""
        return self._ensure().list(prefix)


def backend_kind() -> str:
    """Return the backend that will be used: ``"boto3"`` when importable, else ``"stdlib"``."""
    try:
        import boto3  # noqa: F401,PLC0415
    except ImportError:
        return "stdlib"
    return "boto3"


def _error_code(exc: Exception) -> str | None:
    """Extract the S3 error code from a botocore ``ClientError`` (or None)."""
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return None
    error = response.get("Error")
    if isinstance(error, dict):
        return str(error.get("Code") or "") or None
    return None


def md5_hex(data: bytes) -> str:
    """Public alias for the ETag-compatible content hash."""
    return _md5_hex(data)


__all__ = ["S3Config", "S3Client", "backend_kind", "md5_hex"]
