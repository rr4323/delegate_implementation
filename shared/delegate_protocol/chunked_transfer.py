"""Chunked ZIP transfer protocol shared by the control plane and the worker.

Implements the DATA_START / DATA_CHUNK / DATA_END message sequence described
in Delegate Design.md over a single Redis Stream. Values are base64-encoded so
the whole message can travel as text fields (simpler than juggling raw bytes
through redis-py) -- an explicit, documented simplification vs. production,
which would send chunk bytes as a raw field to avoid the ~33% base64 overhead.
"""
import base64
import hashlib
import io
import os
import time
import uuid
import zipfile

CHUNK_SIZE = 256 * 1024  # 256 KiB


def zip_directory_to_bytes(src_dir: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _dirs, files in os.walk(src_dir):
            for name in files:
                full_path = os.path.join(root, name)
                arcname = os.path.relpath(full_path, src_dir)
                zf.write(full_path, arcname)
    return buf.getvalue()


def zip_single_file_to_bytes(src_dir: str, file_name: str):
    """Zips just one file out of a workspace fixture, for a DATA_REQUEST that
    names a specific file rather than asking for the whole workspace (`"*"`).
    Returns None if the file doesn't exist or escapes src_dir (a
    `file_name` containing `..` could otherwise read outside the fixture).
    """
    full_path = os.path.normpath(os.path.join(src_dir, file_name))
    src_dir_real = os.path.realpath(src_dir)
    if os.path.commonpath([src_dir_real, os.path.realpath(full_path)]) != src_dir_real:
        return None
    if not os.path.isfile(full_path):
        return None

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(full_path, file_name)
    return buf.getvalue()


def extract_zip_bytes(data: bytes, dest_dir: str) -> None:
    os.makedirs(dest_dir, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        zf.extractall(dest_dir)


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class TransferFailed(Exception):
    """Raised when a chunked transfer times out or fails integrity validation.

    Carries the last Redis stream id seen so the caller can resume reading
    from that point on the next attempt instead of replaying the whole stream.
    """

    def __init__(self, message: str, last_id: str = None):
        super().__init__(message)
        self.last_id = last_id


class ChunkSender:
    """Publishes DATA_START / DATA_CHUNK* / DATA_END for a byte payload."""

    def __init__(self, redis_conn, chunk_size: int = CHUNK_SIZE):
        self.r = redis_conn
        self.chunk_size = chunk_size

    def send_bytes(self, stream_key: str, data: bytes, base_fields: dict) -> tuple:
        transfer_id = str(uuid.uuid4())
        checksum = sha256_bytes(data)
        total_size = len(data)

        self.r.xadd(stream_key, {
            **base_fields,
            "type": "DATA_START",
            "transfer_id": transfer_id,
            "total_size": str(total_size),
            "chunk_size": str(self.chunk_size),
            "checksum": checksum,
        })

        seq = 0
        for offset in range(0, total_size, self.chunk_size):
            chunk = data[offset: offset + self.chunk_size]
            self.r.xadd(stream_key, {
                **base_fields,
                "type": "DATA_CHUNK",
                "transfer_id": transfer_id,
                "sequence_no": str(seq),
                "chunk_b64": base64.b64encode(chunk).decode("ascii"),
            })
            seq += 1

        # Guarantee at least one DATA_CHUNK message even for an empty payload
        # so the receiver's state machine has something to key duplicate
        # detection off of; harmless for non-empty payloads.
        self.r.xadd(stream_key, {
            **base_fields,
            "type": "DATA_END",
            "transfer_id": transfer_id,
            "total_chunks": str(seq),
        })
        return transfer_id, checksum, total_size


class ChunkReceiver:
    """Consumes one DATA_START..DATA_END sequence off a Redis Stream.

    `receive_once` blocks (re-polling with XREAD) until a transfer completes
    or `wait_timeout` elapses with no forward progress, mirroring the
    recreate-from-start failure strategy: any partial state is discarded by
    the caller and a fresh DATA_REQUEST is expected to start a new transfer_id.
    """

    def __init__(self, redis_conn, stream_key: str, wait_timeout: float = 15.0):
        self.r = redis_conn
        self.stream_key = stream_key
        self.wait_timeout = wait_timeout

    def receive_once(self, last_id: str = "0") -> tuple:
        transfer_id = None
        total_size = None
        checksum_expected = None
        started = False
        buf = bytearray()
        seen_seq = set()
        deadline = time.time() + self.wait_timeout

        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise TransferFailed("timeout waiting for transfer progress", last_id=last_id)

            block_ms = int(max(remaining, 0.1) * 1000)
            resp = self.r.xread({self.stream_key: last_id}, count=100, block=block_ms)
            if not resp:
                continue

            for _stream, messages in resp:
                for msg_id, fields in messages:
                    last_id = msg_id
                    mtype = fields.get("type")

                    if mtype == "DATA_START":
                        transfer_id = fields["transfer_id"]
                        total_size = int(fields["total_size"])
                        checksum_expected = fields["checksum"]
                        started = True
                        buf = bytearray()
                        seen_seq = set()
                        deadline = time.time() + self.wait_timeout

                    elif mtype == "DATA_CHUNK" and started and fields.get("transfer_id") == transfer_id:
                        seq = int(fields["sequence_no"])
                        if seq in seen_seq:
                            continue  # duplicate chunk, already committed
                        seen_seq.add(seq)
                        buf.extend(base64.b64decode(fields["chunk_b64"]))
                        deadline = time.time() + self.wait_timeout

                    elif mtype == "DATA_END" and started and fields.get("transfer_id") == transfer_id:
                        data = bytes(buf)
                        if len(data) != total_size:
                            raise TransferFailed(
                                f"size mismatch: received {len(data)} expected {total_size}",
                                last_id=last_id,
                            )
                        if sha256_bytes(data) != checksum_expected:
                            raise TransferFailed("checksum mismatch", last_id=last_id)
                        return data, last_id, transfer_id
