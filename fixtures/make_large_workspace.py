"""Generates a large workspace fixture (many MB of pseudo-random data across
several files) so the chunked transfer protocol has enough chunks to exercise
duplicate-detection and mid-transfer failure scenarios meaningfully.

Usage: python make_large_workspace.py [size_mb] [dest_dir]
"""
import os
import sys

DEFAULT_SIZE_MB = 200
DEFAULT_DEST = os.path.join(os.path.dirname(__file__), "large_workspace")


def main():
    size_mb = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_SIZE_MB
    dest_dir = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_DEST

    os.makedirs(dest_dir, exist_ok=True)
    file_count = 10
    bytes_per_file = (size_mb * 1024 * 1024) // file_count

    for i in range(file_count):
        path = os.path.join(dest_dir, f"blob_{i:02d}.bin")
        with open(path, "wb") as f:
            remaining = bytes_per_file
            chunk = os.urandom(1024 * 1024)
            while remaining > 0:
                write_size = min(len(chunk), remaining)
                f.write(chunk[:write_size])
                remaining -= write_size

    print(f"Generated ~{size_mb}MB fixture at {dest_dir} ({file_count} files)")


if __name__ == "__main__":
    main()
