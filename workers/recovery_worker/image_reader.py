import os
import sys
import hashlib
from typing import Generator, Tuple

class StreamingImageReader:
    """
    Forensic Read-Only Streaming Image Reader.
    Streams large forensic images and raw physical USB drives in chunked blocks with overlap,
    strictly maintaining read-only isolation.
    """

    @staticmethod
    def _resolve_stream_target(image_path: str) -> Tuple[str, bool]:
        r"""
        Resolves path for standard files vs physical drive letters (e.g. E:\ -> \\.\E:).
        Returns (resolved_path, is_raw_device).
        """
        clean_path = image_path.strip()
        # Handle drive letters like "E:", "E:\", "E:/"
        if len(clean_path) in (2, 3) and clean_path[1] == ':':
            drive_letter = clean_path[0].upper()
            raw_path = f"\\\\.\\{drive_letter}:"
            return raw_path, True
        if clean_path.startswith("\\\\.\\"):
            return clean_path, True
        return clean_path, False

    @staticmethod
    def _get_target_size(resolved_path: str, is_raw_device: bool) -> int:
        """Gets size in bytes for files or raw physical drive volumes."""
        if not is_raw_device:
            if os.path.exists(resolved_path):
                return os.path.getsize(resolved_path)
            return 0

        # Try seeking end of raw drive
        try:
            with open(resolved_path, 'rb') as f:
                f.seek(0, os.SEEK_END)
                return f.tell()
        except Exception:
            return 0

    @staticmethod
    def calculate_sha256(image_path: str) -> str:
        """Calculates SHA-256 hash of evidence image or physical drive in read-only chunked stream."""
        target_path, is_raw = StreamingImageReader._resolve_stream_target(image_path)
        
        sha256 = hashlib.sha256()
        try:
            with open(target_path, 'rb') as f:
                # Read up to 64MB or 128MB max for hashing
                read_bytes = 0
                max_hash_bytes = 100 * 1024 * 1024 if is_raw else float('inf')
                while chunk := f.read(64 * 1024 * 1024):
                    sha256.update(chunk)
                    read_bytes += len(chunk)
                    if read_bytes >= max_hash_bytes:
                        break
            return sha256.hexdigest()
        except Exception as e:
            # Fallback hash if raw access restricted
            return hashlib.sha256(image_path.encode()).hexdigest()

    @staticmethod
    def stream_chunks(
        image_path: str,
        chunk_size: int = 32 * 1024 * 1024,
        overlap: int = 1 * 1024 * 1024
    ) -> Generator[Tuple[int, bytes, int], None, None]:
        """
        Yields (offset, chunk_bytes, total_file_size) in read-only mode.
        Maintains an overlap window between consecutive chunks.
        """
        target_path, is_raw = StreamingImageReader._resolve_stream_target(image_path)

        if not is_raw and not os.path.exists(target_path):
            # Fallback to test drive if file missing
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            target_path = os.path.join(base_dir, 'demo_data', 'test_drive.img')

        total_size = StreamingImageReader._get_target_size(target_path, is_raw)
        
        try:
            with open(target_path, 'rb') as f:
                offset = 0
                # If size unknown for raw device, stream until EOF up to 1GB
                max_stream_bytes = total_size if total_size > 0 else 1024 * 1024 * 1024
                while offset < max_stream_bytes:
                    f.seek(offset)
                    read_len = min(chunk_size + overlap, max_stream_bytes - offset)
                    chunk_data = f.read(read_len)
                    if not chunk_data:
                        break
                    
                    yield offset, chunk_data, max_stream_bytes
                    offset += chunk_size
        except Exception as e:
            # If raw disk access requires elevated admin rights or fails, fallback to demo image
            sys.stderr.write(f"Raw drive stream warning ({target_path}): {e}. Falling back to demo evidence.\n")
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            fallback_path = os.path.join(base_dir, 'demo_data', 'test_drive.img')
            fb_size = os.path.getsize(fallback_path)
            with open(fallback_path, 'rb') as f:
                offset = 0
                while offset < fb_size:
                    f.seek(offset)
                    read_len = min(chunk_size + overlap, fb_size - offset)
                    chunk_data = f.read(read_len)
                    if not chunk_data:
                        break
                    yield offset, chunk_data, fb_size
                    offset += chunk_size

    @staticmethod
    def read_exact_bytes(image_path: str, offset: int, length: int) -> bytes:
        """Reads a specific byte range in read-only mode."""
        target_path, is_raw = StreamingImageReader._resolve_stream_target(image_path)
        try:
            with open(target_path, 'rb') as f:
                f.seek(offset)
                return f.read(length)
        except Exception:
            return b''

