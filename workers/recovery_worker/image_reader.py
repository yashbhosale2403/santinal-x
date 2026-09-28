import os
import hashlib
from typing import Generator, Tuple

class StreamingImageReader:
    """
    Forensic Read-Only Streaming Image Reader.
    Streams large forensic images in chunked blocks with overlap to prevent 
    memory exhaustion on multi-GB/TB evidence files, strictly maintaining read-only isolation.
    """

    @staticmethod
    def calculate_sha256(image_path: str) -> str:
        """Calculates SHA-256 hash of evidence image in read-only chunked stream."""
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Evidence file not found: {image_path}")
        
        sha256 = hashlib.sha256()
        with open(image_path, 'rb') as f:
            while chunk := f.read(64 * 1024 * 1024):
                sha256.update(chunk)
        return sha256.hexdigest()

    @staticmethod
    def stream_chunks(
        image_path: str,
        chunk_size: int = 32 * 1024 * 1024,
        overlap: int = 1 * 1024 * 1024
    ) -> Generator[Tuple[int, bytes, int], None, None]:
        """
        Yields (offset, chunk_bytes, total_file_size) in read-only mode.
        Maintains an overlap window between consecutive chunks to ensure signature headers
        or file structures straddling chunk boundaries are detected.
        """
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Evidence image not found: {image_path}")

        total_size = os.path.getsize(image_path)
        if total_size == 0:
            return

        with open(image_path, 'rb') as f:
            offset = 0
            while offset < total_size:
                f.seek(offset)
                read_len = min(chunk_size + overlap, total_size - offset)
                chunk_data = f.read(read_len)
                if not chunk_data:
                    break
                
                yield offset, chunk_data, total_size
                offset += chunk_size

    @staticmethod
    def read_exact_bytes(image_path: str, offset: int, length: int) -> bytes:
        """Reads a specific byte range in read-only mode."""
        if not os.path.exists(image_path):
            return b''
        
        total_size = os.path.getsize(image_path)
        if offset >= total_size:
            return b''
        
        with open(image_path, 'rb') as f:
            f.seek(offset)
            return f.read(min(length, total_size - offset))
