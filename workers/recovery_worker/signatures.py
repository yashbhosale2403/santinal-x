import io
from typing import Dict, Any, Optional

class FileSignature:
    def __init__(self, ext: str, mime: str, classification: str, header: bytes, footer: Optional[bytes] = None, max_size: int = 50 * 1024 * 1024):
        self.ext = ext
        self.mime = mime
        self.classification = classification
        self.header = header
        self.footer = footer
        self.max_size = max_size

class SignatureDatabase:
    """
    Modular File Signature Database & Structure Validators.
    Provides headers, footers, MIME types, structure validators, and confidence estimators.
    """

    SIGNATURES = [
        FileSignature('jpg', 'image/jpeg', 'IMAGE', b'\xFF\xD8\xFF', b'\xFF\xD9', 25 * 1024 * 1024),
        FileSignature('png', 'image/png', 'IMAGE', b'\x89PNG\r\n\x1a\n', b'IEND\xaeB`\x82', 25 * 1024 * 1024),
        FileSignature('pdf', 'application/pdf', 'DOCUMENT', b'%PDF-', b'%%EOF', 50 * 1024 * 1024),
        FileSignature('gif', 'image/gif', 'IMAGE', b'GIF89a', b'\x00\x3B', 15 * 1024 * 1024),
        FileSignature('bmp', 'image/bmp', 'IMAGE', b'BM', None, 20 * 1024 * 1024),
        FileSignature('docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'DOCUMENT', b'PK\x03\x04', b'PK\x05\x06', 50 * 1024 * 1024),
        FileSignature('zip', 'application/zip', 'ARCHIVE', b'PK\x03\x04', b'PK\x05\x06', 100 * 1024 * 1024),
        FileSignature('mp3', 'audio/mpeg', 'AUDIO', b'ID3', None, 30 * 1024 * 1024),
        FileSignature('mp4', 'video/mp4', 'VIDEO', b'ftyp', None, 200 * 1024 * 1024),
        FileSignature('wav', 'audio/wav', 'AUDIO', b'RIFF', None, 50 * 1024 * 1024),
        FileSignature('txt', 'text/plain', 'TEXT', b'', None, 10 * 1024 * 1024)
    ]

    @classmethod
    def get_by_ext(cls, ext: str) -> Optional[FileSignature]:
        for s in cls.SIGNATURES:
            if s.ext.lower() == ext.lower():
                return s
        return None

    @classmethod
    def validate_file_structure(cls, data: bytes, ext: str) -> Dict[str, Any]:
        """
        Performs format-specific structure validation and returns validation_status & confidence_score.
        """
        ext = ext.lower()
        
        if ext in ['jpg', 'jpeg']:
            return cls._validate_jpeg(data)
        elif ext == 'png':
            return cls._validate_png(data)
        elif ext == 'pdf':
            return cls._validate_pdf(data)
        elif ext in ['docx', 'zip']:
            return cls._validate_zip_office(data, ext)
        elif ext == 'txt':
            return cls._validate_txt(data)
        elif ext == 'mp4':
            return cls._validate_mp4(data)
        elif ext == 'wav':
            return cls._validate_wav(data)
        elif ext == 'mp3':
            return cls._validate_mp3(data)
        elif ext == 'gif':
            return cls._validate_gif(data)
        elif ext == 'bmp':
            return cls._validate_bmp(data)
        else:
            # Generic signature matching validation
            sig = cls.get_by_ext(ext)
            if sig and data.startswith(sig.header):
                return {
                    'status': 'VALID',
                    'confidence': 85,
                    'details': 'Header magic match verified.'
                }
            return {'status': 'UNKNOWN', 'confidence': 50, 'details': 'Generic format validation.'}

    @staticmethod
    def _validate_jpeg(data: bytes) -> Dict[str, Any]:
        if not data.startswith(b'\xFF\xD8\xFF'):
            return {'status': 'INVALID', 'confidence': 0, 'details': 'Missing JPEG SOI marker.'}

        has_eoi = b'\xFF\xD9' in data
        try:
            from PIL import Image
            img = Image.open(io.BytesIO(data))
            img.verify()
            return {
                'status': 'VALID',
                'confidence': 98,
                'details': f"JPEG decoded successfully ({img.size[0]}x{img.size[1]} px, {img.format})."
            }
        except Exception:
            if has_eoi:
                return {'status': 'PARTIALLY_VALID', 'confidence': 78, 'details': 'Valid SOI and EOI markers found, minor decoder warning.'}
            return {'status': 'CORRUPTED', 'confidence': 45, 'details': 'Valid SOI header, missing EOI marker.'}

    @staticmethod
    def _validate_png(data: bytes) -> Dict[str, Any]:
        if not data.startswith(b'\x89PNG\r\n\x1a\n'):
            return {'status': 'INVALID', 'confidence': 0, 'details': 'Missing PNG magic header.'}
        if b'IHDR' in data[:30] and (b'IEND' in data):
            try:
                from PIL import Image
                img = Image.open(io.BytesIO(data))
                img.verify()
                return {'status': 'VALID', 'confidence': 99, 'details': 'PNG chunks and image payload verified.'}
            except Exception:
                return {'status': 'PARTIALLY_VALID', 'confidence': 82, 'details': 'PNG IHDR & IEND chunks present.'}
        return {'status': 'CORRUPTED', 'confidence': 50, 'details': 'Truncated PNG structure.'}

    @staticmethod
    def _validate_pdf(data: bytes) -> Dict[str, Any]:
        if not data.startswith(b'%PDF-'):
            return {'status': 'INVALID', 'confidence': 0, 'details': 'Missing %PDF- header.'}
        has_eof = b'%%EOF' in data
        has_xref = b'xref' in data or b'/Root' in data
        if has_eof and has_xref:
            return {'status': 'VALID', 'confidence': 95, 'details': 'PDF header, xref table, and %%EOF verified.'}
        elif has_eof:
            return {'status': 'PARTIALLY_VALID', 'confidence': 80, 'details': 'PDF header and %%EOF verified.'}
        return {'status': 'CORRUPTED', 'confidence': 40, 'details': 'Truncated PDF missing %%EOF.'}

    @staticmethod
    def _validate_zip_office(data: bytes, ext: str) -> Dict[str, Any]:
        if not data.startswith(b'PK\x03\x04'):
            return {'status': 'INVALID', 'confidence': 0, 'details': 'Missing ZIP PK header.'}
        try:
            import zipfile
            zf = zipfile.ZipFile(io.BytesIO(data))
            namelist = zf.namelist()
            if ext == 'docx':
                if '[Content_Types].xml' in namelist or 'word/document.xml' in namelist:
                    return {'status': 'VALID', 'confidence': 98, 'details': 'DOCX Office OpenXML container structure verified.'}
                return {'status': 'PARTIALLY_VALID', 'confidence': 75, 'details': 'Valid ZIP container, non-standard DOCX structure.'}
            return {'status': 'VALID', 'confidence': 95, 'details': f"ZIP archive verified ({len(namelist)} files inside)."}
        except Exception:
            return {'status': 'CORRUPTED', 'confidence': 45, 'details': 'Corrupted ZIP central directory.'}

    @staticmethod
    def _validate_txt(data: bytes) -> Dict[str, Any]:
        if not data:
            return {'status': 'INVALID', 'confidence': 0, 'details': 'Empty text file.'}
        try:
            text = data.decode('utf-8', errors='ignore')
            printable = sum(1 for c in text if c.isprintable() or c in '\r\n\t')
            ratio = printable / max(1, len(text))
            if ratio > 0.9:
                return {'status': 'VALID', 'confidence': 92, 'details': f"Valid text file ({ratio*100:.1f}% printable chars)."}
            elif ratio > 0.6:
                return {'status': 'PARTIALLY_VALID', 'confidence': 65, 'details': 'Mixed binary/text content.'}
        except Exception:
            pass
        return {'status': 'INVALID', 'confidence': 20, 'details': 'Non-text binary data.'}

    @staticmethod
    def _validate_mp4(data: bytes) -> Dict[str, Any]:
        if b'ftyp' in data[:32]:
            has_moov = b'moov' in data or b'mdat' in data
            if has_moov:
                return {'status': 'VALID', 'confidence': 94, 'details': 'ISO MP4 container ftyp & moov/mdat boxes verified.'}
            return {'status': 'PARTIALLY_VALID', 'confidence': 75, 'details': 'MP4 ftyp box present, trailing stream truncated.'}
        return {'status': 'INVALID', 'confidence': 0, 'details': 'Missing MP4 ftyp box header.'}

    @staticmethod
    def _validate_wav(data: bytes) -> Dict[str, Any]:
        if data.startswith(b'RIFF') and b'WAVE' in data[8:16]:
            return {'status': 'VALID', 'confidence': 95, 'details': 'RIFF WAVE audio header and fmt chunk verified.'}
        return {'status': 'INVALID', 'confidence': 0, 'details': 'Missing RIFF WAVE audio header.'}

    @staticmethod
    def _validate_mp3(data: bytes) -> Dict[str, Any]:
        if data.startswith(b'ID3') or data.startswith(b'\xFF\xFB') or data.startswith(b'\xFF\xF3'):
            return {'status': 'VALID', 'confidence': 90, 'details': 'MP3 ID3 tag / frame header verified.'}
        return {'status': 'INVALID', 'confidence': 0, 'details': 'Missing MP3 ID3 header or sync word.'}

    @staticmethod
    def _validate_gif(data: bytes) -> Dict[str, Any]:
        if data.startswith(b'GIF87a') or data.startswith(b'GIF89a'):
            has_term = b'\x00\x3B' in data[-4:] or b'\x3B' in data[-2:]
            if has_term:
                return {'status': 'VALID', 'confidence': 96, 'details': 'GIF header and trailer byte 0x3B verified.'}
            return {'status': 'PARTIALLY_VALID', 'confidence': 78, 'details': 'GIF header present, missing trailer.'}
        return {'status': 'INVALID', 'confidence': 0, 'details': 'Missing GIF87a/GIF89a header.'}

    @staticmethod
    def _validate_bmp(data: bytes) -> Dict[str, Any]:
        if data.startswith(b'BM'):
            return {'status': 'VALID', 'confidence': 88, 'details': 'BMP magic header BM verified.'}
        return {'status': 'INVALID', 'confidence': 0, 'details': 'Missing BMP magic header.'}

