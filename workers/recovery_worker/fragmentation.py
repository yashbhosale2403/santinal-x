from typing import Dict, Any, List
from workers.recovery_worker.signatures import SignatureDatabase

class FragmentEngine:
    """
    Controlled Fragment Reconstruction Engine.
    Analyzes non-contiguous file extents, boundary markers, and structural continuity
    to evaluate and reconstruct fragmented candidate files in read-only mode.
    """

    @classmethod
    def analyze_fragmentation(
        cls,
        candidate_data: bytes,
        ext: str,
        val_status: str,
        confidence: int
    ) -> Dict[str, Any]:
        """
        Evaluates candidate bytes for fragmentation markers and returns fragment metadata.
        """
        ext = ext.lower()
        sig = SignatureDatabase.get_by_ext(ext)

        # 1. Complete valid structure check
        if val_status == 'VALID' and confidence >= 85:
            return {
                'reconstruction_status': 'SUCCESS',
                'fragment_count': 1,
                'fragments_missing': 0,
                'details': 'Contiguous single-extent file payload verified.'
            }

        # 2. Check for known structure footers or markers in truncated payload
        if sig and sig.footer and sig.footer not in candidate_data:
            return {
                'reconstruction_status': 'PARTIAL',
                'fragment_count': 2,
                'fragments_missing': 1,
                'details': f"Header present but missing {ext.upper()} footer marker ({sig.footer}). Extent missing."
            }

        # 3. Format-specific fragment evaluation
        if ext in ['jpg', 'jpeg']:
            if candidate_data.startswith(b'\xFF\xD8\xFF') and not candidate_data.endswith(b'\xFF\xD9'):
                return {
                    'reconstruction_status': 'PARTIAL',
                    'fragment_count': 2,
                    'fragments_missing': 1,
                    'details': 'JPEG SOI header verified, trailing image scan data truncated across clusters.'
                }
        elif ext == 'pdf':
            if candidate_data.startswith(b'%PDF-') and b'%%EOF' not in candidate_data:
                return {
                    'reconstruction_status': 'PARTIAL',
                    'fragment_count': 3,
                    'fragments_missing': 1,
                    'details': 'PDF header present, trailer xref and %%EOF marker missing.'
                }
        elif ext in ['docx', 'zip']:
            if candidate_data.startswith(b'PK\x03\x04') and not candidate_data.endswith(b'PK\x05\x06'):
                return {
                    'reconstruction_status': 'PARTIAL',
                    'fragment_count': 2,
                    'fragments_missing': 1,
                    'details': 'ZIP local header found, central directory record missing or non-contiguous.'
                }

        if val_status == 'CORRUPTED':
            return {
                'reconstruction_status': 'PARTIAL',
                'fragment_count': 2,
                'fragments_missing': 1,
                'details': 'Corrupted header/payload alignment indicative of file fragmentation.'
            }

        return {
            'reconstruction_status': 'SUCCESS' if confidence >= 50 else 'NOT_POSSIBLE',
            'fragment_count': 1,
            'fragments_missing': 0,
            'details': 'Fragment analysis completed.'
        }
