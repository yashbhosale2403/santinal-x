import os
import io
import hashlib
from typing import List, Dict, Any, Tuple
from workers.recovery_worker.signatures import SignatureDatabase

class ForensicCarver:
    """
    Read-Only Forensic File Carving Engine.
    Scans forensic disk images (.img / .raw) in read-only mode, extracts file candidates,
    performs structure validation, and assigns confidence scores (0-100).
    """

    @staticmethod
    def scan_and_carve(
        image_path: str,
        target_extensions: List[str],
        output_dir: str
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Reads evidence image in READ-ONLY ('rb') mode, carves signature candidates,
        validates structure, saves recovered files to output_dir, and hashes results.
        """
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Forensic evidence image not found: {image_path}")

        os.makedirs(output_dir, exist_ok=True)
        
        # Calculate pre-scan SHA-256 of original evidence image
        evidence_hash = ForensicCarver._calculate_sha256(image_path)

        recovered_artifacts = []
        scanned_bytes = os.path.getsize(image_path)
        
        target_exts = [e.lower().lstrip('.') for e in target_extensions] if target_extensions else ['jpg', 'png', 'pdf', 'docx', 'txt', 'zip']

        with open(image_path, 'rb') as f:
            content = f.read()

        # Iterate over signatures
        for ext in target_exts:
            sig = SignatureDatabase.get_by_ext(ext)
            if not sig:
                continue

            # Signature header scanning
            header = sig.header
            if not header and ext == 'txt':
                # Special handling for text carving
                continue

            offset = 0
            match_count = 0
            while True:
                idx = content.find(header, offset)
                if idx == -1:
                    break
                
                match_count += 1
                offset = idx + len(header)

                # Determine file end or window size
                end_idx = -1
                if sig.footer:
                    end_idx = content.find(sig.footer, offset)
                    if end_idx != -1:
                        end_idx += len(sig.footer)

                if end_idx == -1 or (end_idx - idx) > sig.max_size or (end_idx - idx) < 100:
                    # Estimate file size or capture default chunk
                    candidate_data = content[idx : idx + min(5 * 1024 * 1024, len(content) - idx)]
                else:
                    candidate_data = content[idx : end_idx]

                # Perform Structure Validation
                val_res = SignatureDatabase.validate_file_structure(candidate_data, ext)
                
                # Filter out low-quality false positives
                if val_res['confidence'] < 20:
                    continue

                filename = f"recovered_off_{idx:08X}.{ext}"
                out_path = os.path.join(output_dir, filename)

                # Write carved artifact
                with open(out_path, 'wb') as out_f:
                    out_f.write(candidate_data)

                carved_hash = hashlib.sha256(candidate_data).hexdigest()

                recovered_artifacts.append({
                    'filename': filename,
                    'detected_type': ext.upper(),
                    'mime_type': sig.mime,
                    'size_bytes': len(candidate_data),
                    'sector_offset': idx,
                    'confidence_score': val_res['confidence'],
                    'validation_status': val_res['status'],
                    'carving_method': 'HEADER_FOOTER_MATCH' if sig.footer and end_idx != -1 else 'STRUCTURE_VALIDATED_HEADER',
                    'sha256_hash': carved_hash,
                    'output_path': out_path,
                    'classification': sig.classification,
                    'validation_details': val_res['details']
                })

                if match_count >= 50: # Limit per extension for safety
                    break

        summary = {
            'evidence_sha256': evidence_hash,
            'scanned_bytes': scanned_bytes,
            'total_candidates': len(recovered_artifacts),
            'valid_count': sum(1 for a in recovered_artifacts if a['validation_status'] == 'VALID'),
            'high_confidence_count': sum(1 for a in recovered_artifacts if a['confidence_score'] >= 75)
        }

        return recovered_artifacts, summary

    @staticmethod
    def _calculate_sha256(file_path: str) -> str:
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
        return sha256.hexdigest()
