import os
import hashlib
from typing import List, Dict, Any, Tuple
from workers.recovery_worker.signatures import SignatureDatabase
from workers.recovery_worker.image_reader import StreamingImageReader

class ForensicCarver:
    """
    Read-Only Forensic File Carving Engine.
    Scans forensic disk images (.img / .raw) in read-only chunked stream, extracts file candidates,
    performs structure validation, and assigns confidence scores (0-100).
    """

    @staticmethod
    def scan_and_carve(
        image_path: str,
        target_extensions: List[str],
        output_dir: str
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Reads evidence image in READ-ONLY ('rb') streaming mode, carves signature candidates,
        validates structure, saves recovered files to output_dir, and hashes results.
        """
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Forensic evidence image not found: {image_path}")

        os.makedirs(output_dir, exist_ok=True)
        
        # Calculate pre-scan SHA-256 of original evidence image
        evidence_hash = StreamingImageReader.calculate_sha256(image_path)

        recovered_artifacts = []
        scanned_bytes = os.path.getsize(image_path)
        
        target_exts = [e.lower().lstrip('.') for e in target_extensions] if target_extensions else ['jpg', 'png', 'pdf', 'docx', 'txt', 'zip']

        # Scan chunks using StreamingImageReader to avoid loading multi-GB/TB files into RAM
        seen_offsets = set()

        for ext in target_exts:
            sig = SignatureDatabase.get_by_ext(ext)
            if not sig:
                continue

            header = sig.header
            if not header and ext == 'txt':
                # Controlled text region scanning
                continue

            match_count = 0

            for chunk_offset, chunk_bytes, total_size in StreamingImageReader.stream_chunks(image_path, chunk_size=16*1024*1024, overlap=1*1024*1024):
                offset_in_chunk = 0

                while True:
                    idx_in_chunk = chunk_bytes.find(header, offset_in_chunk)
                    if idx_in_chunk == -1:
                        break

                    global_offset = chunk_offset + idx_in_chunk
                    offset_in_chunk = idx_in_chunk + len(header)

                    if global_offset in seen_offsets:
                        continue
                    seen_offsets.add(global_offset)
                    match_count += 1

                    # Determine file end or capture window
                    end_idx_in_chunk = -1
                    if sig.footer:
                        end_idx_in_chunk = chunk_bytes.find(sig.footer, offset_in_chunk)
                        if end_idx_in_chunk != -1:
                            end_idx_in_chunk += len(sig.footer)

                    if end_idx_in_chunk != -1 and (end_idx_in_chunk - idx_in_chunk) <= sig.max_size and (end_idx_in_chunk - idx_in_chunk) >= 100:
                        candidate_data = chunk_bytes[idx_in_chunk : end_idx_in_chunk]
                    else:
                        candidate_size = min(sig.max_size, total_size - global_offset, 5 * 1024 * 1024)
                        candidate_data = StreamingImageReader.read_exact_bytes(image_path, global_offset, candidate_size)

                    val_res = SignatureDatabase.validate_file_structure(candidate_data, ext)

                    if val_res['confidence'] < 20:
                        continue

                    filename = f"recovered_off_{global_offset:08X}.{ext}"
                    out_path = os.path.join(output_dir, filename)

                    with open(out_path, 'wb') as out_f:
                        out_f.write(candidate_data)

                    carved_hash = hashlib.sha256(candidate_data).hexdigest()

                    recovered_artifacts.append({
                        'filename': filename,
                        'original_filename': '',
                        'original_path': '',
                        'detected_type': ext.upper(),
                        'mime_type': sig.mime,
                        'size_bytes': len(candidate_data),
                        'byte_offset': global_offset,
                        'sector_number': global_offset // 512,
                        'sector_offset': global_offset,
                        'confidence_score': val_res['confidence'],
                        'validation_status': val_res['status'],
                        'carving_method': 'HEADER_FOOTER_MATCH' if sig.footer and end_idx_in_chunk != -1 else 'STRUCTURE_VALIDATED_HEADER',
                        'recovery_source': 'Unallocated Signature Carving',
                        'deleted_status': True,
                        'sha256_hash': carved_hash,
                        'output_path': out_path,
                        'classification': sig.classification,
                        'validation_details': val_res['details'],
                        'fragment_count': 1,
                        'fragments_missing': 0,
                        'reconstruction_status': 'SUCCESS' if val_res['status'] == 'VALID' else 'PARTIAL'
                    })

                    if match_count >= 50:
                        break

                if match_count >= 50:
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
        return StreamingImageReader.calculate_sha256(file_path)

