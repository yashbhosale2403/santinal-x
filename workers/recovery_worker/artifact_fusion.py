from typing import List, Dict, Any, Tuple

class ArtifactFusion:
    """
    Artifact Fusion & Deduplication Layer.
    Merges duplicate candidate artifacts recovered across multiple methods (e.g. MFT Metadata + Raw Carving),
    combining original metadata with validated file payloads and filtering duplicate SHA-256 artifacts.
    """

    @classmethod
    def fuse_artifacts(
        cls,
        candidate_list: List[Dict[str, Any]],
        deduplicate: bool = True
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Deduplicates candidate list by SHA-256 hash and byte offset.
        Returns (fused_artifacts, fusion_summary).
        """
        if not candidate_list:
            return [], {'total_candidates': 0, 'unique_artifacts': 0, 'duplicates_merged': 0}

        if not deduplicate:
            return candidate_list, {
                'total_candidates': len(candidate_list),
                'unique_artifacts': len(candidate_list),
                'duplicates_merged': 0
            }

        seen_hashes = {}
        fused = []
        duplicates_merged = 0

        for item in candidate_list:
            sha256 = item.get('sha256_hash')
            offset = item.get('byte_offset', 0)
            key = sha256 if sha256 else f"off_{offset}_{item.get('size_bytes')}"

            if key in seen_hashes:
                duplicates_merged += 1
                existing = seen_hashes[key]

                # Prefer item with original filename or higher confidence
                if item.get('original_filename') and not existing.get('original_filename'):
                    existing['original_filename'] = item['original_filename']
                    existing['original_path'] = item.get('original_path', '')
                    existing['filename'] = item['filename']
                
                if item.get('recovery_source') and 'MFT' in item['recovery_source']:
                    existing['recovery_source'] = f"{existing.get('recovery_source', '')} + {item['recovery_source']}"

                if item.get('confidence_score', 0) > existing.get('confidence_score', 0):
                    existing['confidence_score'] = item['confidence_score']
                    existing['validation_status'] = item['validation_status']
                    existing['validation_details'] = item['validation_details']
            else:
                seen_hashes[key] = dict(item)

        fused = list(seen_hashes.values())

        summary = {
            'total_candidates': len(candidate_list),
            'unique_artifacts': len(fused),
            'duplicates_merged': duplicates_merged
        }

        return fused, summary
