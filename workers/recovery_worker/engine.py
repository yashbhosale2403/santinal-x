import os
from typing import List, Dict, Any, Tuple
from workers.recovery_worker.image_reader import StreamingImageReader
from workers.recovery_worker.partition import PartitionDetector
from workers.recovery_worker.filesystem import FilesystemDetector
from workers.recovery_worker.metadata_recovery import FilesystemMetadataRecovery
from workers.recovery_worker.carver import ForensicCarver
from workers.recovery_worker.fragmentation import FragmentEngine
from workers.recovery_worker.artifact_fusion import ArtifactFusion
from workers.recovery_worker.confidence import ConfidenceCalculator

class RecoveryEngine:
    """
    Central Forensic Recovery Orchestrator for SENTINEL-X.
    Coordinates evidence verification, partition detection, filesystem metadata recovery,
    streaming signature carving, fragment reconstruction, artifact fusion, and confidence scoring.
    Maintains 100% read-only evidence isolation.
    """

    @classmethod
    def run(
        cls,
        image_path: str,
        recovery_mode: str = 'DEEP',
        target_extensions: List[str] = None,
        options: Dict[str, Any] = None,
        output_dir: str = '',
        progress_callback = None
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Executes multi-method forensic recovery pipeline based on recovery_mode (QUICK, DEEP, MAXIMUM).
        Returns (recovered_artifacts_list, summary_dict).
        """
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Forensic evidence image missing: {image_path}")

        options = options or {'validation': True, 'fragmentation': True, 'deduplicate': True}
        target_exts = [e.lower().lstrip('.') for e in target_extensions] if target_extensions else ['jpg', 'png', 'pdf', 'docx', 'zip', 'txt', 'mp4', 'mp3']

        methods_attempted = []
        methods_completed = []
        methods_skipped = []

        if progress_callback:
            progress_callback(10, 'Evidence Verification', 'Computing read-only source evidence SHA-256 seal...')

        # Step 1: Pre-operation Evidence SHA-256 calculation
        evidence_hash_before = StreamingImageReader.calculate_sha256(image_path)
        methods_attempted.append("Evidence Verification (Read-Only SHA-256)")
        methods_completed.append("Evidence Verification (Read-Only SHA-256)")

        if progress_callback:
            progress_callback(25, 'Partition & Filesystem Analysis', 'Detecting partition schemes and filesystem structures...')

        # Step 2: Partition Detection
        methods_attempted.append("Partition Scheme Detection")
        partitions = PartitionDetector.detect_partitions(image_path)
        methods_completed.append("Partition Scheme Detection")

        # Step 3: Filesystem Identification
        methods_attempted.append("Filesystem Identification")
        first_part_offset = partitions[0]['start_byte'] if partitions else 0
        fs_info = FilesystemDetector.detect_filesystem(image_path, offset=first_part_offset)
        methods_completed.append("Filesystem Identification")

        all_candidates = []

        if progress_callback:
            progress_callback(40, 'Filesystem Metadata Carving', 'Scanning MFT records and deleted directory entries...')

        # Step 4: Filesystem-Aware Metadata Recovery (MFT / Directory Entries)
        methods_attempted.append("Filesystem Metadata Recovery (NTFS MFT / Directory Entries)")
        try:
            meta_candidates = FilesystemMetadataRecovery.recover_deleted_metadata(
                image_path=image_path,
                target_exts=target_exts,
                output_dir=output_dir
            )
            if meta_candidates:
                all_candidates.extend(meta_candidates)
                methods_completed.append("Filesystem Metadata Recovery (NTFS MFT / Directory Entries)")
            else:
                methods_skipped.append("Filesystem Metadata Recovery (No deleted MFT records matching criteria)")
        except Exception as e:
            methods_skipped.append(f"Filesystem Metadata Recovery (Error: {str(e)})")

        if progress_callback:
            progress_callback(60, 'Signature Carving', f'Streaming unallocated space for file signatures ({len(all_candidates)} candidates found)...', len(all_candidates), 0)

        # Step 5: Unallocated Space Signature Carving (For DEEP and MAXIMUM modes)
        if recovery_mode in ['DEEP', 'MAXIMUM']:
            methods_attempted.append("Unallocated Space Signature Carving (Streaming)")
            try:
                carved_artifacts, _ = ForensicCarver.scan_and_carve(
                    image_path=image_path,
                    target_extensions=target_exts,
                    output_dir=output_dir
                )
                all_candidates.extend(carved_artifacts)
                methods_completed.append("Unallocated Space Signature Carving (Streaming)")
            except Exception as e:
                methods_skipped.append(f"Unallocated Space Signature Carving (Error: {str(e)})")
        else:
            methods_skipped.append("Unallocated Space Signature Carving (Skipped in QUICK mode)")

        if progress_callback:
            progress_callback(75, 'Structure Validation & Fragment Analysis', f'Analyzing fragment continuity and validating headers ({len(all_candidates)} artifacts)...', len(all_candidates), 0)

        # Step 6: Fragment Reconstruction & Structure Analysis (For MAXIMUM mode or options)
        methods_attempted.append("Fragment Reconstruction & Structure Analysis")
        if recovery_mode == 'MAXIMUM' or options.get('fragmentation'):
            for item in all_candidates:
                candidate_data = StreamingImageReader.read_exact_bytes(image_path, item.get('byte_offset', 0), min(item.get('size_bytes', 1024), 1024*1024))
                frag_info = FragmentEngine.analyze_fragmentation(
                    candidate_data=candidate_data,
                    ext=item.get('detected_type', '').lower(),
                    val_status=item.get('validation_status', 'UNKNOWN'),
                    confidence=item.get('confidence_score', 50)
                )
                item['fragment_count'] = frag_info['fragment_count']
                item['fragments_missing'] = frag_info['fragments_missing']
                item['reconstruction_status'] = frag_info['reconstruction_status']
                item['validation_details'] = f"{item.get('validation_details', '')} | {frag_info['details']}".strip(' |')
            methods_completed.append("Fragment Reconstruction & Structure Analysis")
        else:
            methods_skipped.append("Fragment Reconstruction (Skipped by selected mode/options)")

        if progress_callback:
            progress_callback(85, 'Artifact Fusion & Deduplication', 'Fusing recovered metadata with raw carved files...', len(all_candidates), 0)

        # Step 7: Artifact Fusion & Deduplication
        methods_attempted.append("Artifact Fusion & Deduplication")
        fused_candidates, fusion_summary = ArtifactFusion.fuse_artifacts(
            all_candidates,
            deduplicate=options.get('deduplicate', True)
        )
        methods_completed.append("Artifact Fusion & Deduplication")

        if progress_callback:
            valid_so_far = sum(1 for a in fused_candidates if a.get('validation_status') == 'VALID')
            progress_callback(92, 'Analytical Confidence Scoring', 'Computing forensic confidence scores and SHA-256 digests...', len(fused_candidates), valid_so_far)

        # Step 8: Analytical Confidence Scoring
        for item in fused_candidates:
            score, label = ConfidenceCalculator.calculate_confidence(
                val_status=item.get('validation_status', 'UNKNOWN'),
                val_confidence=item.get('confidence_score', 50),
                recovery_source=item.get('recovery_source', 'Carving'),
                has_original_metadata=bool(item.get('original_filename')),
                fragment_status=item.get('reconstruction_status', 'SUCCESS')
            )
            item['confidence_score'] = score

        if progress_callback:
            valid_cnt = sum(1 for a in fused_candidates if a.get('validation_status') == 'VALID')
            progress_callback(96, 'Verifying Evidence Integrity', 'Verifying post-operation evidence hash and sealing chain of custody...', len(fused_candidates), valid_cnt)

        # Step 9: Post-operation Evidence Hash Verification (Read-Only Check)
        evidence_hash_after = StreamingImageReader.calculate_sha256(image_path)
        if evidence_hash_before != evidence_hash_after:
            raise RuntimeError("CRITICAL FORENSIC WARNING: Source evidence hash changed during recovery! Read-only safety violated.")

        scanned_bytes = os.path.getsize(image_path)

        summary = {
            'evidence_sha256': evidence_hash_before,
            'scanned_bytes': scanned_bytes,
            'total_candidates': fusion_summary['total_candidates'],
            'unique_artifacts': fusion_summary['unique_artifacts'],
            'duplicates_merged': fusion_summary['duplicates_merged'],
            'valid_count': sum(1 for a in fused_candidates if a.get('validation_status') == 'VALID'),
            'high_confidence_count': sum(1 for a in fused_candidates if a.get('confidence_score', 0) >= 75),
            'recovery_mode': recovery_mode,
            'partition_scheme': partitions[0]['scheme'] if partitions else 'Direct Image',
            'filesystem': fs_info['filesystem'],
            'filesystem_confidence': fs_info['confidence'],
            'methods_attempted': methods_attempted,
            'methods_completed': methods_completed,
            'methods_skipped': methods_skipped
        }

        return fused_candidates, summary
