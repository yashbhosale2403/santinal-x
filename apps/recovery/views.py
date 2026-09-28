import os
import hashlib
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from apps.forensic.models import Case, EvidenceSource
from apps.recovery.models import RecoveryOperation, RecoveredFile
from workers.recovery_worker.engine import RecoveryEngine
from apps.audit.utils import AuditLogger
from apps.reports.generator import ReportGenerator
from apps.reports.models import Report
from apps.ledger.adapters import LocalImmutableLedger
from apps.ledger.models import LedgerEntry

def recovery_scanner(request):
    cases = Case.objects.all()
    evidence_sources = EvidenceSource.objects.all()

    selected_evidence_id = request.GET.get('evidence_id')
    selected_evidence = None
    if selected_evidence_id:
        selected_evidence = EvidenceSource.objects.filter(evidence_id=selected_evidence_id).first()

    if request.method == 'POST':
        evidence_id = request.POST.get('evidence_id')
        case_id = request.POST.get('case_id')
        recovery_mode = request.POST.get('recovery_mode', 'DEEP')
        
        # Extensions handling: support category checkboxes & individual extensions list
        category_map = {
            'cat_images': ['jpg', 'jpeg', 'png', 'gif', 'bmp'],
            'cat_docs': ['pdf', 'docx'],
            'cat_archives': ['zip'],
            'cat_audio': ['mp3', 'wav'],
            'cat_video': ['mp4'],
            'cat_text': ['txt']
        }
        
        exts = set(request.POST.getlist('extensions'))
        for cat_key, cat_ext_list in category_map.items():
            if request.POST.get(cat_key):
                exts.update(cat_ext_list)

        if not exts:
            # Default extensions fallback
            exts = set(['jpg', 'png', 'pdf', 'docx', 'zip', 'txt'])

        ext_list = sorted(list(exts))

        options = {
            'validation': request.POST.get('opt_validation', 'on') == 'on',
            'fragmentation': request.POST.get('opt_fragmentation', 'on') == 'on',
            'deduplicate': request.POST.get('opt_dedup', 'on') == 'on'
        }

        evidence = get_object_or_404(EvidenceSource, evidence_id=evidence_id)
        case = Case.objects.filter(case_id=case_id).first() if case_id else evidence.case

        # Create RecoveryOperation
        op = RecoveryOperation.objects.create(
            case=case,
            evidence_source=evidence,
            requested_by=request.user if request.user.is_authenticated else None,
            recovery_mode=recovery_mode,
            selected_types=ext_list,
            status='SCANNING',
            current_phase='Initializing Read-Only Forensic Recovery'
        )

        AuditLogger.log_event(
            event_type='RECOVERY_STARTED',
            user=request.user if request.user.is_authenticated else None,
            case=case,
            operation_id=str(op.operation_id),
            details={'evidence': evidence.name, 'mode': recovery_mode, 'types': ext_list}
        )

        # Output directory for recovered artifacts
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        out_dir = os.path.join(base_dir, 'media', 'carved_artifacts', str(op.operation_id))

        # Perform Read-Only Multi-Method Forensic Recovery
        try:
            carved_list, summary = RecoveryEngine.run(
                image_path=evidence.file_path,
                recovery_mode=recovery_mode,
                target_extensions=ext_list,
                options=options,
                output_dir=out_dir
            )

            # Store RecoveredFile objects in DB
            rec_file_objs = []
            for item in carved_list:
                rel_out_path = f"/media/carved_artifacts/{op.operation_id}/{item['filename']}"
                rf = RecoveredFile.objects.create(
                    operation=op,
                    case=case,
                    evidence_source=evidence,
                    filename=item['filename'],
                    original_filename=item.get('original_filename', ''),
                    original_path=item.get('original_path', ''),
                    detected_type=item['detected_type'],
                    mime_type=item.get('mime_type', 'application/octet-stream'),
                    size_bytes=item.get('size_bytes', 0),
                    byte_offset=item.get('byte_offset', 0),
                    sector_number=item.get('sector_number', 0),
                    sector_offset=item.get('byte_offset', 0), # Preserved backward compatibility
                    confidence_score=item.get('confidence_score', 50),
                    carving_method=item.get('carving_method', 'HEADER_FOOTER_MATCH'),
                    recovery_source=item.get('recovery_source', 'Signature Carving'),
                    deleted_status=item.get('deleted_status', True),
                    validation_status=item.get('validation_status', 'UNKNOWN'),
                    validation_details=item.get('validation_details', ''),
                    fragment_count=item.get('fragment_count', 1),
                    fragments_missing=item.get('fragments_missing', 0),
                    reconstruction_status=item.get('reconstruction_status', 'SUCCESS'),
                    sha256_hash=item.get('sha256_hash', ''),
                    output_path=rel_out_path,
                    classification=item.get('classification', 'OTHER')
                )
                rec_file_objs.append(rf)

            op.status = 'COMPLETED'
            op.current_phase = 'Completed'
            op.progress_percent = 100
            op.total_scanned_bytes = summary['scanned_bytes']
            op.candidates_found = summary['total_candidates']
            op.valid_files_count = summary['valid_count']
            op.operation_hash = summary['evidence_sha256']
            op.methods_attempted = summary.get('methods_attempted', [])
            op.methods_completed = summary.get('methods_completed', [])
            op.methods_skipped = summary.get('methods_skipped', [])
            op.save()

            # Generate Forensic Recovery PDF Report
            report_pdf_path = os.path.join(base_dir, 'media', 'reports', f"forensic_report_{op.operation_id}.pdf")
            report_hash = ReportGenerator.generate_forensic_recovery_report({
                'case_number': case.case_number,
                'evidence_name': evidence.name,
                'evidence_hash': summary['evidence_sha256'],
                'recovery_mode': recovery_mode,
                'total_candidates': summary['total_candidates'],
                'valid_count': summary['valid_count'],
                'methods_attempted': summary.get('methods_attempted', []),
                'methods_completed': summary.get('methods_completed', []),
                'methods_skipped': summary.get('methods_skipped', []),
                'recovered_files': [
                    {
                        'filename': rf.display_name(),
                        'detected_type': rf.detected_type,
                        'size_bytes': rf.size_bytes,
                        'recovery_source': rf.recovery_source,
                        'validation_status': rf.validation_status,
                        'confidence_score': rf.confidence_score,
                        'sha256_hash': rf.sha256_hash
                    } for rf in rec_file_objs
                ]
            }, report_pdf_path)

            report_obj = Report.objects.create(
                report_type=Report.ReportType.FORENSIC_RECOVERY_REPORT,
                title=f"Forensic Recovery Report - {case.case_number}",
                case=case,
                generated_by=request.user if request.user.is_authenticated else None,
                file_path=f"/media/reports/forensic_report_{op.operation_id}.pdf",
                report_hash=report_hash,
                format=Report.Format.PDF
            )

            # Audit Completion Event
            audit_event = AuditLogger.log_event(
                event_type='RECOVERY_COMPLETED',
                user=request.user if request.user.is_authenticated else None,
                case=case,
                operation_id=str(op.operation_id),
                details={
                    'candidates': summary['total_candidates'],
                    'valid': summary['valid_count'],
                    'report_hash': report_hash
                }
            )

            # Record Immutable Ledger Entry
            ledger_adapter = LocalImmutableLedger()
            ledger_res = ledger_adapter.record_hash(
                event_hash=audit_event.event_hash if audit_event else op.operation_hash,
                operation_id=str(op.operation_id),
                report_hash=report_hash
            )

            messages.success(
                request,
                f"Forensic Recovery Completed! Found {summary['total_candidates']} candidates ({summary['valid_count']} valid). "
                f"Immutable Ledger Tx ID: {ledger_res.get('transaction_id', '')[:16]}..."
            )
            return redirect(f"/recovery/results/{op.operation_id}/")

        except Exception as e:
            op.status = 'FAILED'
            op.failure_details = str(e)
            op.save()
            AuditLogger.log_event(
                event_type='RECOVERY_FAILED',
                user=request.user if request.user.is_authenticated else None,
                case=case,
                operation_id=str(op.operation_id),
                details={'error': str(e)}
            )
            messages.error(request, f"Forensic recovery failed: {e}")
            return redirect('/recovery/')

    recent_recoveries = RecoveryOperation.objects.order_by('-started_at')[:5]

    context = {
        'cases': cases,
        'evidence_sources': evidence_sources,
        'selected_evidence': selected_evidence,
        'recent_recoveries': recent_recoveries
    }
    return render(request, 'recovery/index.html', context)

def recovery_results(request, operation_id):
    op = get_object_or_404(RecoveryOperation, operation_id=operation_id)
    recovered_files = op.recovered_files.order_by('-confidence_score')

    high_conf = recovered_files.filter(confidence_score__gte=75).count()
    med_conf = recovered_files.filter(confidence_score__range=(50, 74)).count()
    low_conf = recovered_files.filter(confidence_score__lt=50).count()

    # Retrieve associated ledger entry and report
    ledger_entry = LedgerEntry.objects.filter(operation_id=str(op.operation_id)).first()
    report = Report.objects.filter(file_path__contains=str(op.operation_id)).first()

    context = {
        'op': op,
        'recovered_files': recovered_files,
        'high_conf': high_conf,
        'med_conf': med_conf,
        'low_conf': low_conf,
        'ledger_entry': ledger_entry,
        'report': report
    }
    return render(request, 'recovery/results.html', context)

