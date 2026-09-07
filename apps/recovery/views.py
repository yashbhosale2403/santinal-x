import os
import hashlib
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from apps.forensic.models import Case, EvidenceSource
from apps.recovery.models import RecoveryOperation, RecoveredFile
from workers.recovery_worker.carver import ForensicCarver
from apps.audit.utils import AuditLogger
from apps.reports.generator import ReportGenerator
from apps.reports.models import Report

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
        exts = request.POST.getlist('extensions')

        evidence = get_object_or_404(EvidenceSource, evidence_id=evidence_id)
        case = Case.objects.filter(case_id=case_id).first() if case_id else evidence.case

        # Create RecoveryOperation
        op = RecoveryOperation.objects.create(
            case=case,
            evidence_source=evidence,
            requested_by=request.user if request.user.is_authenticated else None,
            selected_types=exts,
            status='SCANNING'
        )

        AuditLogger.log_event(
            event_type='CARVING_SCAN_STARTED',
            user=request.user if request.user.is_authenticated else None,
            case=case,
            operation_id=str(op.operation_id),
            details={'evidence': evidence.name, 'types': exts}
        )

        # Output directory for carved artifacts
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        out_dir = os.path.join(base_dir, 'media', 'carved_artifacts', str(op.operation_id))

        # Perform Read-Only Forensic Carving
        try:
            carved_list, summary = ForensicCarver.scan_and_carve(
                image_path=evidence.file_path,
                target_extensions=exts,
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
                    detected_type=item['detected_type'],
                    mime_type=item['mime_type'],
                    size_bytes=item['size_bytes'],
                    sector_offset=item['sector_offset'],
                    confidence_score=item['confidence_score'],
                    carving_method=item['carving_method'],
                    validation_status=item['validation_status'],
                    sha256_hash=item['sha256_hash'],
                    output_path=rel_out_path,
                    classification=item['classification']
                )
                rec_file_objs.append(rf)

            op.status = 'COMPLETED'
            op.total_scanned_bytes = summary['scanned_bytes']
            op.candidates_found = summary['total_candidates']
            op.valid_files_count = summary['valid_count']
            op.operation_hash = summary['evidence_sha256']
            op.save()

            # Generate Forensic Recovery PDF Report
            report_pdf_path = os.path.join(base_dir, 'media', 'reports', f"forensic_report_{op.operation_id}.pdf")
            report_hash = ReportGenerator.generate_forensic_recovery_report({
                'case_number': case.case_number,
                'evidence_name': evidence.name,
                'evidence_hash': summary['evidence_sha256'],
                'total_candidates': summary['total_candidates'],
                'valid_count': summary['valid_count'],
                'recovered_files': [
                    {
                        'filename': rf.filename,
                        'detected_type': rf.detected_type,
                        'size_bytes': rf.size_bytes,
                        'validation_status': rf.validation_status,
                        'confidence_score': rf.confidence_score
                    } for rf in rec_file_objs
                ]
            }, report_pdf_path)

            Report.objects.create(
                report_type=Report.ReportType.FORENSIC_RECOVERY_REPORT,
                title=f"Forensic Carving Report - {case.case_number}",
                case=case,
                generated_by=request.user if request.user.is_authenticated else None,
                file_path=f"/media/reports/forensic_report_{op.operation_id}.pdf",
                report_hash=report_hash,
                format=Report.Format.PDF
            )

            AuditLogger.log_event(
                event_type='CARVING_COMPLETED',
                user=request.user if request.user.is_authenticated else None,
                case=case,
                operation_id=str(op.operation_id),
                details={'candidates': summary['total_candidates'], 'valid': summary['valid_count']}
            )

            messages.success(request, f"Forensic Scan Completed! Carved {summary['total_candidates']} candidates ({summary['valid_count']} valid).")
            return redirect(f"/recovery/results/{op.operation_id}/")

        except Exception as e:
            op.status = 'FAILED'
            op.save()
            messages.error(request, f"Carving failed: {e}")
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

    context = {
        'op': op,
        'recovered_files': recovered_files,
        'high_conf': high_conf,
        'med_conf': med_conf,
        'low_conf': low_conf
    }
    return render(request, 'recovery/results.html', context)
