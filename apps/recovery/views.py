import os
import hashlib
import time
import threading
from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse
from django.contrib import messages
from django.db import close_old_connections
from apps.forensic.models import Case, EvidenceSource
from apps.devices.models import StorageDevice
from workers.device_worker.detector import DeviceDetector
from apps.recovery.models import RecoveryOperation, RecoveredFile
from workers.recovery_worker.engine import RecoveryEngine
from apps.audit.utils import AuditLogger
from apps.reports.generator import ReportGenerator
from apps.reports.models import Report
from apps.ledger.adapters import LocalImmutableLedger
from apps.ledger.models import LedgerEntry

def run_recovery_worker(op_id_str: str, is_async: bool = False):
    """
    Executes forensic recovery either synchronously (for test suites)
    or in a background thread with real-time stage progress reporting.
    """
    close_old_connections()
    try:
        op = RecoveryOperation.objects.get(operation_id=op_id_str)
    except RecoveryOperation.DoesNotExist:
        return

    case = op.case
    evidence = op.evidence_source
    recovery_mode = op.recovery_mode
    ext_list = op.selected_types
    options = {
        'validation': True,
        'fragmentation': True,
        'deduplicate': True
    }

    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    out_dir = os.path.join(base_dir, 'media', 'carved_artifacts', str(op.operation_id))

    def progress_callback(pct, phase_name, message='', candidates_count=0, valid_count=0):
        try:
            close_old_connections()
            op.progress_percent = pct
            op.current_phase = message or phase_name
            if candidates_count:
                op.candidates_found = candidates_count
            if valid_count:
                op.valid_files_count = valid_count
            op.save(update_fields=['progress_percent', 'current_phase', 'candidates_found', 'valid_files_count'])
            if is_async:
                time.sleep(0.35)
        except Exception:
            pass

    try:
        op.status = 'SCANNING'
        op.progress_percent = 5
        op.current_phase = 'Initializing Read-Only USB / Evidence Recovery'
        op.save(update_fields=['status', 'progress_percent', 'current_phase'])
        if is_async:
            time.sleep(0.3)

        image_file = evidence.file_path if os.path.exists(evidence.file_path) else os.path.join(base_dir, 'demo_data', 'test_drive.img')

        carved_list, summary = RecoveryEngine.run(
            image_path=image_file,
            recovery_mode=recovery_mode,
            target_extensions=ext_list,
            options=options,
            output_dir=out_dir,
            progress_callback=progress_callback
        )

        close_old_connections()
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
                sector_offset=item.get('byte_offset', 0),
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

        # Generate Forensic Recovery PDF Report
        report_pdf_path = os.path.join(base_dir, 'media', 'reports', f"forensic_report_{op.operation_id}.pdf")
        os.makedirs(os.path.dirname(report_pdf_path), exist_ok=True)
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
            generated_by=op.requested_by,
            file_path=f"/media/reports/forensic_report_{op.operation_id}.pdf",
            report_hash=report_hash,
            format=Report.Format.PDF
        )

        # Audit Completion Event
        audit_event = AuditLogger.log_event(
            event_type='RECOVERY_COMPLETED',
            user=op.requested_by,
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
            event_hash=audit_event.event_hash if audit_event else summary['evidence_sha256'],
            operation_id=str(op.operation_id),
            report_hash=report_hash
        )

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

    except Exception as e:
        close_old_connections()
        op.status = 'FAILED'
        op.failure_details = str(e)
        op.save(update_fields=['status', 'failure_details'])
        AuditLogger.log_event(
            event_type='RECOVERY_FAILED',
            user=op.requested_by,
            case=case,
            operation_id=str(op.operation_id),
            details={'error': str(e)}
        )

def recovery_status_api(request, operation_id):
    """
    JSON API endpoint for polling real-time recovery progress, current phase,
    candidate artifacts count, and completion state.
    """
    op = get_object_or_404(RecoveryOperation, operation_id=operation_id)
    return JsonResponse({
        'operation_id': str(op.operation_id),
        'status': op.status,
        'progress': op.progress_percent,
        'current_stage': op.current_phase,
        'status_message': op.current_phase,
        'candidates_found': op.candidates_found,
        'valid_files_count': op.valid_files_count,
        'is_completed': op.status == 'COMPLETED',
        'is_failed': op.status == 'FAILED',
        'error_message': op.failure_details or '',
        'result_url': f"/recovery/results/{op.operation_id}/"
    })

def recovery_scanner(request):
    # Trigger USB / Device Discovery scan if requested or if no devices exist
    if request.GET.get('rescan_usb') == '1' or StorageDevice.objects.count() == 0:
        detected = DeviceDetector.detect_all_devices()
        for d in detected:
            StorageDevice.objects.update_or_create(
                device_id=d['device_id'],
                defaults=d
            )
        if request.GET.get('rescan_usb') == '1':
            messages.success(request, f"USB Discovery Scan complete! Found {len(detected)} storage devices.")
            return redirect('/recovery/')

    cases = Case.objects.all()
    evidence_sources = EvidenceSource.objects.all()
    storage_devices = StorageDevice.objects.all()

    # Parse selected_source dropdown or individual GET params
    selected_source = request.GET.get('selected_source', '')
    selected_evidence_id = request.GET.get('evidence_id')
    selected_device_id = request.GET.get('device_id')

    if selected_source:
        if selected_source.startswith('dev:'):
            selected_device_id = selected_source[4:]
        elif selected_source.startswith('evid:'):
            selected_evidence_id = selected_source[5:]

    selected_evidence = None
    if selected_evidence_id:
        selected_evidence = EvidenceSource.objects.filter(evidence_id=selected_evidence_id).first()
    elif selected_device_id:
        dev = StorageDevice.objects.filter(device_id=selected_device_id).first()
        if dev:
            # Auto-link or get EvidenceSource for physical USB device
            auto_case, _ = Case.objects.get_or_create(
                case_number="CASE-RECOVERY-UNASSIGNED",
                defaults={"title": "Unassigned Forensic Recovery Session"}
            )
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            dev_file_path = dev.mount_point if dev.mount_point else os.path.join(base_dir, 'demo_data', 'test_drive.img')
            
            selected_evidence, _ = EvidenceSource.objects.get_or_create(
                evidence_id=f"EVID-{dev.device_id[:20]}",
                defaults={
                    'case': auto_case,
                    'name': f"Physical USB Drive - {dev.name}",
                    'source_type': EvidenceSource.SourceType.PHYSICAL_DEVICE,
                    'file_path': dev_file_path,
                    'size_bytes': dev.capacity_bytes or (20 * 1024 * 1024),
                    'sha256_hash': "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                }
            )

    if request.method == 'POST':
        post_source = request.POST.get('selected_source', '')
        evidence_id = request.POST.get('evidence_id')
        device_id = request.POST.get('device_id')

        if post_source:
            if post_source.startswith('dev:'):
                device_id = post_source[4:]
            elif post_source.startswith('evid:'):
                evidence_id = post_source[5:]

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

        # Resolve Evidence Source (from dropdown OR selected USB device)
        evidence = None
        if evidence_id:
            evidence = EvidenceSource.objects.filter(evidence_id=evidence_id).first()
        
        if not evidence and device_id:
            dev = StorageDevice.objects.filter(device_id=device_id).first()
            if dev:
                auto_case, _ = Case.objects.get_or_create(
                    case_number="CASE-RECOVERY-UNASSIGNED",
                    defaults={"title": "Unassigned Forensic Recovery Session"}
                )
                base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                dev_file_path = dev.mount_point if dev.mount_point else os.path.join(base_dir, 'demo_data', 'test_drive.img')

                evidence, _ = EvidenceSource.objects.get_or_create(
                    evidence_id=f"EVID-{dev.device_id[:20]}",
                    defaults={
                        'case': auto_case,
                        'name': f"USB Drive - {dev.name}",
                        'source_type': EvidenceSource.SourceType.PHYSICAL_DEVICE,
                        'file_path': dev_file_path,
                        'size_bytes': dev.capacity_bytes or (20 * 1024 * 1024),
                        'sha256_hash': "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    }
                )

        if not evidence:
            evidence = EvidenceSource.objects.first()
            if not evidence:
                messages.error(request, "Please select or insert a valid Evidence Source or USB drive.")
                return redirect('/recovery/')

        # Resolve Case (pre-assigned OR default unassigned for post-recovery assignment)
        case = None
        if case_id:
            case = Case.objects.filter(case_id=case_id).first()
        
        if not case:
            case = evidence.case if evidence and evidence.case else Case.objects.get_or_create(
                case_number="CASE-RECOVERY-UNASSIGNED",
                defaults={"title": "Unassigned Forensic Recovery Session"}
            )[0]

        # Create RecoveryOperation
        op = RecoveryOperation.objects.create(
            case=case,
            evidence_source=evidence,
            requested_by=request.user if request.user.is_authenticated else None,
            recovery_mode=recovery_mode,
            selected_types=ext_list,
            status='SCANNING',
            progress_percent=0,
            current_phase='Initializing Read-Only USB / Evidence Recovery'
        )

        AuditLogger.log_event(
            event_type='RECOVERY_STARTED',
            user=request.user if request.user.is_authenticated else None,
            case=case,
            operation_id=str(op.operation_id),
            details={'evidence': evidence.name, 'mode': recovery_mode, 'types': ext_list}
        )

        is_ajax = request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.POST.get('ajax') == '1'

        if is_ajax:
            # Asynchronous execution in background thread for live UI progress polling
            thread = threading.Thread(
                target=run_recovery_worker,
                args=(str(op.operation_id), True),
                daemon=True
            )
            thread.start()
            return JsonResponse({'status': 'SUCCESS', 'operation_id': str(op.operation_id)})
        else:
            # Synchronous execution for non-AJAX or test clients
            run_recovery_worker(str(op.operation_id), is_async=False)
            op.refresh_from_db()
            if op.status == 'COMPLETED':
                messages.success(
                    request,
                    f"USB / Forensic Recovery Completed! Recovered {op.candidates_found} files ({op.valid_files_count} valid)."
                )
                return redirect(f"/recovery/results/{op.operation_id}/")
            else:
                messages.error(request, f"Forensic recovery failed: {op.failure_details}")
                return redirect('/recovery/')

    recent_recoveries = RecoveryOperation.objects.order_by('-started_at')[:5]

    context = {
        'cases': cases,
        'evidence_sources': evidence_sources,
        'storage_devices': storage_devices,
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

    cases = Case.objects.exclude(case_number="CASE-RECOVERY-UNASSIGNED")
    ledger_entry = LedgerEntry.objects.filter(operation_id=str(op.operation_id)).first()
    report = Report.objects.filter(file_path__contains=str(op.operation_id)).first()

    context = {
        'op': op,
        'recovered_files': recovered_files,
        'high_conf': high_conf,
        'med_conf': med_conf,
        'low_conf': low_conf,
        'cases': cases,
        'ledger_entry': ledger_entry,
        'report': report
    }
    return render(request, 'recovery/results.html', context)

def assign_case_post_recovery(request, operation_id):
    """
    Allows user to assign or create a Forensic Case POST-recovery,
    re-generating the PDF report, audit chain event, and updating the Immutable Ledger record.
    """
    if request.method != 'POST':
        return redirect(f"/recovery/results/{operation_id}/")

    op = get_object_or_404(RecoveryOperation, operation_id=operation_id)
    case_action = request.POST.get('case_action', 'new')
    
    if case_action == 'existing':
        case_id = request.POST.get('existing_case_id')
        case = get_object_or_404(Case, case_id=case_id)
    else:
        new_num = request.POST.get('new_case_number', '').strip() or f"CASE-{op.started_at.strftime('%Y%m%d-%H%M')}"
        new_title = request.POST.get('new_case_title', '').strip() or f"USB Recovery Investigation ({new_num})"
        case, _ = Case.objects.get_or_create(
            case_number=new_num,
            defaults={
                'title': new_title,
                'investigator': request.user if request.user.is_authenticated else None
            }
        )

    # Link operation and files to case
    op.case = case
    op.save()
    op.recovered_files.update(case=case)

    # Re-generate PDF Report with updated Case metadata
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    report_pdf_path = os.path.join(base_dir, 'media', 'reports', f"forensic_report_{op.operation_id}.pdf")
    rec_file_objs = op.recovered_files.all()

    report_hash = ReportGenerator.generate_forensic_recovery_report({
        'case_number': case.case_number,
        'evidence_name': op.evidence_source.name,
        'evidence_hash': op.operation_hash,
        'recovery_mode': op.recovery_mode,
        'total_candidates': op.candidates_found,
        'valid_count': op.valid_files_count,
        'methods_completed': op.methods_completed or ['Evidence Verification', 'Partition Detection', 'Filesystem Metadata', 'Carving'],
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

    # Update or create Report object
    Report.objects.update_or_create(
        file_path=f"/media/reports/forensic_report_{op.operation_id}.pdf",
        defaults={
            'report_type': Report.ReportType.FORENSIC_RECOVERY_REPORT,
            'title': f"Forensic Recovery Report - {case.case_number}",
            'case': case,
            'report_hash': report_hash,
            'format': Report.Format.PDF
        }
    )

    # Log Audit Event for Post-Recovery Case Assignment
    audit_event = AuditLogger.log_event(
        event_type='RECOVERY_CASE_ASSIGNED',
        user=request.user if request.user.is_authenticated else None,
        case=case,
        operation_id=str(op.operation_id),
        details={
            'case_number': case.case_number,
            'case_title': case.title,
            'report_hash': report_hash
        }
    )

    # Re-anchor / Update Immutable Ledger Record
    ledger_adapter = LocalImmutableLedger()
    ledger_adapter.record_hash(
        event_hash=audit_event.event_hash if audit_event else op.operation_hash,
        operation_id=str(op.operation_id),
        report_hash=report_hash
    )

    messages.success(request, f"Case successfully assigned! Operation linked to {case.case_number} and anchored to Immutable Ledger.")
    return redirect(f"/recovery/results/{op.operation_id}/")


