from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from apps.devices.models import StorageDevice
from apps.sanitization.models import SanitizationOperation
from apps.file_erasure.models import FileErasureOperation
from apps.recovery.models import RecoveryOperation, RecoveredFile
from apps.forensic.models import Case, EvidenceSource
from apps.audit.models import AuditEvent
from apps.audit.utils import AuditLogger
from apps.ledger.models import LedgerEntry
from apps.reports.models import Report
from workers.device_worker.detector import DeviceDetector

def landing_view(request):
    return render(request, 'landing.html')

def dashboard_index(request):
    # Perform device scan if DB has no devices yet
    if not StorageDevice.objects.exists():
        detected = DeviceDetector.detect_all_devices()
        for d in detected:
            StorageDevice.objects.update_or_create(
                device_id=d['device_id'],
                defaults=d
            )

    devices_count = StorageDevice.objects.count()
    sanitization_count = SanitizationOperation.objects.count()
    recovery_ops_count = RecoveryOperation.objects.count()
    recovered_files_count = RecoveredFile.objects.count()
    open_cases_count = Case.objects.filter(status__in=['OPEN', 'ACTIVE']).count()
    
    # Audit Integrity Status
    integrity_result = AuditLogger.verify_audit_integrity()
    
    recent_audits = AuditEvent.objects.order_by('-timestamp')[:6]
    recent_sanitizations = SanitizationOperation.objects.order_by('-started_at')[:5]
    recent_recoveries = RecoveredFile.objects.order_by('-created_at')[:5]
    ledger_count = LedgerEntry.objects.count()

    context = {
        'devices_count': devices_count,
        'sanitization_count': sanitization_count,
        'recovery_ops_count': recovery_ops_count,
        'recovered_files_count': recovered_files_count,
        'open_cases_count': open_cases_count,
        'integrity_result': integrity_result,
        'recent_audits': recent_audits,
        'recent_sanitizations': recent_sanitizations,
        'recent_recoveries': recent_recoveries,
        'ledger_count': ledger_count,
    }
    return render(request, 'dashboard/index.html', context)

def integrity_view(request):
    integrity_result = AuditLogger.verify_audit_integrity()
    evidence_count = EvidenceSource.objects.count()
    audit_count = AuditEvent.objects.count()
    reports_count = Report.objects.count()
    ledger_count = LedgerEntry.objects.count()

    context = {
        'integrity_result': integrity_result,
        'evidence_count': evidence_count,
        'audit_count': audit_count,
        'reports_count': reports_count,
        'ledger_count': ledger_count
    }
    return render(request, 'integrity/index.html', context)

def technology_view(request):
    context = {
        'total_devices': StorageDevice.objects.count(),
        'supported_formats': ['JPEG', 'PNG', 'PDF', 'DOCX', 'ZIP', 'MP3', 'MP4', 'WAV', 'TXT'],
        'nist_reference': 'NIST SP 800-88 Rev. 2',
    }
    return render(request, 'technology/index.html', context)

def documentation_view(request):
    import os
    doc_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'docs', 'sentinelx-technical-documentation.md')
    
    doc_content = ""
    error_message = None
    
    if os.path.exists(doc_path):
        try:
            with open(doc_path, 'r', encoding='utf-8') as f:
                doc_content = f.read()
        except Exception as e:
            error_message = f"Failed to load documentation file: {str(e)}"
    else:
        error_message = f"Documentation file not found at {doc_path}"
        
    context = {
        'doc_content': doc_content,
        'error_message': error_message,
        'metadata': {
            'document_type': 'Technical Documentation',
            'project': 'SIH26149',
            'platform': 'NTRO',
            'theme': 'Blockchain & Cybersecurity',
            'version': 'SENTINEL-X v1.0',
            'reference': 'NIST SP 800-88 Rev. 2',
        }
    }
    return render(request, 'documentation/index.html', context)

from django.http import JsonResponse

def technology_api(request):
    data = {
        'status': 'success',
        'platform': 'SENTINEL-X',
        'architecture_version': '1.0',
        'nist_standard': 'NIST SP 800-88 Rev. 2',
        'supported_devices': ['HDD', 'SATA SSD', 'NVMe SSD', 'USB Flash', 'SD / microSD', 'Encrypted Storage'],
        'supported_recovery_formats': ['JPEG', 'PNG', 'PDF', 'DOCX', 'ZIP', 'MP3', 'MP4', 'WAV', 'TXT'],
        'hashing_algorithm': 'SHA-256',
        'ledger_integration': True,
    }
    return JsonResponse(data)

def documentation_api(request):
    import os
    doc_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'docs', 'sentinelx-technical-documentation.md')
    if os.path.exists(doc_path):
        with open(doc_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return JsonResponse({'status': 'success', 'content': content})
    return JsonResponse({'status': 'error', 'message': 'Documentation file not found'}, status=404)

