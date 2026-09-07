from django.shortcuts import render, redirect
from django.contrib import messages
from apps.audit.models import AuditEvent
from apps.audit.utils import AuditLogger

def audit_trail_view(request):
    events = AuditEvent.objects.order_by('-timestamp')
    integrity_res = AuditLogger.verify_audit_integrity()
    
    context = {
        'events': events,
        'integrity_res': integrity_res
    }
    return render(request, 'audit/index.html', context)

def verify_integrity(request):
    res = AuditLogger.verify_audit_integrity()
    if res['status'] == 'GREEN':
        messages.success(request, f"Audit Chain Verification: GREEN — Integrity Verified across {res['total_events']} events.")
    else:
        messages.error(request, f"Audit Chain Verification: RED — TAMPERING DETECTED! Broken hash link at event {res.get('tampered_event_id')}.")
    return redirect('/audit/')

def trigger_tamper_demo(request):
    """
    SIH Demonstration helper: Intentionally breaks a hash link in an audit record
    to showcase SENTINEL-X's cryptographic tamper-detection capabilities.
    """
    event = AuditEvent.objects.order_by('timestamp').first()
    if event:
        event.event_hash = "f" * 64 # Corrupt hash
        event.save()
        messages.error(request, "DEMO TRIGGER: Corrupted Audit Event Hash in Database to demonstrate Tamper Detection! Click 'Restore Audit Chain' below to reset.")
    return redirect('/audit/')

def reset_audit_chain(request):
    """
    Restores normal cryptographic integrity by recalculating and re-anchoring
    the hash chain across all audit log events.
    """
    repaired_count = AuditLogger.repair_audit_integrity()
    messages.success(request, f"Audit Chain Restored: Recalculated cryptographic hashes across {repaired_count} event(s). Status returned to GREEN (Verified).")
    return redirect(request.META.get('HTTP_REFERER', '/audit/'))

