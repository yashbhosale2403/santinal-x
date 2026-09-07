import os
import hashlib
from django.shortcuts import render, redirect
from django.contrib import messages
from apps.forensic.models import Case, EvidenceSource, ChainOfCustodyEvent
from apps.audit.utils import AuditLogger

def cases_index(request):
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'create_case':
            case_number = request.POST.get('case_number', '').strip()
            title = request.POST.get('title', '').strip()
            description = request.POST.get('description', '').strip()
            
            case = Case.objects.create(
                case_number=case_number,
                title=title,
                description=description,
                investigator=request.user if request.user.is_authenticated else None
            )

            AuditLogger.log_event('CASE_CREATED', user=request.user if request.user.is_authenticated else None, case=case, details={'number': case_number, 'title': title})
            messages.success(request, f"Case {case_number} created successfully.")
            return redirect('/cases/')

        elif action == 'add_evidence':
            case_id = request.POST.get('case_id')
            evidence_id = request.POST.get('evidence_id', '').strip()
            name = request.POST.get('name', '').strip()
            file_path = request.POST.get('file_path', '').strip()
            
            case = Case.objects.get(case_id=case_id)
            
            # Compute SHA-256 hash if file exists
            sha256 = ""
            size = 0
            if os.path.exists(file_path):
                size = os.path.getsize(file_path)
                h = hashlib.sha256()
                with open(file_path, 'rb') as f:
                    while chunk := f.read(65536):
                        h.update(chunk)
                sha256 = h.hexdigest()
            else:
                sha256 = hashlib.sha256(f"{evidence_id}:{file_path}".encode('utf-8')).hexdigest()
                size = 100 * 1024 * 1024

            ev = EvidenceSource.objects.create(
                evidence_id=evidence_id,
                case=case,
                name=name,
                file_path=file_path,
                size_bytes=size,
                sha256_hash=sha256,
                acquired_by=request.user if request.user.is_authenticated else None
            )

            # Record Chain of Custody Event
            ChainOfCustodyEvent.objects.create(
                case=case,
                evidence_source=ev,
                actor_name=request.user.username if request.user.is_authenticated else 'Investigator',
                action='EVIDENCE_ACQUIRED',
                object_description=f"Evidence {evidence_id} ({name})",
                recorded_hash=sha256,
                notes='Initial evidence acquisition & bit-stream SHA-256 hashing.'
            )

            AuditLogger.log_event('EVIDENCE_ACQUIRED', user=request.user if request.user.is_authenticated else None, case=case, details={'evidence_id': evidence_id, 'hash': sha256})
            messages.success(request, f"Evidence Source {evidence_id} added & SHA-256 hashed.")
            return redirect('/cases/')

    cases = Case.objects.order_by('-created_at')
    evidence_sources = EvidenceSource.objects.order_by('-created_at')
    custody_events = ChainOfCustodyEvent.objects.order_by('-timestamp')[:10]

    context = {
        'cases': cases,
        'evidence_sources': evidence_sources,
        'custody_events': custody_events
    }
    return render(request, 'forensic/index.html', context)
