import os
import threading
from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse
from django.contrib import messages
from apps.devices.models import StorageDevice
from apps.sanitization.models import SanitizationOperation
from workers.sanitization_worker.policy import SanitizationPolicyEngine
from workers.sanitization_worker.sanitizer import DriveSanitizer
from workers.device_worker.detector import DeviceDetector
from apps.audit.utils import AuditLogger

def sanitization_wizard(request):
    # Rescan or auto-detect if no devices exist
    if request.GET.get('rescan') == '1' or StorageDevice.objects.count() == 0:
        detected = DeviceDetector.detect_all_devices()
        for d in detected:
            StorageDevice.objects.update_or_create(device_id=d['device_id'], defaults=d)
        if request.GET.get('rescan') == '1':
            messages.success(request, f"Device Discovery Engine synchronized: {len(detected)} storage device(s) active.")
            return redirect('/sanitization/')

    selected_device_id = request.GET.get('device_id')
    active_op_id = request.GET.get('active_op_id')
    selected_device = None
    policy = None
    active_op = None

    devices = StorageDevice.objects.all()

    if selected_device_id:
        selected_device = StorageDevice.objects.filter(device_id=selected_device_id).first()

    # If no device was explicitly chosen or if device_id was empty, default to the first available device
    if not selected_device and devices.exists():
        selected_device = devices.first()

    if selected_device:
        policy = SanitizationPolicyEngine.evaluate_policy(
            media_type=selected_device.media_type,
            interface_type=selected_device.interface_type,
            capabilities=selected_device.detected_capabilities or {}
        )
        # Page refresh recovery check: look for active running operation on this device
        active_op = SanitizationOperation.objects.filter(
            device=selected_device,
            status__in=['PENDING', 'INITIALIZING', 'DETECTING_DEVICE', 'CHECKING_CAPABILITIES', 'PREPARING', 'SANITIZING', 'VERIFYING']
        ).order_by('-started_at').first()

    if active_op_id and not active_op:
        active_op = SanitizationOperation.objects.filter(operation_id=active_op_id).first()

    if request.method == 'POST':
        device_id = request.POST.get('device_id')
        method = request.POST.get('method', 'NIST_CLEAR')
        execution_mode = request.POST.get('execution_mode', 'REAL_MODE')
        confirmation_code = request.POST.get('confirmation_code', '').strip()
        ack_checkbox = request.POST.get('ack_checkbox') == 'on'

        device = get_object_or_404(StorageDevice, device_id=device_id)

        # 1. Check for Duplicate Submission on active operation
        existing_active = SanitizationOperation.objects.filter(
            device=device,
            status__in=['PENDING', 'INITIALIZING', 'DETECTING_DEVICE', 'CHECKING_CAPABILITIES', 'PREPARING', 'SANITIZING', 'VERIFYING']
        ).first()

        if existing_active:
            err_msg = f"Operation already in progress for device {device.name} (ID: {existing_active.operation_id})."
            if request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.POST.get('ajax') == '1':
                return JsonResponse({'status': 'ERROR', 'error_message': err_msg}, status=400)
            messages.error(request, err_msg)
            return redirect(f"/sanitization/?device_id={device.device_id}&active_op_id={existing_active.operation_id}")

        # 2. Double Safety Confirmation Check
        expected_code = f"ERASE {device.device_id}"
        if not ack_checkbox or confirmation_code != expected_code:
            err_msg = f"Safety Confirmation Failed: You must check the acknowledgment box and type exact confirmation code '{expected_code}'."
            if request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.POST.get('ajax') == '1':
                return JsonResponse({'status': 'ERROR', 'error_message': err_msg}, status=400)
            messages.error(request, err_msg)
            return redirect(f"/sanitization/?device_id={device.device_id}")

        # 3. Create SanitizationOperation Record in INITIALIZING state
        op = SanitizationOperation.objects.create(
            device=device,
            method=method,
            requested_by=request.user if request.user.is_authenticated else None,
            execution_mode=execution_mode,
            status='INITIALIZING',
            progress=0,
            current_stage='INITIALIZING',
            status_message='Initializing background sanitization worker...',
            assurance_level='PURGE' if method in ['CRYPTOGRAPHIC_ERASE', 'NIST_PURGE', 'DOD_3_PASS'] else 'CLEAR'
        )

        # 4. Pre-Operation Audit Event
        AuditLogger.log_event(
            event_type='SANITIZATION_REQUESTED',
            user=request.user if request.user.is_authenticated else None,
            operation_id=str(op.operation_id),
            details={'device': device.name, 'method': method, 'mode': execution_mode, 'mount': device.mount_point}
        )

        # 5. Launch Real Asynchronous Background Worker Thread
        thread = threading.Thread(
            target=DriveSanitizer.run_background_sanitization,
            args=(str(op.operation_id),),
            daemon=True
        )
        thread.start()

        if request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.POST.get('ajax') == '1':
            return JsonResponse({'status': 'SUCCESS', 'operation_id': str(op.operation_id)})

        return redirect(f"/sanitization/?device_id={device.device_id}&active_op_id={op.operation_id}")

    devices = StorageDevice.objects.all()
    recent_ops = SanitizationOperation.objects.order_by('-started_at')[:5]
    
    # Dynamically build method choices
    raw_choices = SanitizationOperation.Method.choices
    method_choices = []
    if policy:
        rec_val = policy.get('recommended_method')
        rec_name = policy.get('method_name')
        for val, default_label in raw_choices:
            if val == rec_val:
                method_choices.append((val, rec_name))
            else:
                method_choices.append((val, default_label))
    else:
        method_choices = list(raw_choices)

    context = {
        'devices': devices,
        'selected_device': selected_device,
        'policy': policy,
        'active_op': active_op,
        'recent_ops': recent_ops,
        'method_choices': method_choices
    }
    return render(request, 'sanitization/index.html', context)

def sanitization_status_api(request, operation_id):
    """
    JSON API endpoint for polling real backend progress & stage updates.
    """
    op = get_object_or_404(SanitizationOperation, operation_id=operation_id)
    return JsonResponse({
        'operation_id': str(op.operation_id),
        'status': op.status,
        'progress': op.progress,
        'current_stage': op.current_stage,
        'status_message': op.status_message,
        'bytes_processed': op.bytes_processed,
        'total_bytes': op.total_bytes,
        'verification_status': op.verification_status,
        'error_message': op.error_message,
        'report_path': op.report_path,
        'is_completed': op.status == 'COMPLETED',
        'is_failed': op.status == 'FAILED',
        'is_cancelled': op.status == 'CANCELLED',
    })

def sanitization_cancel_api(request, operation_id):
    """
    POST API endpoint to request cancellation of an active operation.
    """
    if request.method == 'POST':
        op = get_object_or_404(SanitizationOperation, operation_id=operation_id)
        if op.status in ['PENDING', 'INITIALIZING', 'DETECTING_DEVICE', 'CHECKING_CAPABILITIES', 'PREPARING', 'SANITIZING', 'VERIFYING']:
            op.status = 'CANCELLED'
            op.status_message = 'Cancellation requested by investigator'
            op.save(update_fields=['status', 'status_message'])
            return JsonResponse({'status': 'SUCCESS', 'message': 'Cancellation requested.'})
        return JsonResponse({'status': 'NOTICE', 'message': f'Operation already in {op.status} state.'})
    return JsonResponse({'status': 'ERROR', 'error_message': 'POST method required'}, status=405)

def sanitization_result(request, operation_id):
    op = get_object_or_404(SanitizationOperation, operation_id=operation_id)
    return render(request, 'sanitization/result.html', {'op': op})
