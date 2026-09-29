from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from apps.devices.models import StorageDevice
from workers.device_worker.detector import DeviceDetector
from workers.sanitization_worker.policy import SanitizationPolicyEngine
from apps.audit.utils import AuditLogger

def device_list(request):
    # Refresh devices on scan button click
    if request.GET.get('rescan') == '1':
        detected = DeviceDetector.detect_all_devices()
        current_ids = set()
        for d in detected:
            current_ids.add(d['device_id'])
            StorageDevice.objects.update_or_create(
                device_id=d['device_id'],
                defaults=d
            )
        # Prune stale or duplicate devices that are no longer detected
        StorageDevice.objects.exclude(device_id__in=current_ids).delete()
        AuditLogger.log_event('DEVICE_DISCOVERY_SCAN', user=request.user if request.user.is_authenticated else None, details={'count': len(detected)})
        messages.success(request, f"Device Discovery Engine synchronized: {len(detected)} storage device(s) active.")
        return redirect('/devices/')

    devices = StorageDevice.objects.all()
    return render(request, 'devices/index.html', {'devices': devices})

def device_detail(request, device_id):
    device = get_object_or_404(StorageDevice, device_id=device_id)
    
    # Evaluate NIST policy for this device
    policy = SanitizationPolicyEngine.evaluate_policy(
        media_type=device.media_type,
        interface_type=device.interface_type,
        capabilities=device.detected_capabilities or {}
    )

    context = {
        'device': device,
        'policy': policy
    }
    return render(request, 'devices/detail.html', context)
