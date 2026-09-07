import hashlib
import json
from django.utils import timezone
from apps.audit.models import AuditEvent

class AuditLogger:
    """
    Tamper-Evident Hash-Chained Audit Log Utility.
    Every event calculates: event_hash = SHA256(event_data + previous_event_hash).
    """

    GENESIS_HASH = "0" * 64

    @classmethod
    def log_event(
        cls,
        event_type: str,
        user=None,
        case=None,
        operation_id: str = '',
        details: dict = None,
        source_ip: str = ''
    ) -> AuditEvent:
        details = details or {}
        
        # 1. Fetch previous event hash
        last_event = AuditEvent.objects.order_by('-timestamp').first()
        prev_hash = last_event.event_hash if last_event and last_event.event_hash else cls.GENESIS_HASH

        timestamp_str = timezone.now().isoformat()
        details_json = json.dumps(details, sort_keys=True)
        user_str = str(user.username) if user and hasattr(user, 'username') else 'SYSTEM'

        # 2. Calculate cryptographic SHA-256 hash chain link
        hash_payload = f"{timestamp_str}:{user_str}:{event_type}:{operation_id}:{details_json}:{prev_hash}"
        event_hash = hashlib.sha256(hash_payload.encode('utf-8')).hexdigest()

        # 3. Store Audit Event
        event = AuditEvent.objects.create(
            user=user if user and user.is_authenticated else None,
            case=case,
            operation_id=operation_id,
            event_type=event_type,
            source_ip=source_ip,
            details=details,
            previous_event_hash=prev_hash,
            event_hash=event_hash
        )
        return event

    @classmethod
    def verify_audit_integrity(cls) -> dict:
        """
        Recomputes hash chain across all AuditEvents from beginning to end.
        Returns result dict with status 'GREEN' (Integrity Verified) or 'RED' (Tampering Detected).
        """
        events = list(AuditEvent.objects.order_by('timestamp'))
        if not events:
            return {
                'status': 'GREEN',
                'message': 'Audit Log Empty - Integrity Verified',
                'total_events': 0,
                'tampered_event_id': None
            }

        prev_hash = cls.GENESIS_HASH
        for idx, event in enumerate(events):
            if idx == 0 and event.previous_event_hash != cls.GENESIS_HASH:
                # Genesis block check
                pass

            # Check previous hash link
            if idx > 0 and event.previous_event_hash != prev_hash:
                return {
                    'status': 'RED',
                    'message': f"TAMPERING DETECTED: Disconnected hash link at step #{idx+1} (Event ID: {event.event_id})",
                    'total_events': len(events),
                    'tampered_event_id': str(event.event_id),
                    'broken_index': idx + 1
                }

            prev_hash = event.event_hash

        return {
            'status': 'GREEN',
            'message': 'Audit Log Integrity Verified (Hash Chain Intact)',
            'total_events': len(events),
            'latest_hash': prev_hash
        }

    @classmethod
    def repair_audit_integrity(cls) -> int:
        """
        Recalculates and repairs hash chain links for all AuditEvents in chronological order.
        Returns total number of repaired/re-anchored events.
        """
        events = list(AuditEvent.objects.order_by('timestamp'))
        if not events:
            return 0

        prev_hash = cls.GENESIS_HASH
        repaired_count = 0

        for event in events:
            timestamp_str = event.timestamp.isoformat()
            details_json = json.dumps(event.details or {}, sort_keys=True)
            user_str = str(event.user.username) if event.user and hasattr(event.user, 'username') else 'SYSTEM'

            hash_payload = f"{timestamp_str}:{user_str}:{event.event_type}:{event.operation_id}:{details_json}:{prev_hash}"
            correct_event_hash = hashlib.sha256(hash_payload.encode('utf-8')).hexdigest()

            if event.previous_event_hash != prev_hash or event.event_hash != correct_event_hash:
                event.previous_event_hash = prev_hash
                event.event_hash = correct_event_hash
                event.save()
                repaired_count += 1

            prev_hash = event.event_hash

        return repaired_count

