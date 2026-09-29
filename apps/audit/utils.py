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

        # 2. Store Audit Event
        event = AuditEvent.objects.create(
            user=user if user and user.is_authenticated else None,
            case=case,
            operation_id=operation_id,
            event_type=event_type,
            source_ip=source_ip,
            details=details,
            previous_event_hash=prev_hash,
            event_hash=''
        )

        timestamp_str = event.timestamp.isoformat()
        details_json = json.dumps(details, sort_keys=True)
        user_str = str(user.username) if user and hasattr(user, 'username') else 'SYSTEM'

        # 3. Calculate cryptographic SHA-256 hash chain link
        hash_payload = f"{timestamp_str}:{user_str}:{event_type}:{operation_id}:{details_json}:{prev_hash}"
        event.event_hash = hashlib.sha256(hash_payload.encode('utf-8')).hexdigest()
        event.save(update_fields=['event_hash'])
        return event

    @classmethod
    def verify_audit_integrity(cls) -> dict:
        """
        Recomputes hash chain across all AuditEvents from beginning to end.
        Returns result dict with status 'GREEN' (Integrity Verified) or 'RED' (Tampering Detected).
        Also returns a list of all tampered event IDs with detailed info for UI highlighting.
        """
        events = list(AuditEvent.objects.order_by('timestamp'))
        if not events:
            return {
                'status': 'GREEN',
                'message': 'Audit Log Empty - Integrity Verified',
                'total_events': 0,
                'tampered_event_id': None,
                'tampered_events': [],
            }

        prev_hash = cls.GENESIS_HASH
        tampered_events = []
        first_break_event_id = None
        first_break_index = None

        for idx, event in enumerate(events):
            # 1. Check previous hash chain link (does this event's back-pointer match?)
            chain_broken = False
            if idx > 0 and event.previous_event_hash != prev_hash:
                chain_broken = True

            # 2. Recalculate expected hash to detect direct corruption
            timestamp_str = event.timestamp.isoformat()
            details_json = json.dumps(event.details or {}, sort_keys=True)
            user_str = str(event.user.username) if event.user and hasattr(event.user, 'username') else 'SYSTEM'

            expected_prev = prev_hash
            hash_payload = f"{timestamp_str}:{user_str}:{event.event_type}:{event.operation_id}:{details_json}:{expected_prev}"
            expected_hash = hashlib.sha256(hash_payload.encode('utf-8')).hexdigest()
            hash_corrupted = (event.event_hash != expected_hash)

            if chain_broken or hash_corrupted:
                reason_parts = []
                if hash_corrupted:
                    reason_parts.append("Hash corrupted (stored hash doesn't match recalculated SHA-256)")
                if chain_broken:
                    reason_parts.append("Chain link broken (previous_event_hash mismatch)")

                tampered_events.append({
                    'event_id': str(event.event_id),
                    'index': idx + 1,
                    'event_type': event.event_type,
                    'timestamp': event.timestamp.isoformat(),
                    'reason': '; '.join(reason_parts),
                    'hash_corrupted': hash_corrupted,
                    'chain_broken': chain_broken,
                    'stored_hash': event.event_hash[:20] + '...',
                    'expected_hash': expected_hash[:20] + '...',
                })
                if first_break_event_id is None:
                    first_break_event_id = str(event.event_id)
                    first_break_index = idx + 1

            # Use the STORED hash to continue chain walk (to detect downstream breaks)
            prev_hash = event.event_hash

        if tampered_events:
            if len(tampered_events) == 1:
                msg = f"TAMPERING DETECTED: {tampered_events[0]['reason']} at event #{tampered_events[0]['index']}"
            else:
                msg = f"TAMPERING DETECTED: {len(tampered_events)} compromised events found in the hash chain"
            return {
                'status': 'RED',
                'message': msg,
                'total_events': len(events),
                'tampered_event_id': first_break_event_id,
                'broken_index': first_break_index,
                'tampered_events': tampered_events,
            }

        return {
            'status': 'GREEN',
            'message': 'Audit Log Integrity Verified (Hash Chain Intact)',
            'total_events': len(events),
            'latest_hash': prev_hash,
            'tampered_events': [],
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

