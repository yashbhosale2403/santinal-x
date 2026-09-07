import uuid
from django.db import models

class LedgerEntry(models.Model):
    class LedgerType(models.TextChoices):
        LOCAL_IMMUTABLE = 'LOCAL_IMMUTABLE', 'Local Immutable Hash Ledger'
        ETHEREUM_SIMULATED = 'ETHEREUM_SIMULATED', 'Ethereum Smart Contract Adapter'
        SOLANA_SIMULATED = 'SOLANA_SIMULATED', 'Solana Forensic Program Adapter'
        HYPERLEDGER_SIMULATED = 'HYPERLEDGER_SIMULATED', 'Hyperledger Fabric Adapter'

    class Status(models.TextChoices):
        VERIFIED = 'VERIFIED', 'Verified Immutable'
        TAMPERED = 'TAMPERED', 'Tamper Detected'
        PENDING = 'PENDING', 'Pending Confirmation'

    entry_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    event_hash = models.CharField(max_length=64)
    timestamp = models.DateTimeField(auto_now_add=True)
    operation_id = models.CharField(max_length=100)
    ledger_type = models.CharField(max_length=30, choices=LedgerType.choices, default=LedgerType.LOCAL_IMMUTABLE)
    transaction_id = models.CharField(max_length=100)
    report_hash = models.CharField(max_length=64, blank=True)
    verification_status = models.CharField(max_length=20, choices=Status.choices, default=Status.VERIFIED)

    def __str__(self):
        return f"LedgerEntry {self.transaction_id[:16]} ({self.ledger_type}) - Status: {self.verification_status}"
