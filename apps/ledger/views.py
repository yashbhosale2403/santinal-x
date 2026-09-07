from django.shortcuts import render
from apps.ledger.models import LedgerEntry

def ledger_view(request):
    entries = LedgerEntry.objects.order_by('-timestamp')
    return render(request, 'ledger/index.html', {'entries': entries})
