from django.shortcuts import render
from apps.verification.models import VerificationResult

def verification_index(request):
    results = VerificationResult.objects.order_by('-timestamp')
    return render(request, 'verification/index.html', {'results': results})
