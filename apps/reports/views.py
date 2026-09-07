from django.shortcuts import render
from apps.reports.models import Report

def reports_list_view(request):
    reports = Report.objects.order_by('-created_at')
    return render(request, 'reports/index.html', {'reports': reports})
