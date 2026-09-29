from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

from apps.dashboard.views import dashboard_index, landing_view, integrity_view, technology_view, documentation_view, technology_api, documentation_api
from apps.authentication.views import login_view, logout_view, signup_view
from apps.devices.views import device_list, device_detail
from apps.sanitization.views import sanitization_wizard, sanitization_result, sanitization_status_api, sanitization_cancel_api
from apps.file_erasure.views import file_erasure_view, file_erasure_result
from apps.recovery.views import recovery_scanner, recovery_results, assign_case_post_recovery
from apps.forensic.views import cases_index
from apps.audit.views import audit_trail_view, verify_integrity, trigger_tamper_demo, reset_audit_chain
from apps.ledger.views import ledger_view
from apps.reports.views import reports_list_view
from apps.verification.views import verification_index

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # Auth
    path('auth/login/', login_view, name='login'),
    path('auth/logout/', logout_view, name='logout'),
    path('auth/signup/', signup_view, name='signup'),

    # Landing & Dashboard
    path('', dashboard_index, name='dashboard'),
    path('landing/', landing_view, name='landing'),

    # Devices
    path('devices/', device_list, name='device_list'),
    path('devices/<str:device_id>/', device_detail, name='device_detail'),

    # Sanitization
    path('sanitization/', sanitization_wizard, name='sanitization_wizard'),
    path('sanitization/result/<uuid:operation_id>/', sanitization_result, name='sanitization_result'),
    path('sanitization/api/status/<uuid:operation_id>/', sanitization_status_api, name='sanitization_status_api'),
    path('sanitization/api/cancel/<uuid:operation_id>/', sanitization_cancel_api, name='sanitization_cancel_api'),

    # File Erasure
    path('file-erasure/', file_erasure_view, name='file_erasure'),
    path('file-erasure/result/<uuid:operation_id>/', file_erasure_result, name='file_erasure_result'),

    # Forensic Carving & Recovery
    path('recovery/', recovery_scanner, name='recovery_scanner'),
    path('recovery/results/<uuid:operation_id>/', recovery_results, name='recovery_results'),
    path('recovery/assign-case/<uuid:operation_id>/', assign_case_post_recovery, name='assign_case_post_recovery'),

    # Cases & Evidence
    path('cases/', cases_index, name='cases'),

    # Audit & Tamper Chain
    path('audit/', audit_trail_view, name='audit'),
    path('audit/verify/', verify_integrity, name='verify_integrity'),
    path('audit/tamper-demo/', trigger_tamper_demo, name='trigger_tamper_demo'),
    path('audit/reset/', reset_audit_chain, name='reset_audit_chain'),

    # Integrity Page
    path('integrity/', integrity_view, name='integrity'),

    # Immutable Ledger
    path('ledger/', ledger_view, name='ledger'),

    # Reports
    path('reports/', reports_list_view, name='reports'),

    # Verification Engine
    path('verification/', verification_index, name='verification'),

    # Knowledge: Technology & Technical Documentation
    path('technology/', technology_view, name='technology'),
    path('documentation/', documentation_view, name='documentation'),
    path('api/technology/', technology_api, name='technology_api'),
    path('api/documentation/', documentation_api, name='documentation_api'),
]



if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
