"""
URL configuration for core project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
"""
from django.contrib import admin
from django.urls import path, include
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from django.urls import path
from analyzer import views # or from . import views
# Import your dynamic application views from the analyzer app
from analyzer.views import (
    upload_page, 
    MalwareUploadView, 
    AIThreatReportView, 
    ScanHistoryLedgerView,
    UserSignupView,
    UserLoginView,
    UserLogoutView
)

# Core Local Authentication View Matrix matching your React UI endpoints
@csrf_exempt
def local_login_endpoint(request):
    if request.method == 'POST':
        try:
            body = json.loads(request.body)
            email = body.get('email')
            password = body.get('password')
            
            # Step-by-step logic will match database validation here later
            # For now, safely trigger the multi-factor OTP stage required by your frontend
            return JsonResponse({'status': 'mfa_required', 'requires_otp': True}, status=200)
        except Exception:
            return JsonResponse({'error': 'Malformed authentication context parameters.'}, status=400)
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def local_otp_endpoint(request):
    if request.method == 'POST':
        return JsonResponse({'status': 'authorized', 'verified': True}, status=200)
    return JsonResponse({'error': 'Method not allowed'}, status=405)


urlpatterns = [
    # Admin Interface Routing Node
    path('admin/', admin.site.urls),
    
    # Empty path portal view mapping
    path('', upload_page, name='home'), 
    
    # Federated Social Authorization Gateways (Google & Facebook SSO)
    path('accounts/', include('allauth.urls')),
    
    # Local Manual Credentials & Token Onboarding Handlers called by your React form
    path('api/v1/auth/signup/', UserSignupView.as_view(), name='api_auth_signup'),
    path('api/v1/auth/login/', UserLoginView.as_view(), name='api_auth_login'),
    path('api/v1/auth/logout/', UserLogoutView.as_view(), name='api_auth_logout'),
    
    # Local Application API Core Analysis Routes Namespace
    path('api/v1/', include('analyzer.urls')), 
    path('api/v1/upload/', MalwareUploadView.as_view(), name='file_upload_analysis'),
    path('api/v1/ai-report/', AIThreatReportView.as_view(), name='ai_threat_report'),
    path('api/v1/history-ledger/', ScanHistoryLedgerView.as_view(), name='history_ledger'),
    path('login/', views.login_view, name='login'),
]