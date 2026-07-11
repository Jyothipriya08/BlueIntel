from django.contrib import admin
from django.urls import path, include
from analyzer.views import (
    upload_page, 
    MalwareUploadView, 
    AIThreatReportView, 
    ScanHistoryLedgerView,
    UserSignupView,
    UserLoginView,
    UserLogoutView,
    VerifyOTPView,
    ResendOTPView,
    GoogleLoginView,
    SessionTokenView,
    UserProfileView,
    UserSettingView,
    DownloadPDFReportView,
    PasswordResetRequestView,
    PasswordResetVerifyView,
    PasswordChangeView,
    ScanStatusView,
    DashboardStatsView,
    ThreatIntelligenceView,
    GlobalSearchView,
    NotificationView,
    TelemetryStreamView
)

urlpatterns = [
    # Admin Interface Access Gateway
    path('admin/', admin.site.urls),
    
    # Static home template
    path('', upload_page, name='home'), 
    
    # Federated Social Authorization Gateways (Social Django Allauth Providers)
    path('accounts/', include('allauth.urls')),
    
    # Class-based Token-Based User Authentication API Routes
    path('api/v1/auth/signup/', UserSignupView.as_view(), name='api_auth_signup'),
    path('api/v1/auth/login/', UserLoginView.as_view(), name='api_auth_login'),
    path('api/v1/auth/logout/', UserLogoutView.as_view(), name='api_auth_logout'),
    path('api/v1/auth/verify-otp/', VerifyOTPView.as_view(), name='api_auth_verify_otp'),
    path('api/v1/auth/resend-otp/', ResendOTPView.as_view(), name='api_auth_resend_otp'),
    path('api/v1/auth/password-reset/request/', PasswordResetRequestView.as_view(), name='api_password_reset_request'),
    path('api/v1/auth/password-reset/verify/', PasswordResetVerifyView.as_view(), name='api_password_reset_verify'),
    path('api/v1/auth/password-change/', PasswordChangeView.as_view(), name='api_password_change'),
    
    # Google OAuth Redirection Callback endpoints
    path('api/v1/auth/google/login/', GoogleLoginView.as_view(), name='api_auth_google_login'),
    path('api/v1/auth/session-token/', SessionTokenView.as_view(), name='api_auth_session_token'),
    
    # User Profile & Activity audit logging details
    path('api/v1/profile/', UserProfileView.as_view(), name='api_profile'),
    
    # Encrypted settings keys storage updating controls
    path('api/v1/settings/', UserSettingView.as_view(), name='api_settings'),
    
    # Analysis detonate upload and historical registry
    path('api/v1/upload/', MalwareUploadView.as_view(), name='file_upload_analysis'),
    path('api/v1/ai-report/', AIThreatReportView.as_view(), name='ai_threat_report'),
    path('api/v1/history-ledger/', ScanHistoryLedgerView.as_view(), name='history_ledger'),
    path('api/v1/scan-status/<int:pk>/', ScanStatusView.as_view(), name='api_scan_status'),
    path('api/v1/dashboard-stats/', DashboardStatsView.as_view(), name='api_dashboard_stats'),
    path('api/v1/threat-intelligence/', ThreatIntelligenceView.as_view(), name='api_threat_intelligence'),
    path('api/v1/global-search/', GlobalSearchView.as_view(), name='api_global_search'),
    path('api/v1/notifications/', NotificationView.as_view(), name='api_notifications'),
    path('api/v1/telemetry-stream/', TelemetryStreamView.as_view(), name='api_telemetry_stream'),
    
    # Downloadable analyst briefing PDF generator route
    path('api/v1/reports/<int:pk>/download/', DownloadPDFReportView.as_view(), name='download_report_pdf'),
]