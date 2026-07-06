from django.urls import path
from .views import MalwareUploadView, upload_page

urlpatterns = [
    path('upload/', MalwareUploadView.as_view(), name='malware-upload'),
    path('portal/', upload_page, name='upload-portal'),
]