from django.shortcuts import render
import hashlib
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.parsers import MultiPartParser

class MalwareUploadView(APIView):
    # MultiPartParser allows this endpoint to accept file uploads
    parser_classes = [MultiPartParser]

    def post(self, request, format=None):
        # Check if a file was actually uploaded
        if 'file' not in request.FILES:
            return Response(
                {"error": "No file provided."}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        uploaded_file = request.FILES['file']
        
        # Calculate SHA-256 hash of the uploaded file
        sha256_hash = hashlib.sha256()
        
        # Read the file in chunks so large files don't crash the server memory
        for chunk in uploaded_file.chunks():
            sha256_hash.update(chunk)
            
        file_hash = sha256_hash.hexdigest()

        # For this step, we return the metadata back to the user
        analysis_summary = {
            "file_name": uploaded_file.name,
            "file_size_bytes": uploaded_file.size,
            "sha256": file_hash,
            "status": "Received & Hashed Successfully"
        }

        return Response(analysis_summary, status=status.HTTP_200_OK)

# Create your views here.
def upload_page(request):
    return render(request, 'analyzer/upload.html')