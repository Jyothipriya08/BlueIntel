import hashlib
import math
import pefile
import yara
import os
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.parsers import MultiPartParser
from django.shortcuts import render

# 1. Simple view to serve the HTML portal UI
def upload_page(request):
    return render(request, 'analyzer/upload.html')


# 2. Advanced Static Malware Analysis & Signature View
class MalwareUploadView(APIView):
    parser_classes = [MultiPartParser]

    def calculate_entropy(self, data):
        """Calculates Shannon Entropy of file data (0 to 8) to find packing/encryption."""
        if not data:
            return 0.0
        entropy = 0
        length = len(data)
        # Count frequency of each byte occurrence (0-255)
        frequencies = [0] * 256
        for byte in data:
            frequencies[byte] += 1
        
        # Calculate Shannon Entropy formula
        for count in frequencies:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    def post(self, request, format=None):
        if 'file' not in request.FILES:
            return Response({"error": "No file provided."}, status=status.HTTP_400_BAD_REQUEST)
        
        uploaded_file = request.FILES['file']
        file_data = uploaded_file.read()  # Read entire file into memory safely

        # Calculate standard SHA-256 Hash
        sha256_hash = hashlib.sha256(file_data).hexdigest()
        
        # Calculate Information Entropy
        file_entropy = self.calculate_entropy(file_data)

        # Base response metadata
        analysis_results = {
            "file_name": uploaded_file.name,
            "file_size_bytes": uploaded_file.size,
            "sha256": sha256_hash,
            "entropy": file_entropy,
            "is_pe": False,
            "pe_metadata": {},
            "yara_matches": []  # Added this field back!
        }

        # --- YARA SIGNATURE SCANNING ENGINE ---
        try:
            # Locate the absolute path of your rules file
            rule_path = os.path.join(os.path.dirname(__file__), 'rules', 'malware_signatures.yar')
            
            # Verify the rule file exists before trying to compile it
            if os.path.exists(rule_path):
                rules = yara.compile(filepath=rule_path)
                matches = rules.match(data=file_data)
                
                # Extract names of all rules matched by this binary file
                for match in matches:
                    analysis_results["yara_matches"].append(match.rule)
            else:
                analysis_results["yara_matches"].append("Error: Signature rule file missing.")
        except Exception as e:
            analysis_results["yara_matches"].append(f"Scan Error: {str(e)}")

        # --- PE PORTABLE EXECUTABLE ENGINE ---
        try:
            pe = pefile.PE(data=file_data)
            analysis_results["is_pe"] = True
            
            # Extract AddressOfEntryPoint and basic structural counts
            analysis_results["pe_metadata"] = {
                "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "number_of_sections": pe.FILE_HEADER.NumberOfSections,
                "sections": []
            }

            # Loop through sections (.text, .data, .rsrc) and map their structural footprints
            for section in pe.sections:
                # Decode the binary section name safely
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                analysis_results["pe_metadata"]["sections"].append({
                    "name": section_name,
                    "virtual_address": hex(section.VirtualAddress),
                    "virtual_size": hex(section.Misc_VirtualSize),
                    "raw_data_size": hex(section.SizeOfRawData)
                })

        except pefile.PEFormatError:
            # Not an executable binary (e.g., text, image, doc). Fall back gracefully.
            pass

        return Response(analysis_results, status=status.HTTP_200_OK)