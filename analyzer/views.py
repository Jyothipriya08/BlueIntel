import hashlib
import math
import os
import re
import pefile
import yara
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.parsers import MultiPartParser

# --- ADD THESE IMPORTS FOR CSRF BYPASS ---
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

# 1. View to serve the fallback legacy HTML portal UI
def upload_page(request):
    return render(request, 'analyzer/upload.html')


# 2. Advanced Unified Malware Identification, Static Analysis, & IOC Engine
# The method_decorator tells Django's dispatcher to ignore CSRF validation requirements on this API point
@method_decorator(csrf_exempt, name='dispatch')
class MalwareUploadView(APIView):
    parser_classes = [MultiPartParser]

    def calculate_entropy(self, data):
        """Calculates Shannon Entropy of file data ($0$ to $8$) to detect obfuscation."""
        if not data:
            return 0.0
        entropy = 0
        length = len(data)
        frequencies = [0] * 256
        for byte in data:
            frequencies[byte] += 1
        
        for count in frequencies:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    def extract_iocs(self, file_data):
        """Parses readable ASCII strings out of data and classifies hardcoded IOCs."""
        strings = re.findall(b"[ -~]{4,}", file_data)
        decoded_strings = [s.decode('ascii', errors='ignore') for s in strings]
        joined_text = "\n".join(decoded_strings)

        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        domain_pattern = r'\b(?:[a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}\b'
        registry_pattern = r'\b(HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[a-zA-Z0-9_\\]+\b'

        extracted_domains = re.findall(domain_pattern, joined_text)
        clean_domains = [d for d in extracted_domains if not d.lower().endswith(('.dll', '.exe', '.sys', '.sym'))]

        return {
            "ips": list(set(re.findall(ip_pattern, joined_text))),
            "domains": list(set(clean_domains)),
            "registry_keys": list(set(re.findall(registry_pattern, joined_text)))
        }

    def post(self, request, format=None):
        if 'file' not in request.FILES:
            return Response({"error": "No file provided."}, status=status.HTTP_400_BAD_REQUEST)
        
        uploaded_file = request.FILES['file']
        file_data = uploaded_file.read()

        # Cryptographic Fingerprint Matrix
        hashes = {
            "md5": hashlib.md5(file_data).hexdigest(),
            "sha1": hashlib.sha1(file_data).hexdigest(),
            "sha256": hashlib.sha256(file_data).hexdigest()
        }
        
        file_entropy = self.calculate_entropy(file_data)
        iocs = self.extract_iocs(file_data)

        analysis_results = {
            "file_name": uploaded_file.name,
            "file_size_bytes": uploaded_file.size,
            "sha256": hashes["sha256"],  
            "hashes": hashes,
            "entropy": file_entropy,
            "is_pe": False,
            "pe_metadata": {},
            "yara_matches": [],
            "iocs": iocs,
            "malware_classification": {
                "verdict": "CLEAN",
                "score": 0,
                "indicators": []
            }
        }

        # --- YARA SIGNATURE SCANNING ENGINE ---
        try:
            rule_path = os.path.join(os.path.dirname(__file__), 'rules', 'malware_signatures.yar')
            if os.path.exists(rule_path):
                rules = yara.compile(filepath=rule_path)
                matches = rules.match(data=file_data)
                for match in matches:
                    analysis_results["yara_matches"].append(match.rule)
            else:
                analysis_results["yara_matches"].append("Warning: Signature rule file missing.")
        except Exception as e:
            analysis_results["yara_matches"].append(f"Scan Error: {str(e)}")

        # --- PE PORTABLE EXECUTABLE STRUCTURE PARSER ---
        try:
            pe = pefile.PE(data=file_data)
            analysis_results["is_pe"] = True
            analysis_results["pe_metadata"] = {
                "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "subsystem": pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, "UNKNOWN"),
                "number_of_sections": pe.FILE_HEADER.NumberOfSections,
                "sections": []
            }

            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                analysis_results["pe_metadata"]["sections"].append({
                    "name": section_name,
                    "virtual_address": hex(section.VirtualAddress),
                    "virtual_size": hex(section.Misc_VirtualSize),
                    "raw_data_size": hex(section.SizeOfRawData)
                })
        except pefile.PEFormatError:
            pass  

        # --- AUTOMATED HEURISTIC SECURITY RISK SCORING ---
        malware_score = 0
        indicators = []

        if len(analysis_results["yara_matches"]) > 0 and not any("Warning" in str(m) or "Scan Error" in str(m) for m in analysis_results["yara_matches"]):
            malware_score += 50
            indicators.append(f"YARA Rule Match: {', '.join(analysis_results['yara_matches'])}")
        
        if file_entropy > 7.2:
            malware_score += 35
            indicators.append("High structural entropy detected (Potential packing or code encryption)")
        elif file_entropy > 6.0 and analysis_results["is_pe"]:
            malware_score += 15
            indicators.append("Elevated structural entropy found inside binary file")

        if len(iocs["ips"]) > 0 or len(iocs["domains"]) > 0:
            malware_score += 30
            indicators.append("Hardcoded host or C2 networking strings identified")

        if len(iocs["registry_keys"]) > 0:
            malware_score += 10
            indicators.append("Discovered persistent Windows Registry manipulation strings")

        analysis_results["malware_classification"] = {
            "verdict": "MALICIOUS" if malware_score >= 50 else "SUSPICIOUS" if malware_score >= 20 else "CLEAN",
            "score": min(malware_score, 100),
            "indicators": indicators
        }

        return Response(analysis_results, status=status.HTTP_200_OK)