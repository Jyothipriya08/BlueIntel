import hashlib
import math
import os
import re
import pefile
import yara
import anthropic

from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.parsers import MultiPartParser
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as auth_login
from django.contrib import messages

# DRF authentication and permission imports
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from rest_framework import permissions

# Import the persistence data objects we just deployed
from .models import ThreatAnalysisLog

def upload_page(request):
    return render(request, 'analyzer/upload.html')


@method_decorator(csrf_exempt, name='dispatch')
class MalwareUploadView(APIView):
    parser_classes = [MultiPartParser]
    permission_classes = [permissions.IsAuthenticated]

    def calculate_entropy(self, data):
        if not data: return 0.0
        entropy = 0
        length = len(data)
        frequencies = [0] * 256
        for byte in data: frequencies[byte] += 1
        for count in frequencies:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    def extract_iocs(self, file_data):
        strings = re.findall(b"[ -~]{4,}", file_data)
        decoded_strings = [s.decode('ascii', errors='ignore') for s in strings]
        joined_text = "\n".join(decoded_strings)
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        domain_pattern = r'\b(?:[a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}\b'
        registry_pattern = r'\b(HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[a-zA-Z0-9_\\]+\b'
        return {
            "ips": list(set(re.findall(ip_pattern, joined_text))),
            "domains": list(set([d for d in re.findall(domain_pattern, joined_text) if not d.lower().endswith(('.dll', '.exe', '.sys'))])),
            "registry_keys": list(set(re.findall(registry_pattern, joined_text)))
        }

    def post(self, request, format=None):
        if 'file' not in request.FILES:
            return Response({"error": "No file provided."}, status=status.HTTP_400_BAD_REQUEST)
        
        uploaded_file = request.FILES['file']
        file_data = uploaded_file.read()

        # Generate cryptographic fingerprint
        sha256_hash = hashlib.sha256(file_data).hexdigest()

        # --- DUPONT CACHE CHECK SYSTEM ---
        # If the file hash already exists in the database, return the historical log instantly
        existing_log = ThreatAnalysisLog.objects.filter(sha256=sha256_hash).first()
        if existing_log:
            return Response({
                "id": existing_log.id,
                "file_name": existing_log.file_name,
                "file_size_bytes": existing_log.file_size_bytes,
                "sha256": existing_log.sha256,
                "hashes": {"md5": existing_log.md5, "sha1": existing_log.sha1, "sha256": existing_log.sha256},
                "entropy": existing_log.entropy,
                "is_pe": existing_log.is_pe,
                "pe_metadata": existing_log.pe_metadata,
                "yara_matches": existing_log.yara_matches,
                "iocs": existing_log.extracted_iocs,
                "malware_classification": existing_log.malware_classification,
                "ai_generated_report": existing_log.ai_generated_report, # Loaded instantly without calling Claude!
                "cached": True
            }, status=status.HTTP_200_OK)

        # Proceed with raw calculations if it is a fresh un-scanned asset
        hashes = {
            "md5": hashlib.md5(file_data).hexdigest(),
            "sha1": hashlib.sha1(file_data).hexdigest(),
            "sha256": sha256_hash
        }
        file_entropy = self.calculate_entropy(file_data)
        iocs = self.extract_iocs(file_data)

        analysis_results = {
            "file_name": uploaded_file.name,
            "file_size_bytes": uploaded_file.size,
            "sha256": sha256_hash,
            "hashes": hashes,
            "entropy": file_entropy,
            "is_pe": False,
            "pe_metadata": {},
            "yara_matches": [],
            "iocs": iocs,
            "malware_classification": {"verdict": "CLEAN", "score": 0, "indicators": []}
        }

        try:
            rule_path = os.path.join(os.path.dirname(__file__), 'rules', 'malware_signatures.yar')
            if os.path.exists(rule_path):
                rules = yara.compile(filepath=rule_path)
                matches = rules.match(data=file_data)
                for match in matches: analysis_results["yara_matches"].append(match.rule)
        except Exception: pass

        try:
            pe = pefile.PE(data=file_data)
            analysis_results["is_pe"] = True
            analysis_results["pe_metadata"] = {
                "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "subsystem": pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, "UNKNOWN"),
                "sections": [{"name": s.Name.decode('utf-8', errors='ignore').strip('\x00'), "virtual_size": hex(s.Misc_VirtualSize), "raw_data_size": hex(s.SizeOfRawData)} for s in pe.sections]
            }
        except Exception: pass

        malware_score = 0
        indicators = []
        if len(analysis_results["yara_matches"]) > 0:
            malware_score += 50
            indicators.append(f"YARA Rule Match: {', '.join(analysis_results['yara_matches'])}")
        if file_entropy > 7.2:
            malware_score += 35
            indicators.append("High structural entropy detected (Potential packing/obfuscation)")
        if len(iocs["ips"]) > 0 or len(iocs["domains"]) > 0:
            malware_score += 30
            indicators.append("Hardcoded host or C2 configurations discovered")

        analysis_results["malware_classification"] = {
            "verdict": "MALICIOUS" if malware_score >= 50 else "SUSPICIOUS" if malware_score >= 20 else "CLEAN",
            "score": min(malware_score, 100),
            "indicators": indicators
        }

        # Save base metadata records to database cache layer initially
        log_instance = ThreatAnalysisLog.objects.create(
            file_name=analysis_results["file_name"],
            file_size_bytes=analysis_results["file_size_bytes"],
            sha256=analysis_results["sha256"],
            md5=hashes["md5"],
            sha1=hashes["sha1"],
            entropy=analysis_results["entropy"],
            is_pe=analysis_results["is_pe"],
            pe_metadata=analysis_results["pe_metadata"],
            yara_matches=analysis_results["yara_matches"],
            extracted_iocs=analysis_results["iocs"],
            malware_classification=analysis_results["malware_classification"]
        )
        
        analysis_results["id"] = log_instance.id
        return Response(analysis_results, status=status.HTTP_200_OK)


@method_decorator(csrf_exempt, name='dispatch')
class AIThreatReportView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def post(self, request, format=None):
        analysis_data = request.data.get("analysis_results")
        user_query = request.data.get("query", None)

        if not analysis_data:
            return Response({"error": "No analysis data provided."}, status=status.HTTP_400_BAD_REQUEST)

        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            return Response({"error": "Anthropic API Key is missing."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        try:
            client = anthropic.Anthropic(api_key=api_key)
            system_prompt = "You are the BlueIntel Autonomous SecOps AI Copilot, an elite tier-3 malware analysis agent."

            if user_query:
                prompt = f"Telemetry data for '{analysis_data.get('file_name')}':\n- SHA-256: {analysis_data.get('sha256')}\n- Verdict: {analysis_data.get('malware_classification', {}).get('verdict')}\n\nOperator asks: '{user_query}'"
            else:
                prompt = f"Perform threat assessment for file: {analysis_data.get('file_name')}\nEntropy: {analysis_data.get('entropy')}\nYARA: {analysis_data.get('yara_matches')}\nIOCs: {analysis_data.get('iocs')}\n\nFormat output precisely with Markdown headers: ### 🛡️ Executive Summary & Threat Classification, ### 🥷 MITRE ATT&CK Mapping Matrix, ### ⚡ Actionable Incident Response Playbook"

            message = client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=1500,
                temperature=0.1,
                system=system_prompt,
                messages=[{"role": "user", "content": prompt}]
            )

            ai_response_text = message.content[0].text

            # --- UPDATE STORAGE LOGS ---
            # If generating an initial full report (not a quick user chat query), bind it permanently into the database row record!
            if not user_query and "sha256" in analysis_data:
                ThreatAnalysisLog.objects.filter(sha256=analysis_data["sha256"]).update(ai_generated_report=ai_response_text)

            return Response({"report": ai_response_text}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": f"API Error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# NEW API NODE: Fetches all historical entries straight into the frontend ledger table layout
@method_decorator(csrf_exempt, name='dispatch')
class ScanHistoryLedgerView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, format=None):
        logs = ThreatAnalysisLog.objects.all()[:15] # Grab trailing 15 events
        data_matrix = [{
            "name": log.file_name,
            "time": log.timestamp.strftime('%H:%M'),
            "hash": f"{log.sha256[:4]}...{log.sha256[-4:]}",
            "verdict": log.malware_classification.get('verdict', 'CLEAN'),
            "score": log.malware_classification.get('score', 0)
        } for log in logs]
        return Response(data_matrix, status=status.HTTP_200_OK)
    
def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard:home')
        
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        # Resolve username if email is used as primary identity
        from django.contrib.auth.models import User
        try:
            user_obj = User.objects.get(email=email)
            username = user_obj.username
        except User.DoesNotExist:
            messages.error(request, "User Not Found")
            return render(request, 'auth/login.html')

        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            if not user.is_active:
                messages.error(request, "Account Not Verified")
                return render(request, 'auth/login.html')
            
            # Successful authentication requirement
            auth_login(request, user)
            return redirect('dashboard:home')
        else:
            messages.error(request, "Incorrect Password")
            return render(request, 'auth/login.html')
            
    return render(request, 'auth/login.html')


# --- CLASS-BASED USER AUTHENTICATION API ENDPOINTS ---

@method_decorator(csrf_exempt, name='dispatch')
class UserSignupView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, format=None):
        email = request.data.get('email')
        username = request.data.get('username')
        password = request.data.get('password')

        if not email or not password:
            return Response({"error": "Email and password are required."}, status=status.HTTP_400_BAD_REQUEST)

        # Generate a username from email if not specified
        if not username:
            username = email.split('@')[0]
            # Ensure unique username
            base_username = username
            counter = 1
            while User.objects.filter(username=username).exists():
                username = f"{base_username}{counter}"
                counter += 1

        if User.objects.filter(email=email).exists():
            return Response({"error": "A user with this email already exists."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.create_user(username=username, email=email, password=password)
            token, created = Token.objects.get_or_create(user=user)
            return Response({
                "token": token.key,
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email
                }
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name='dispatch')
class UserLoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, format=None):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response({"error": "Email and password are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user_obj = User.objects.get(email=email)
            username = user_obj.username
        except User.DoesNotExist:
            return Response({"error": "Invalid credentials. User does not exist."}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(username=username, password=password)
        if user is not None:
            if not user.is_active:
                return Response({"error": "Account is disabled."}, status=status.HTTP_403_FORBIDDEN)
            
            token, created = Token.objects.get_or_create(user=user)
            return Response({
                "token": token.key,
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email
                }
            }, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid credentials. Incorrect password."}, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(csrf_exempt, name='dispatch')
class UserLogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, format=None):
        try:
            request.user.auth_token.delete()
            return Response({"message": "Successfully logged out."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)