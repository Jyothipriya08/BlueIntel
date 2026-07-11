import hashlib
import math
import os
import re
import pefile
import yara
import anthropic
import random
import io
import requests

from django.shortcuts import render, redirect
from django.utils import timezone
from datetime import timedelta
from django.core.mail import send_mail
from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib.auth import authenticate, login as auth_login
from django.contrib.auth.models import User
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.contrib import messages

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework.parsers import MultiPartParser
from rest_framework.authtoken.models import Token

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

# Import models, utils and services
from .models import ThreatAnalysisLog, UserOTP, UserActivityLog, UserNotification, UserSetting
from .utils import encrypt_key, decrypt_key
from .services.virustotal_service import VirusTotalService

def get_developer_user(request):
    if request.user and request.user.is_authenticated:
        return request.user
    user, created = User.objects.get_or_create(username='developer', defaults={'email': 'developer@blueintel.com'})
    if created:
        UserSetting.objects.get_or_create(user=user)
    return user

def upload_page(request):
    return render(request, 'analyzer/upload.html')


# --- TELEMETRY AND ANALYSIS VIEW ENGINES ---

@method_decorator(csrf_exempt, name='dispatch')
class MalwareUploadView(APIView):
    parser_classes = [MultiPartParser]
    permission_classes = [permissions.AllowAny]

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
            return Response({"error": "No file payload provided."}, status=status.HTTP_400_BAD_REQUEST)
        
        uploaded_file = request.FILES['file']
        file_name = uploaded_file.name
        
        # Enforce file size limit of 15MB
        if uploaded_file.size > 15 * 1024 * 1024:
            return Response({"error": "File size exceeds maximum allowable limit of 15MB."}, status=status.HTTP_400_BAD_REQUEST)

        # Enforce supported extensions checks
        ext = os.path.splitext(file_name)[1].lower()
        allowed_extensions = ['.exe', '.dll', '.pdf', '.doc', '.docx', '.zip', '.rar', '.iso', '.apk', '.js', '.ps1', '.bat']
        if ext not in allowed_extensions:
            return Response({"error": f"Unsupported file extension '{ext}'. Ingestion bypassed."}, status=status.HTTP_400_BAD_REQUEST)

        file_data = uploaded_file.read()
        sha256_hash = hashlib.sha256(file_data).hexdigest()

        # Check Cache Layer
        existing_log = ThreatAnalysisLog.objects.filter(sha256=sha256_hash).first()
        if existing_log:
            # Audit log cache hit
            UserActivityLog.objects.create(
                user=get_developer_user(request),
                action=f"CACHE_HIT_SCAN_INGEST: {file_name}",
                ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1'),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
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
                "virus_total_report": existing_log.virus_total_report,
                "ai_generated_report": existing_log.ai_generated_report,
                "cached": True
            }, status=status.HTTP_200_OK)

        # Calculate static telemetry
        hashes = {
            "md5": hashlib.md5(file_data).hexdigest(),
            "sha1": hashlib.sha1(file_data).hexdigest(),
            "sha256": sha256_hash
        }
        file_entropy = self.calculate_entropy(file_data)
        iocs = self.extract_iocs(file_data)

        analysis_results = {
            "file_name": file_name,
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

        # Run YARA engine checks
        try:
            rule_path = os.path.join(os.path.dirname(__file__), 'rules', 'malware_signatures.yar')
            if os.path.exists(rule_path):
                rules = yara.compile(filepath=rule_path)
                matches = rules.match(data=file_data)
                for match in matches: 
                    analysis_results["yara_matches"].append(match.rule)
        except Exception: 
            pass

        # Parse PE structures
        try:
            pe = pefile.PE(data=file_data)
            analysis_results["is_pe"] = True
            analysis_results["pe_metadata"] = {
                "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "subsystem": pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, "UNKNOWN"),
                "sections": [{"name": s.Name.decode('utf-8', errors='ignore').strip('\x00'), "virtual_size": hex(s.Misc_VirtualSize), "raw_data_size": hex(s.SizeOfRawData)} for s in pe.sections]
            }
        except Exception: 
            pass

        # Risk Heuristic Score Calculations
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
            indicators.append("Embedded hardcoded host/C2 network configurations discovered")

        analysis_results["malware_classification"] = {
            "verdict": "MALICIOUS" if malware_score >= 50 else "SUSPICIOUS" if malware_score >= 20 else "CLEAN",
            "score": min(malware_score, 100),
            "indicators": indicators
        }

        # Fetch custom user VT key or fallback to environment variables
        vt_key_plain = ""
        try:
            user_settings = get_developer_user(request).settings
            if user_settings.encrypted_vt_key:
                vt_key_plain = decrypt_key(user_settings.encrypted_vt_key)
        except Exception:
            pass

        # Execute VirusTotal lookup
        vt_report = VirusTotalService.query_file_reputation(sha256_hash, api_key=vt_key_plain)
        analysis_results["virus_total_report"] = vt_report

        # Create persistent database row
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
            malware_classification=analysis_results["malware_classification"],
            virus_total_report=analysis_results["virus_total_report"]
        )
        
        # Log detonated payload event
        UserActivityLog.objects.create(
            user=get_developer_user(request),
            action=f"FILE_DETONATED_SCAN: {file_name} (Verdict: {analysis_results['malware_classification']['verdict']})",
            ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )

        analysis_results["id"] = log_instance.id
        return Response(analysis_results, status=status.HTTP_200_OK)


@method_decorator(csrf_exempt, name='dispatch')
class AIThreatReportView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, format=None):
        analysis_data = request.data.get("analysis_results")
        user_query = request.data.get("query", None)

        if not analysis_data:
            return Response({"error": "No analysis data provided."}, status=status.HTTP_400_BAD_REQUEST)

        # Get custom decrypted Claude API key or fallback to env vars
        claude_key_plain = ""
        try:
            user_settings = get_developer_user(request).settings
            if user_settings.encrypted_claude_key:
                claude_key_plain = decrypt_key(user_settings.encrypted_claude_key)
        except Exception:
            pass

        api_key = claude_key_plain or os.getenv("ANTHROPIC_API_KEY", "")
        if not api_key:
            return Response({"error": "Anthropic Claude API Key is missing. Configure it in Settings to enable AI analysis."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

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

            # Update cache if it is an initial report calculation
            if not user_query and "sha256" in analysis_data:
                ThreatAnalysisLog.objects.filter(sha256=analysis_data["sha256"]).update(ai_generated_report=ai_response_text)

            return Response({"report": ai_response_text}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": f"AI Engine Connection Pipeline Error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name='dispatch')
class ScanHistoryLedgerView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, format=None):
        logs = ThreatAnalysisLog.objects.all()[:15]
        data_matrix = [{
            "id": log.id,
            "name": log.file_name,
            "time": log.timestamp.strftime('%H:%M'),
            "hash": f"{log.sha256[:4]}...{log.sha256[-4:]}",
            "verdict": log.malware_classification.get('verdict', 'CLEAN'),
            "score": log.malware_classification.get('score', 0)
        } for log in logs]
        return Response(data_matrix, status=status.HTTP_200_OK)


# --- CLASS-BASED USER AUTHENTICATION API ENDPOINTS ---

@method_decorator(csrf_exempt, name='dispatch')
class UserSignupView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, format=None):
        email = request.data.get('email')
        username = request.data.get('username')
        password = request.data.get('password')

        if not email or not password:
            return Response({"error": "Email and password parameters are required."}, status=status.HTTP_400_BAD_REQUEST)

        # Build clean username from email if not provided
        if not username:
            username = email.split('@')[0]
            base_username = username
            counter = 1
            while User.objects.filter(username=username).exists():
                username = f"{base_username}{counter}"
                counter += 1

        if User.objects.filter(email=email).exists():
            return Response({"error": "A user with this email address already exists."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Create user and immediately disable active flag until OTP verifies
            user = User.objects.create_user(username=username, email=email, password=password)
            user.is_active = False
            user.save()

            # Create default settings
            UserSetting.objects.create(user=user)

            # Generate OTP code
            otp_code = str(random.randint(100000, 999999))
            expires_at = timezone.now() + timedelta(minutes=5)
            UserOTP.objects.create(user=user, code=otp_code, expires_at=expires_at)

            # Send OTP email
            subject = "BlueIntel Security Console - OTP Email Verification"
            message_body = f"Operator Call-sign: {username}\nYour 6-digit email OTP security code is: {otp_code}\n\nNote: Code expires in 5 minutes."
            send_mail(
                subject,
                message_body,
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )

            # Audit log
            UserActivityLog.objects.create(
                user=user,
                action="USER_SIGNUP_OTP_TRANSMITTED",
                ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1'),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )

            return Response({
                "status": "verification_pending",
                "email": email,
                "message": "Onboarding credentials stored. Verification OTP transmitted."
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({"error": f"Onboarding pipeline error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name='dispatch')
class VerifyOTPView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, format=None):
        email = request.data.get('email')
        code = request.data.get('code')

        if not email or not code:
            return Response({"error": "Email and verification code are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User profile was not discovered in SQL database registries."}, status=status.HTTP_404_NOT_FOUND)

        # Retrieve active OTP
        otp = UserOTP.objects.filter(user=user, is_used=False).first()
        if not otp:
            return Response({"error": "No active verification OTP was found for this user."}, status=status.HTTP_400_BAD_REQUEST)

        # Check expiration
        if timezone.now() > otp.expires_at:
            return Response({"error": "OTP has expired. Please trigger a resend command."}, status=status.HTTP_400_BAD_REQUEST)

        # Match check
        if otp.code != code:
            otp.resend_attempts += 1
            otp.save()
            if otp.resend_attempts >= 5:
                # Force invalidate OTP on brute force
                otp.is_used = True
                otp.save()
                return Response({"error": "Maximum matching attempts exceeded. OTP invalidated."}, status=status.HTTP_400_BAD_REQUEST)
            return Response({"error": f"Invalid verification code. {5 - otp.resend_attempts} attempts remaining."}, status=status.HTTP_400_BAD_REQUEST)

        # Success OTP validation
        otp.is_used = True
        otp.save()

        user.is_active = True
        user.save()

        # Audit logs
        UserActivityLog.objects.create(
            user=user,
            action="USER_EMAIL_OTP_VERIFIED",
            ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )

        token, created = Token.objects.get_or_create(user=user)
        return Response({
            "token": token.key,
            "message": "Operator identity verified successfully.",
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email
            }
        }, status=status.HTTP_200_OK)


@method_decorator(csrf_exempt, name='dispatch')
class ResendOTPView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, format=None):
        email = request.data.get('email')
        if not email:
            return Response({"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        if user.is_active:
            return Response({"error": "Email already verified. Bypassing OTP request."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Revoke previous OTP codes
            UserOTP.objects.filter(user=user, is_used=False).update(is_used=True)

            # Generate new OTP code
            otp_code = str(random.randint(100000, 999999))
            expires_at = timezone.now() + timedelta(minutes=5)
            UserOTP.objects.create(user=user, code=otp_code, expires_at=expires_at)

            # Resend OTP email
            subject = "BlueIntel Security Console - OTP Resend Verification"
            message_body = f"Your fresh 6-digit email OTP security code is: {otp_code}\n\nNote: Code expires in 5 minutes."
            send_mail(
                subject,
                message_body,
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )

            return Response({"message": "Fresh verification code transmitted successfully."}, status=status.HTTP_200_OK)
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

        # REAL credentials validation against DB - resolves authentication bugs completely!
        user = authenticate(username=username, password=password)
        if user is not None:
            if not user.is_active:
                # User exists but is inactive, implying email OTP is pending!
                # Generate new OTP automatically and redirect user to OTP page
                UserOTP.objects.filter(user=user, is_used=False).update(is_used=True)
                otp_code = str(random.randint(100000, 999999))
                expires_at = timezone.now() + timedelta(minutes=5)
                UserOTP.objects.create(user=user, code=otp_code, expires_at=expires_at)

                send_mail(
                    "BlueIntel Security Console - OTP Email Verification",
                    f"Operator Call-sign: {username}\nYour verification OTP security code is: {otp_code}",
                    settings.DEFAULT_FROM_EMAIL,
                    [email],
                    fail_silently=False,
                )
                return Response({
                    "status": "verification_pending",
                    "email": email,
                    "error": "Email validation code transmitted. Action verification required."
                }, status=status.HTTP_403_FORBIDDEN)
            
            # Log action
            UserActivityLog.objects.create(
                user=user,
                action="USER_LOGIN",
                ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1'),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )

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
            # Audit log action before deletion
            UserActivityLog.objects.create(
                user=request.user,
                action="USER_LOGOUT",
                ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1'),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            request.user.auth_token.delete()
            return Response({"message": "Successfully logged out."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# --- PASSWORD RESET & CREDENTIAL MODIFICATION VIEWS ---

@method_decorator(csrf_exempt, name='dispatch')
class PasswordResetRequestView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, format=None):
        email = request.data.get('email')
        if not email:
            return Response({"error": "Email parameter is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "No account matched this email address."}, status=status.HTTP_404_NOT_FOUND)

        try:
            # Revoke previous reset OTP codes
            UserOTP.objects.filter(user=user, is_used=False).update(is_used=True)

            # Generate fresh OTP code
            otp_code = str(random.randint(100000, 999999))
            expires_at = timezone.now() + timedelta(minutes=5)
            UserOTP.objects.create(user=user, code=otp_code, expires_at=expires_at)

            # Send OTP email
            subject = "BlueIntel Security Console - Password Reset OTP"
            message_body = f"Operator Call-sign: {user.username}\nYour 6-digit security code to reset your password is: {otp_code}\n\nNote: Code expires in 5 minutes."
            send_mail(
                subject,
                message_body,
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )

            # Audit log
            UserActivityLog.objects.create(
                user=user,
                action="USER_PASSWORD_RESET_REQUESTED",
                ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1'),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )

            return Response({"message": "Password reset verification code transmitted successfully."}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": f"Password reset transmission failure: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name='dispatch')
class PasswordResetVerifyView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, format=None):
        email = request.data.get('email')
        code = request.data.get('code')
        new_password = request.data.get('new_password')

        if not email or not code or not new_password:
            return Response({"error": "Email, verification code, and new password are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User profile not found."}, status=status.HTTP_404_NOT_FOUND)

        # Retrieve active OTP
        otp = UserOTP.objects.filter(user=user, is_used=False).first()
        if not otp:
            return Response({"error": "No active reset OTP was found for this user."}, status=status.HTTP_400_BAD_REQUEST)

        # Check expiration
        if timezone.now() > otp.expires_at:
            return Response({"error": "Reset OTP has expired. Please trigger a new password reset request."}, status=status.HTTP_400_BAD_REQUEST)

        # Match check
        if otp.code != code:
            otp.resend_attempts += 1
            otp.save()
            if otp.resend_attempts >= 5:
                otp.is_used = True
                otp.save()
                return Response({"error": "Maximum matching attempts exceeded. Reset OTP invalidated."}, status=status.HTTP_400_BAD_REQUEST)
            return Response({"error": f"Invalid verification code. {5 - otp.resend_attempts} attempts remaining."}, status=status.HTTP_400_BAD_REQUEST)

        # Success OTP validation
        otp.is_used = True
        otp.save()

        # Update password and activate user
        user.set_password(new_password)
        user.is_active = True
        user.save()

        # Audit logs
        UserActivityLog.objects.create(
            user=user,
            action="USER_PASSWORD_RESET_COMPLETED",
            ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )

        return Response({"message": "Password updated successfully. You can now login with your new credentials."}, status=status.HTTP_200_OK)


@method_decorator(csrf_exempt, name='dispatch')
class PasswordChangeView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, format=None):
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')

        if not old_password or not new_password:
            return Response({"error": "Old and new password parameters are required."}, status=status.HTTP_400_BAD_REQUEST)

        # Validate old password
        if not request.user.check_password(old_password):
            return Response({"error": "Incorrect current password."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            request.user.set_password(new_password)
            request.user.save()

            # Log password change
            UserActivityLog.objects.create(
                user=request.user,
                action="USER_PASSWORD_CHANGED",
                ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1'),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )

            return Response({"message": "Password changed successfully."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# --- SOCIAL AUTHENTICATION GOOGLE OAUTH VIEWS ---

@method_decorator(csrf_exempt, name='dispatch')
class GoogleLoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, format=None):
        # Redirect directly to Allauth's built-in Google login path to use registered redirect URIs
        return HttpResponseRedirect('/accounts/google/login/')


@method_decorator(csrf_exempt, name='dispatch')
class SessionTokenView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, format=None):
        try:
            if request.user.is_authenticated:
                # Set default settings if they don't exist
                UserSetting.objects.get_or_create(user=request.user)
                
                # Generate/Retrieve token
                token, _ = Token.objects.get_or_create(user=request.user)
                
                # Log SSO Session Authorized
                UserActivityLog.objects.create(
                    user=request.user,
                    action="GOOGLE_SSO_SESSION_AUTHORIZED",
                    ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1'),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
                
                return Response({
                    "token": token.key,
                    "user": {
                        "id": request.user.id,
                        "username": request.user.username,
                        "email": request.user.email
                    }
                }, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Google Session unauthorized."}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# --- USER PROFILE & SYSTEM SETTINGS VIEWS ---

@method_decorator(csrf_exempt, name='dispatch')
class UserProfileView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, format=None):
        dev_user = get_developer_user(request)
        logs = UserActivityLog.objects.filter(user=dev_user)[:10]
        activities = [{
            "action": log.action,
            "ip": log.ip_address,
            "time": log.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        } for log in logs]
        
        return Response({
            "username": dev_user.username,
            "email": dev_user.email,
            "date_joined": dev_user.date_joined.strftime('%Y-%m-%d'),
            "activities": activities
        }, status=status.HTTP_200_OK)


@method_decorator(csrf_exempt, name='dispatch')
class UserSettingView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, format=None):
        dev_user = get_developer_user(request)
        settings_obj, created = UserSetting.objects.get_or_create(user=dev_user)
        
        # Check if keys are configured, but mask them for security
        vt_configured = bool(settings_obj.encrypted_vt_key)
        claude_configured = bool(settings_obj.encrypted_claude_key)

        return Response({
            "theme": settings_obj.theme,
            "enable_notifications": settings_obj.enable_notifications,
            "vt_key_configured": vt_configured,
            "claude_key_configured": claude_configured
        }, status=status.HTTP_200_OK)

    def put(self, request, format=None):
        dev_user = get_developer_user(request)
        settings_obj, created = UserSetting.objects.get_or_create(user=dev_user)
        
        theme = request.data.get('theme', settings_obj.theme)
        enable_notifications = request.data.get('enable_notifications', settings_obj.enable_notifications)
        vt_key = request.data.get('vt_key', None)
        claude_key = request.data.get('claude_key', None)

        settings_obj.theme = theme
        settings_obj.enable_notifications = enable_notifications

        # Encrypt keys if provided
        if vt_key is not None:
            settings_obj.encrypted_vt_key = encrypt_key(vt_key)
        if claude_key is not None:
            settings_obj.encrypted_claude_key = encrypt_key(claude_key)

        settings_obj.save()

        # Log setting mutation
        UserActivityLog.objects.create(
            user=dev_user,
            action="OPERATOR_SETTINGS_UPDATED",
            ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )

        return Response({
            "message": "Operator Settings updated successfully.",
            "theme": settings_obj.theme,
            "enable_notifications": settings_obj.enable_notifications,
            "vt_key_configured": bool(settings_obj.encrypted_vt_key),
            "claude_key_configured": bool(settings_obj.encrypted_claude_key)
        }, status=status.HTTP_200_OK)


# --- REPORTLAB PDF COMPILATION VIEW ---

@method_decorator(csrf_exempt, name='dispatch')
class DownloadPDFReportView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, pk, format=None):
        try:
            log = ThreatAnalysisLog.objects.get(pk=pk)
        except ThreatAnalysisLog.DoesNotExist:
            return Response({"error": "Malware report record was not found."}, status=status.HTTP_404_NOT_FOUND)

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer, 
            pagesize=letter,
            rightMargin=36, 
            leftMargin=36, 
            topMargin=36, 
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        
        # Dark Cyberpunk aesthetics mapped to PDF Color Layouts
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            textColor=colors.HexColor('#0055ff'),
            fontSize=22,
            spaceAfter=15,
            fontName='Helvetica-Bold'
        )

        section_heading = ParagraphStyle(
            'SectionHeading',
            parent=styles['Heading2'],
            textColor=colors.HexColor('#111827'),
            fontSize=12,
            spaceBefore=12,
            spaceAfter=6,
            fontName='Helvetica-Bold',
            borderColor=colors.HexColor('#3b82f6'),
            borderWidth=0.5
        )

        normal_text = ParagraphStyle(
            'NormalText',
            parent=styles['Normal'],
            textColor=colors.HexColor('#374151'),
            fontSize=9,
            leading=13
        )

        label_style = ParagraphStyle(
            'LabelStyle',
            parent=styles['Normal'],
            textColor=colors.HexColor('#4b5563'),
            fontSize=8,
            fontName='Helvetica-Bold'
        )

        value_style = ParagraphStyle(
            'ValueStyle',
            parent=styles['Normal'],
            textColor=colors.HexColor('#111827'),
            fontSize=8,
            fontName='Courier'
        )

        elements = []

        # Report Header
        elements.append(Paragraph("BLUEINTEL AUTOMATED SEC-OPS SECURITY BRIEFING", title_style))
        elements.append(Spacer(1, 10))

        # Metadata Table Matrix
        verdict = log.malware_classification.get('verdict', 'CLEAN')
        score = log.malware_classification.get('score', 0)
        
        data = [
            [Paragraph("Detonated Payload Name", label_style), Paragraph(log.file_name, value_style)],
            [Paragraph("Payload Ingestion Size", label_style), Paragraph(f"{log.file_size_bytes} Bytes", value_style)],
            [Paragraph("Cryptographic SHA-256", label_style), Paragraph(log.sha256, value_style)],
            [Paragraph("Cryptographic MD5", label_style), Paragraph(log.md5 or 'N/A', value_style)],
            [Paragraph("Shannon Entropy Index", label_style), Paragraph(str(log.entropy), value_style)],
            [Paragraph("Analysis Security Score", label_style), Paragraph(f"{verdict} ({score}/100 Risk Rating)", value_style)]
        ]

        meta_table = Table(data, colWidths=[130, 410])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f9fafb')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e5e7eb')),
            ('PADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 15))

        # YARA Rules Mappings
        elements.append(Paragraph("YARA Rule Match Telemetry", section_heading))
        yara_matches = log.yara_matches
        yara_text = ", ".join(yara_matches) if yara_matches else "No dangerous threat signatures matched YARA rules."
        elements.append(Paragraph(yara_text, normal_text))
        elements.append(Spacer(1, 15))

        # IOCs Tracker
        elements.append(Paragraph("Indicators of Compromise (IOCs) Mapped", section_heading))
        ips = log.extracted_iocs.get("ips", [])
        domains = log.extracted_iocs.get("domains", [])
        reg_keys = log.extracted_iocs.get("registry_keys", [])
        
        ioc_details = (
            f"<b>Hardcoded Connections (IPs):</b> {', '.join(ips) if ips else 'None'}<br/>"
            f"<b>Domain Callouts:</b> {', '.join(domains) if domains else 'None'}<br/>"
            f"<b>Windows Registry Mutations:</b> {', '.join(reg_keys) if reg_keys else 'None'}"
        )
        elements.append(Paragraph(ioc_details, normal_text))
        elements.append(Spacer(1, 15))

        # VirusTotal Integration Results
        elements.append(Paragraph("VirusTotal Threat Intelligence Lookup Results", section_heading))
        vt_report = log.virus_total_report
        if vt_report and vt_report.get('status') == 'success':
            stats = vt_report.get('stats', {})
            vt_text = (
                f"<b>Reputation Score:</b> {vt_report.get('reputation', 0)}<br/>"
                f"<b>Anti-Virus Engine Detections:</b> {stats.get('malicious', 0)} malicious engines flagged, "
                f"{stats.get('suspicious', 0)} suspicious, "
                f"{stats.get('harmless', 0)} harmless, "
                f"{stats.get('undetected', 0)} undetected."
            )
        else:
            vt_text = f"<i>{vt_report.get('message', 'VirusTotal lookup not run or API settings missing.')}</i>"
        elements.append(Paragraph(vt_text, normal_text))
        elements.append(Spacer(1, 15))

        # AI Analyst Summary
        elements.append(Paragraph("AI SecOps Incident Response & MITRE Matrix", section_heading))
        ai_report = log.ai_generated_report or "No AI briefings compiled for this signature hash yet."
        elements.append(Paragraph(ai_report.replace('\n', '<br/>'), normal_text))

        # Compile PDF document
        doc.build(elements)

        # Output bytes buffer
        buffer.seek(0)
        response = HttpResponse(buffer, content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="BlueIntel_Report_{log.sha256[:8]}.pdf"'
        return response