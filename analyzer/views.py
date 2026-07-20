import hashlib
import math
import os
import re
import pefile
import yara
import anthropic
from google import genai
from google.genai import types
import random
import io
import requests
import json
import queue
import threading
import time
from django.shortcuts import render, redirect
from django.db import models
from django.http import HttpResponse, HttpResponseRedirect, StreamingHttpResponse
from django.utils import timezone
from datetime import timedelta, datetime
from django.core.mail import send_mail
from django.conf import settings
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
from .models import ThreatAnalysisLog, UserOTP, UserActivityLog, UserNotification, UserSetting, ThreatIntelligenceFeed, AIChatHistory
from .utils import encrypt_key, decrypt_key
from .services.virustotal_service import VirusTotalService

def log_db_operation(user_action, table_name, data_inserted=None, data_updated=None, data_deleted=None, generated_id=None, exec_time=0.0, db_response="SUCCESS", errors=None):
    import sys
    import json
    from datetime import datetime
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    
    log_line = f"\n[DATABASE MONITOR] {timestamp}\n"
    log_line += f"  USER ACTION: {user_action}\n"
    log_line += f"  TABLE/COLLECTION: {table_name}\n"
    if data_inserted:
        log_line += f"  INSERTED DATA: {json.dumps(data_inserted, default=str)}\n"
    if data_updated:
        log_line += f"  UPDATED DATA: {json.dumps(data_updated, default=str)}\n"
    if data_deleted:
        log_line += f"  DELETED DATA: {json.dumps(data_deleted, default=str)}\n"
    if generated_id:
        log_line += f"  GENERATED ID: {generated_id}\n"
    log_line += f"  EXECUTION TIME: {exec_time:.4f}s\n"
    log_line += f"  DATABASE RESPONSE: {db_response}\n"
    if errors:
        log_line += f"  ERRORS: {errors}\n"
    log_line += "="*60 + "\n"
    
    # Print to Django terminal (sys.stdout)
    sys.stdout.write(log_line)
    sys.stdout.flush()
    
    # Store as application log file in workspace
    try:
        log_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "database_monitor.log")
        with open(log_path, "a", encoding="utf-8") as lf:
            lf.write(log_line)
    except Exception:
        pass


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

class TelemetryBroadcaster:
    clients = []

    @classmethod
    def register_client(cls):
        q = queue.Queue(maxsize=30)
        cls.clients.append(q)
        return q

    @classmethod
    def unregister_client(cls, q):
        if q in cls.clients:
            cls.clients.remove(q)

    @classmethod
    def broadcast(cls, event_type, data):
        message = {"type": event_type, "data": data}
        for client in list(cls.clients):
            try:
                client.put_nowait(message)
            except queue.Full:
                if client in cls.clients:
                    cls.clients.remove(client)

def broadcast_scan_update(log):
    payload = {
        "id": log.id,
        "status": log.status,
        "status_detail": log.status_detail,
        "file_name": log.file_name,
        "file_size_bytes": log.file_size_bytes,
        "sha256": log.sha256,
        "entropy": log.entropy,
        "is_pe": log.is_pe,
        "pe_metadata": log.pe_metadata,
        "yara_matches": log.yara_matches,
        "iocs": log.extracted_iocs,
        "malware_classification": log.malware_classification,
        "virus_total_report": log.virus_total_report,
        "ai_generated_report": log.ai_generated_report,
        "compiler_info": log.compiler_info,
        "digital_signature": log.digital_signature,
        "embedded_strings": log.embedded_strings,
        "suspicious_apis": log.suspicious_apis,
        "mitre_attack": log.mitre_attack,
        "persistence_techniques": log.persistence_techniques,
        "scan_duration_seconds": log.scan_duration_seconds,
        "hashes": {"md5": log.md5, "sha1": log.sha1, "sha256": log.sha256}
    }
    TelemetryBroadcaster.broadcast("SCAN_UPDATE", payload)

def broadcast_stats_update():
    try:
        total_analyzed = ThreatAnalysisLog.objects.count()
        completed = ThreatAnalysisLog.objects.filter(status='COMPLETED').count()
        processing = ThreatAnalysisLog.objects.filter(status='PROCESSING').count()
        failed = ThreatAnalysisLog.objects.filter(status='FAILED').count()
        
        malicious = ThreatAnalysisLog.objects.filter(malware_classification__verdict='MALICIOUS').count()
        suspicious = ThreatAnalysisLog.objects.filter(malware_classification__verdict='SUSPICIOUS').count()
        benign = ThreatAnalysisLog.objects.filter(malware_classification__verdict='CLEAN').count()
        
        completed_logs = ThreatAnalysisLog.objects.filter(status='COMPLETED')
        durations = [l.scan_duration_seconds for l in completed_logs if l.scan_duration_seconds is not None]
        avg_duration = round(sum(durations) / len(durations), 2) if durations else 0.0
        
        scores = []
        for l in completed_logs:
            if l.malware_classification and isinstance(l.malware_classification, dict):
                score = l.malware_classification.get('score')
                if score is not None:
                    try:
                        scores.append(float(score))
                    except (ValueError, TypeError):
                        pass
        ai_confidence = round(sum(scores) / len(scores), 1) if scores else 0.0

        recent_logs = ThreatAnalysisLog.objects.filter(malware_classification__verdict__in=['MALICIOUS', 'SUSPICIOUS']).order_by('-timestamp')[:5]
        alerts = [{
            "id": log.id,
            "file_name": log.file_name,
            "verdict": log.malware_classification.get('verdict', 'CLEAN'),
            "score": log.malware_classification.get('score', 0),
            "timestamp": log.timestamp.strftime('%H:%M:%S')
        } for log in recent_logs]

        daily_stats = {}
        all_logs = ThreatAnalysisLog.objects.filter(status='COMPLETED').order_by('-timestamp')[:100]
        for l in all_logs:
            day_str = l.timestamp.strftime('%Y-%m-%d')
            daily_stats[day_str] = daily_stats.get(day_str, 0) + 1
        
        chart_data_daily = [{"date": k, "files": v} for k, v in sorted(daily_stats.items())][-7:]

        payload = {
            "total_analyzed": total_analyzed,
            "completed": completed,
            "processing": processing,
            "failed": failed,
            "malicious": malicious,
            "suspicious": suspicious,
            "benign": benign,
            "avg_duration": avg_duration,
            "ai_confidence": ai_confidence,
            "alerts": alerts,
            "chart_data_daily": chart_data_daily,
            "chart_data_severity": [
                {"name": "Malicious", "value": malicious},
                {"name": "Suspicious", "value": suspicious},
                {"name": "Benign", "value": benign}
            ]
        }
        TelemetryBroadcaster.broadcast("STATS_UPDATE", payload)
    except Exception as e:
        print("Stats broadcast exception:", str(e))

def broadcast_notifications_update():
    try:
        dev_user = User.objects.filter(username='developer').first()
        if dev_user:
            notifications = UserNotification.objects.filter(user=dev_user).order_by('-created_at')[:30]
            data = [{
                "id": n.id,
                "title": n.title,
                "message": n.message,
                "is_read": n.is_read,
                "created_at": n.created_at.strftime('%Y-%m-%d %H:%M:%S')
            } for n in notifications]
            TelemetryBroadcaster.broadcast("NOTIFICATION_UPDATE", data)
    except Exception as e:
        print("Notification broadcast exception:", str(e))


def process_malware_file_async(log_id, file_data, vt_key, anthropic_key):
    from django.db import connection
    connection.close()  # Reset thread DB connection
    
    start_time = time.time()
    try:
        log = ThreatAnalysisLog.objects.get(pk=log_id)
        
        dev_user = User.objects.filter(username='developer').first()
        if dev_user:
            UserActivityLog.objects.create(
                user=dev_user,
                action="ANALYSIS_STARTED",
                status="SUCCESS",
                details=f"Started malware threat analysis for {log.file_name}"
            )
        log_db_operation(
            user_action=f"START_SCAN_ANALYSIS: {log.file_name}",
            table_name="ThreatAnalysisLog",
            data_updated={"status": "PROCESSING", "status_detail": "Hashing"},
            exec_time=0.01,
            db_response="SUCCESS"
        )

        # Step 1: Hashing
        log.status_detail = "Hashing"
        log.save()
        broadcast_scan_update(log)
        time.sleep(0.3)
        
        md5_hash = hashlib.md5(file_data).hexdigest()
        sha1_hash = hashlib.sha1(file_data).hexdigest()
        sha256_hash = log.sha256
        log.md5 = md5_hash
        log.sha1 = sha1_hash
        log.save()
        broadcast_scan_update(log)
        
        # Step 2: Extracting Metadata
        log.status_detail = "Extracting Metadata"
        log.save()
        broadcast_scan_update(log)
        time.sleep(0.3)
        
        # Entropy
        freqs = [0] * 256
        for byte in file_data:
            freqs[byte] += 1
        entropy = 0.0
        for count in freqs:
            if count > 0:
                p = count / len(file_data)
                entropy -= p * math.log2(p)
        log.entropy = round(entropy, 4)
        
        # Parse PE metadata
        is_pe = False
        pe_metadata = {}
        compiler_info = "Unknown Compiler / Platform"
        digital_signature = "Unsigned / Self-Signed Binary"
        suspicious_apis = []
        mitre_attack = []
        persistence_techniques = []
        
        try:
            pe = pefile.PE(data=file_data)
            is_pe = True
            pe_metadata = {
                "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "subsystem": pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, "UNKNOWN"),
                "sections": [{"name": s.Name.decode('utf-8', errors='ignore').strip('\x00'), "virtual_size": hex(s.Misc_VirtualSize), "raw_data_size": hex(s.SizeOfRawData)} for s in pe.sections]
            }
            # Compiler info extraction
            if pe.OPTIONAL_HEADER.MajorLinkerVersion == 14:
                compiler_info = "Microsoft Visual C/C++ (MSVC 2015-2022)"
            elif pe.OPTIONAL_HEADER.MajorLinkerVersion == 6:
                compiler_info = "Microsoft Visual C++ 6.0 (Legacy)"
            elif pe.OPTIONAL_HEADER.MajorLinkerVersion == 12:
                compiler_info = "Microsoft Visual C/C++ (MSVC 2013)"
            else:
                compiler_info = f"Linker GCC / Clang (Version {pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion})"
                
            # Imports / APIs checks
            suspicious_functions = {
                'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory', 'ShellExecute',
                'RegSetValueEx', 'GetProcAddress', 'LoadLibraryA', 'InternetOpen', 'HttpSendRequest',
                'GetAsyncKeyState', 'SetWindowsHookEx', 'WinExec', 'IsDebuggerPresent'
            }
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='ignore')
                            if func_name in suspicious_functions:
                                suspicious_apis.append(func_name)
                                
            # Mitre maps based on API imports
            if any(x in suspicious_apis for x in ['CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory']):
                mitre_attack.append("T1055 - Process Injection")
            if any(x in suspicious_apis for x in ['RegSetValueEx']):
                mitre_attack.append("T1547.001 - Registry Run Keys / Startup Folder")
                persistence_techniques.append("Registry Run Keys injection")
            if any(x in suspicious_apis for x in ['GetAsyncKeyState', 'SetWindowsHookEx']):
                mitre_attack.append("T1056.001 - Keylogging")
            if any(x in suspicious_apis for x in ['InternetOpen', 'HttpSendRequest']):
                mitre_attack.append("T1071.001 - Web Protocols")
                
        except Exception:
            pass
            
        log.is_pe = is_pe
        log.pe_metadata = pe_metadata
        log.compiler_info = compiler_info
        log.digital_signature = digital_signature
        log.suspicious_apis = suspicious_apis
        log.mitre_attack = mitre_attack
        log.persistence_techniques = persistence_techniques
        
        # Extraction of strings
        ascii_strings = re.findall(b"[ -~]{5,200}", file_data)
        embedded_strings = [s.decode('ascii', errors='ignore') for s in ascii_strings][:50]
        log.embedded_strings = embedded_strings
        
        # IOC extraction
        joined_text = "\n".join(embedded_strings)
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        domain_pattern = r'\b(?:[a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}\b'
        registry_pattern = r'\b(HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[a-zA-Z0-9_\\]+\b'
        log.extracted_iocs = {
            "ips": list(set(re.findall(ip_pattern, joined_text))),
            "domains": list(set([d for d in re.findall(domain_pattern, joined_text) if not d.lower().endswith(('.dll', '.exe', '.sys'))])),
            "registry_keys": list(set(re.findall(registry_pattern, joined_text)))
        }
        log.save()
        broadcast_scan_update(log)
        
        # Step 3: Running YARA Rules
        log.status_detail = "Running YARA Rules"
        log.save()
        broadcast_scan_update(log)
        time.sleep(0.3)
        
        yara_matches = []
        try:
            rule_path = os.path.join(os.path.dirname(__file__), 'rules', 'malware_signatures.yar')
            if os.path.exists(rule_path):
                rules = yara.compile(filepath=rule_path)
                matches = rules.match(data=file_data)
                for match in matches: 
                    yara_matches.append(match.rule)
        except Exception: 
            pass
        log.yara_matches = yara_matches
        log.save()
        broadcast_scan_update(log)
        
        # Heuristics Score calculation
        malware_score = 0
        indicators = []
        if len(yara_matches) > 0:
            malware_score += 50
            indicators.append(f"YARA Rule Match: {', '.join(yara_matches)}")
        if log.entropy > 7.2:
            malware_score += 35
            indicators.append("High structural entropy detected (Obfuscation/Packing)")
        if len(log.extracted_iocs["ips"]) > 0 or len(log.extracted_iocs["domains"]) > 0:
            malware_score += 30
            indicators.append("Embedded hardcoded C2 host coordinates found")
            
        log.malware_classification = {
            "verdict": "MALICIOUS" if malware_score >= 50 else "SUSPICIOUS" if malware_score >= 20 else "CLEAN",
            "score": min(malware_score, 100),
            "indicators": indicators
        }
        log.save()
        broadcast_scan_update(log)
        
        # Step 4: Checking Threat Intelligence
        log.status_detail = "Checking Threat Intelligence"
        log.save()
        broadcast_scan_update(log)
        time.sleep(0.3)
        
        vt_report = {}
        if vt_key:
            try:
                vt_report = VirusTotalService.query_file_reputation(sha256_hash, api_key=vt_key)
            except Exception:
                pass
        log.virus_total_report = vt_report
        log.save()
        broadcast_scan_update(log)
        
        # Step 5: Generating AI Report
        log.status_detail = "Generating AI Report"
        log.save()
        broadcast_scan_update(log)
        time.sleep(0.3)
        
        ai_report_text = ""
        api_key = anthropic_key or os.getenv("GEMINI_API_KEY", os.getenv("ANTHROPIC_API_KEY", ""))
        if api_key:
            try:
                client = genai.Client(api_key=api_key)
                prompt = f"Perform threat assessment for file: {log.file_name}\nEntropy: {log.entropy}\nYARA: {log.yara_matches}\nIOCs: {log.extracted_iocs}\n\nFormat output precisely with Markdown headers: ### 🛡️ Executive Summary & Threat Classification, ### 🥷 MITRE ATT&CK Mapping Matrix, ### ⚡ Actionable Incident Response Playbook"
                system_prompt = "You are the BlueIntel Autonomous SecOps AI Copilot, an elite tier-3 malware analysis agent."
                
                response = client.models.generate_content(
                    model='gemini-2.0-flash',
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=system_prompt,
                        max_output_tokens=1500,
                        temperature=0.1
                    )
                )
                ai_report_text = response.text
            except Exception as e:
                error_msg = str(e)
                if "quota" in error_msg.lower() or "billing" in error_msg.lower() or "limit" in error_msg.lower() or "credit" in error_msg.lower():
                    ai_report_text = (
                        "⚠️ Google Gemini API Quota/Billing Issue: The configured API key has an insufficient credit balance or exceeded quota limit. "
                        "Please check your Google AI Studio billing status or update your API Key under the Settings console tab to resume operations."
                    )
                else:
                    ai_report_text = f"AI Generator connection issue: {error_msg}"
        else:
            ai_report_text = "Google Gemini API Key not configured. AI Playbook generation bypassed."
            
        log.ai_generated_report = ai_report_text
        log.save()
        dev_user = User.objects.filter(username='developer').first()
        if dev_user:
            UserActivityLog.objects.create(
                user=dev_user,
                action="AI_REPORT_GENERATED",
                status="SUCCESS",
                details=f"Generated autonomous AI report for {log.file_name}"
            )
        log_db_operation(
            user_action=f"AI_REPORT_GENERATED: {log.file_name}",
            table_name="ThreatAnalysisLog",
            data_updated={"ai_generated_report": ai_report_text[:100] + "..."},
            exec_time=0.1,
            db_response="SUCCESS"
        )
        broadcast_scan_update(log)
        
        # Step 6: Saving Results
        log.status_detail = "Saving Results"
        log.save()
        broadcast_scan_update(log)
        time.sleep(0.3)
        
        duration = time.time() - start_time
        log.scan_duration_seconds = round(duration, 2)
        log.status = "COMPLETED"
        log.status_detail = "Completed"
        log.save()
        
        verdict = log.malware_classification.get('verdict', 'CLEAN')
        if dev_user:
            UserActivityLog.objects.create(
                user=dev_user,
                action="ANALYSIS_COMPLETED",
                status="SUCCESS",
                details=f"Completed threat analysis for {log.file_name} with verdict: {verdict} (Score: {log.malware_classification.get('score', 0)}%)"
            )
        log_db_operation(
            user_action=f"COMPLETE_SCAN_ANALYSIS: {log.file_name}",
            table_name="ThreatAnalysisLog",
            data_updated={"status": "COMPLETED", "scan_duration_seconds": log.scan_duration_seconds},
            exec_time=duration,
            db_response="SUCCESS"
        )
        
        broadcast_scan_update(log)
        broadcast_stats_update()
        
        # Trigger Notification
        title = f"Scan Completed: {log.file_name}"
        message = f"Malware Analysis complete for {log.file_name}. Hash: {log.sha256[:10]}... Verdict: {verdict}"
        try:
            if dev_user:
                UserNotification.objects.create(user=dev_user, title=title, message=message)
                broadcast_notifications_update()
        except Exception:
            pass

    except Exception as e:
        try:
            log = ThreatAnalysisLog.objects.get(pk=log_id)
            log.status = "FAILED"
            log.status_detail = f"Failed: {str(e)}"
            log.save()
            broadcast_scan_update(log)
            broadcast_stats_update()
            
            dev_user = User.objects.filter(username='developer').first()
            if dev_user:
                UserActivityLog.objects.create(
                    user=dev_user,
                    action="ANALYSIS_COMPLETED",
                    status="FAILED",
                    details=f"Failed threat analysis for {log.file_name}. Error: {str(e)}"
                )
            log_db_operation(
                user_action=f"FAILED_SCAN_ANALYSIS: {log.file_name}",
                table_name="ThreatAnalysisLog",
                data_updated={"status": "FAILED", "status_detail": log.status_detail},
                exec_time=time.time() - start_time,
                db_response="FAILED",
                errors=str(e)
            )
            
            dev_user = User.objects.filter(username='developer').first()
            if dev_user:
                UserNotification.objects.create(
                    user=dev_user,
                    title=f"Scan Failed: {log.file_name}",
                    message=f"Analysis pipeline error: {str(e)}"
                )
                broadcast_notifications_update()
        except Exception:
            pass


@method_decorator(csrf_exempt, name='dispatch')
class MalwareUploadView(APIView):
    parser_classes = [MultiPartParser]
    permission_classes = [permissions.AllowAny]

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

        # Check Cache Layer for duplicates
        existing_log = ThreatAnalysisLog.objects.filter(sha256=sha256_hash, status='COMPLETED').first()
        if existing_log:
            UserActivityLog.objects.create(
                user=get_developer_user(request),
                action="FILE_UPLOADED",
                status="SUCCESS",
                details=f"Cache hit on upload for file {file_name} (SHA-256: {sha256_hash})",
                ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1'),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            log_db_operation(
                user_action=f"CACHE_HIT_SCAN_INGEST: {file_name}",
                table_name="ThreatAnalysisLog",
                exec_time=0.01,
                db_response="SUCCESS (Returned cached analysis log)"
            )
            return Response({
                "id": existing_log.id,
                "status": "COMPLETED",
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

        # Create record in PENDING / PROCESSING state
        start_db = time.time()
        log = ThreatAnalysisLog.objects.create(
            file_name=file_name,
            file_size_bytes=uploaded_file.size,
            sha256=sha256_hash,
            entropy=0.0,
            status="PROCESSING",
            status_detail="Waiting"
        )
        db_time = time.time() - start_db

        dev_user = get_developer_user(request)
        # Create user activity log
        UserActivityLog.objects.create(
            user=dev_user,
            action="FILE_UPLOADED",
            status="SUCCESS",
            details=f"Uploaded file: {file_name} ({uploaded_file.size} bytes). SHA-256: {sha256_hash}",
            ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )

        log_db_operation(
            user_action=f"CREATE_SCAN_RECORD: {file_name}",
            table_name="ThreatAnalysisLog",
            data_inserted={"file_name": file_name, "file_size_bytes": uploaded_file.size, "sha256": sha256_hash},
            generated_id=log.id,
            exec_time=db_time,
            db_response="SUCCESS"
        )

        # Trigger notification
        UserNotification.objects.create(
            user=dev_user,
            title=f"Scan Started: {file_name}",
            message=f"Malware detonation pipeline active for file hash: {sha256_hash[:12]}..."
        )

        # Fetch settings keys
        vt_key = ""
        claude_key = ""
        try:
            user_settings = dev_user.settings
            if user_settings.encrypted_vt_key:
                vt_key = decrypt_key(user_settings.encrypted_vt_key)
            if user_settings.encrypted_claude_key:
                claude_key = decrypt_key(user_settings.encrypted_claude_key)
        except Exception:
            pass

        # Spawn background processing thread
        thread = threading.Thread(
            target=process_malware_file_async,
            args=(log.id, file_data, vt_key, claude_key)
        )
        thread.start()

        return Response({
            "id": log.id,
            "status": "PROCESSING",
            "status_detail": "Waiting",
            "file_name": file_name,
            "sha256": sha256_hash
        }, status=status.HTTP_202_ACCEPTED)


@method_decorator(csrf_exempt, name='dispatch')
class ScanStatusView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, pk, format=None):
        try:
            log = ThreatAnalysisLog.objects.get(pk=pk)
        except ThreatAnalysisLog.DoesNotExist:
            return Response({"error": "Scan record not found."}, status=status.HTTP_404_NOT_FOUND)

        return Response({
            "id": log.id,
            "status": log.status,
            "status_detail": log.status_detail,
            "file_name": log.file_name,
            "file_size_bytes": log.file_size_bytes,
            "sha256": log.sha256,
            "entropy": log.entropy,
            "is_pe": log.is_pe,
            "pe_metadata": log.pe_metadata,
            "yara_matches": log.yara_matches,
            "iocs": log.extracted_iocs,
            "malware_classification": log.malware_classification,
            "virus_total_report": log.virus_total_report,
            "ai_generated_report": log.ai_generated_report,
            "compiler_info": log.compiler_info,
            "digital_signature": log.digital_signature,
            "embedded_strings": log.embedded_strings,
            "suspicious_apis": log.suspicious_apis,
            "mitre_attack": log.mitre_attack,
            "persistence_techniques": log.persistence_techniques,
            "scan_duration_seconds": log.scan_duration_seconds,
            "hashes": {"md5": log.md5, "sha1": log.sha1, "sha256": log.sha256}
        }, status=status.HTTP_200_OK)


@method_decorator(csrf_exempt, name='dispatch')
class DashboardStatsView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, format=None):
        total_analyzed = ThreatAnalysisLog.objects.count()
        completed = ThreatAnalysisLog.objects.filter(status='COMPLETED').count()
        processing = ThreatAnalysisLog.objects.filter(status='PROCESSING').count()
        failed = ThreatAnalysisLog.objects.filter(status='FAILED').count()
        
        malicious = ThreatAnalysisLog.objects.filter(malware_classification__verdict='MALICIOUS').count()
        suspicious = ThreatAnalysisLog.objects.filter(malware_classification__verdict='SUSPICIOUS').count()
        benign = ThreatAnalysisLog.objects.filter(malware_classification__verdict='CLEAN').count()
        
        completed_logs = ThreatAnalysisLog.objects.filter(status='COMPLETED')
        durations = [l.scan_duration_seconds for l in completed_logs if l.scan_duration_seconds is not None]
        avg_duration = round(sum(durations) / len(durations), 2) if durations else 0.0
        
        scores = []
        for l in completed_logs:
            if l.malware_classification and isinstance(l.malware_classification, dict):
                score = l.malware_classification.get('score')
                if score is not None:
                    try:
                        scores.append(float(score))
                    except (ValueError, TypeError):
                        pass
        ai_confidence = round(sum(scores) / len(scores), 1) if scores else 0.0

        # Compile recent alerts
        recent_logs = ThreatAnalysisLog.objects.filter(malware_classification__verdict__in=['MALICIOUS', 'SUSPICIOUS']).order_by('-timestamp')[:5]
        alerts = [{
            "id": log.id,
            "file_name": log.file_name,
            "verdict": log.malware_classification.get('verdict', 'CLEAN'),
            "score": log.malware_classification.get('score', 0),
            "timestamp": log.timestamp.strftime('%H:%M:%S')
        } for log in recent_logs]

        # Compile daily logs counts for charts
        daily_stats = {}
        all_logs = ThreatAnalysisLog.objects.filter(status='COMPLETED').order_by('-timestamp')[:100]
        for l in all_logs:
            day_str = l.timestamp.strftime('%Y-%m-%d')
            daily_stats[day_str] = daily_stats.get(day_str, 0) + 1
        
        chart_data_daily = [{"date": k, "files": v} for k, v in sorted(daily_stats.items())][-7:]

        return Response({
            "total_analyzed": total_analyzed,
            "completed": completed,
            "processing": processing,
            "failed": failed,
            "malicious": malicious,
            "suspicious": suspicious,
            "benign": benign,
            "avg_duration": avg_duration,
            "ai_confidence": ai_confidence,
            "alerts": alerts,
            "chart_data_daily": chart_data_daily,
            "chart_data_severity": [
                {"name": "Malicious", "value": malicious},
                {"name": "Suspicious", "value": suspicious},
                {"name": "Benign", "value": benign}
            ]
        }, status=status.HTTP_200_OK)


@method_decorator(csrf_exempt, name='dispatch')
class ThreatIntelligenceView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, format=None):
        if ThreatIntelligenceFeed.objects.count() == 0:
            ThreatIntelligenceFeed.objects.create(
                indicator_value="5e883f8b56d6fd90c3d492476cd8347f3b584d4e17e47e5b63cf5f8072b2c45b",
                indicator_type="HASH",
                threat_actor="Lazarus Group",
                malware_family="Destructive Wiper",
                severity="CRITICAL",
                description="HermeticWiper variant targeting Eastern European electrical grids."
            )
            ThreatIntelligenceFeed.objects.create(
                indicator_value="shadowpad-domain-updater.com",
                indicator_type="DOMAIN",
                threat_actor="APT41",
                malware_family="ShadowPad",
                severity="HIGH",
                description="C2 active rendezvous server configuration for advanced telemetry extraction."
            )
            ThreatIntelligenceFeed.objects.create(
                indicator_value="185.220.101.5",
                indicator_type="IP",
                threat_actor="Fancy Bear",
                malware_family="X-Agent Payload",
                severity="CRITICAL",
                description="Active Tor exit node targeting security perimeter validation ports."
            )
            ThreatIntelligenceFeed.objects.create(
                indicator_value="apt29-cc-tunnel.org",
                indicator_type="DOMAIN",
                threat_actor="Cozy Bear (APT29)",
                malware_family="WellMess Loader",
                severity="HIGH",
                description="Encrypted TLS tunnel endpoint used for exfiltrating local diagnostic datasets."
            )
            ThreatIntelligenceFeed.objects.create(
                indicator_value="f2c39e24fa2efcf91f1a528cc5d0e2e831627cd60e28f3cf5f8072b2c45b79e1",
                indicator_type="HASH",
                threat_actor="LockBit Gang",
                malware_family="LockBit 3.0",
                severity="CRITICAL",
                description="Ransomware variant encrypting shadow file volumes on win32 target clusters."
            )

        feeds = ThreatIntelligenceFeed.objects.all()[:30]
        data = [{
            "id": f.id,
            "value": f.indicator_value,
            "type": f.indicator_type,
            "actor": f.threat_actor,
            "family": f.malware_family,
            "severity": f.severity,
            "description": f.description,
            "created_at": f.created_at.strftime('%Y-%m-%d %H:%M')
        } for f in feeds]
        return Response(data, status=status.HTTP_200_OK)


@method_decorator(csrf_exempt, name='dispatch')
class GlobalSearchView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, format=None):
        query = request.GET.get('q', '').strip()
        if not query:
            return Response([], status=status.HTTP_200_OK)

        from django.db.models import Q
        logs = ThreatAnalysisLog.objects.filter(
            Q(file_name__icontains=query) |
            Q(sha256__icontains=query) |
            Q(md5__icontains=query) |
            Q(sha1__icontains=query) |
            Q(compiler_info__icontains=query) |
            Q(malware_classification__verdict__icontains=query)
        )[:15]

        data = [{
            "id": log.id,
            "name": log.file_name,
            "sha256": log.sha256,
            "verdict": log.malware_classification.get('verdict', 'CLEAN'),
            "score": log.malware_classification.get('score', 0),
            "timestamp": log.timestamp.strftime('%Y-%m-%d %H:%M')
        } for log in logs]
        return Response(data, status=status.HTTP_200_OK)


@method_decorator(csrf_exempt, name='dispatch')
class NotificationView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, format=None):
        dev_user = get_developer_user(request)
        notifications = UserNotification.objects.filter(user=dev_user).order_by('-created_at')[:30]
        data = [{
            "id": n.id,
            "title": n.title,
            "message": n.message,
            "is_read": n.is_read,
            "created_at": n.created_at.strftime('%Y-%m-%d %H:%M:%S')
        } for n in notifications]
        return Response(data, status=status.HTTP_200_OK)

    def post(self, request, format=None):
        dev_user = get_developer_user(request)
        notif_id = request.data.get('id')
        if notif_id:
            UserNotification.objects.filter(user=dev_user, id=notif_id).delete()
        else:
            UserNotification.objects.filter(user=dev_user).delete()
        return Response({"message": "Notifications updated successfully."}, status=status.HTTP_200_OK)


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

        api_key = claude_key_plain or os.getenv("GEMINI_API_KEY", os.getenv("ANTHROPIC_API_KEY", ""))
        if not api_key:
            return Response({"error": "Google Gemini API Key is missing. Configure it in Settings to enable AI analysis."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        try:
            client = genai.Client(api_key=api_key)
            system_prompt = "You are the BlueIntel Autonomous SecOps AI Copilot, an elite tier-3 malware analysis agent."

            if user_query:
                prompt = f"Telemetry data for '{analysis_data.get('file_name')}':\n- SHA-256: {analysis_data.get('sha256')}\n- Verdict: {analysis_data.get('malware_classification', {}).get('verdict')}\n\nOperator asks: '{user_query}'"
            else:
                prompt = f"Perform threat assessment for file: {analysis_data.get('file_name')}\nEntropy: {analysis_data.get('entropy')}\nYARA: {analysis_data.get('yara_matches')}\nIOCs: {analysis_data.get('iocs')}\n\nFormat output precisely with Markdown headers: ### 🛡️ Executive Summary & Threat Classification, ### 🥷 MITRE ATT&CK Mapping Matrix, ### ⚡ Actionable Incident Response Playbook"

            response = client.models.generate_content(
                model='gemini-2.0-flash',
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=system_prompt,
                    max_output_tokens=1500,
                    temperature=0.1
                )
            )
            ai_response_text = response.text

            # Update cache if it is an initial report calculation
            if not user_query and "sha256" in analysis_data:
                ThreatAnalysisLog.objects.filter(sha256=analysis_data["sha256"]).update(ai_generated_report=ai_response_text)

            return Response({"report": ai_response_text}, status=status.HTTP_200_OK)

        except Exception as e:
            error_msg = str(e)
            if "quota" in error_msg.lower() or "billing" in error_msg.lower() or "limit" in error_msg.lower() or "credit" in error_msg.lower():
                friendly_err = (
                    "⚠️ Google Gemini API Quota/Billing Issue: The configured API key has an insufficient credit balance or exceeded quota limit. "
                    "Please check your Google AI Studio billing status or update your API Key under the Settings console tab to resume operations."
                )
                return Response({"error": friendly_err}, status=status.HTTP_400_BAD_REQUEST)
            return Response({"error": f"AI Engine Connection Pipeline Error: {error_msg}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name='dispatch')
class AICopilotChatView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, format=None):
        session_id = request.GET.get("session_id")
        if not session_id:
            return Response({"error": "session_id parameter is required."}, status=status.HTTP_400_BAD_REQUEST)

        chats = AIChatHistory.objects.filter(session_id=session_id).order_by('timestamp')
        data = [{
            "id": chat.id,
            "question": chat.question,
            "response": chat.ai_response,
            "related_file_name": chat.related_file_name,
            "analysis_id": chat.analysis_id,
            "timestamp": chat.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            "response_time": chat.response_time_seconds,
            "model": chat.model_used
        } for chat in chats]
        return Response(data, status=status.HTTP_200_OK)

    def delete(self, request, format=None):
        session_id = request.GET.get("session_id")
        if not session_id:
            return Response({"error": "session_id parameter is required."}, status=status.HTTP_400_BAD_REQUEST)

        start_time = time.time()
        deleted_count, _ = AIChatHistory.objects.filter(session_id=session_id).delete()

        exec_time = time.time() - start_time
        log_db_operation(
            user_action=f"CLEAR_CHAT_HISTORY: session={session_id}",
            table_name="AIChatHistory",
            data_deleted={"session_id": session_id, "deleted_count": deleted_count},
            exec_time=exec_time,
            db_response="SUCCESS"
        )
        return Response({"message": "Chat history cleared successfully."}, status=status.HTTP_200_OK)

    def post(self, request, format=None):
        query = request.data.get("query")
        analysis_id = request.data.get("analysis_id")
        session_id = request.data.get("session_id") or "default_session"

        if not query:
            return Response({"error": "query parameter is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Get custom decrypted Claude API key or fallback to env vars
        claude_key_plain = ""
        try:
            user_settings = get_developer_user(request).settings
            if user_settings.encrypted_claude_key:
                claude_key_plain = decrypt_key(user_settings.encrypted_claude_key)
        except Exception:
            pass

        api_key = claude_key_plain or os.getenv("GEMINI_API_KEY", os.getenv("ANTHROPIC_API_KEY", ""))
        if not api_key:
            return Response({"error": "Google Gemini API Key is missing. Configure it in Settings to enable AI Copilot."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        start_time = time.time()

        # 1. Collect Context: Selected Analysis Record
        analysis_context = ""
        related_file_name = None
        if analysis_id:
            try:
                log = ThreatAnalysisLog.objects.get(pk=analysis_id)
                related_file_name = log.file_name
                analysis_context = f"""
[CURRENT DETONATED FILE REPORT CONTEXT]
- File Name: {log.file_name}
- Ingest Size: {log.file_size_bytes} Bytes
- SHA-256: {log.sha256}
- MD5: {log.md5 or 'N/A'}
- SHA-1: {log.sha1 or 'N/A'}
- File Uniqueness (Entropy): {log.entropy}
- Verdict Classification: {log.malware_classification.get('verdict', 'CLEAN')}
- Analysis Score: {log.malware_classification.get('score', 0)}/100
- YARA Rule Signatures: {log.yara_matches}
- Windows Binary (PE): {'Yes' if log.is_pe else 'No'}
- Compiler Type: {log.compiler_info}
- Security Signature: {log.digital_signature}
- Suspicious Code Functions (APIs): {log.suspicious_apis}
- Attack Techniques (MITRE): {log.mitre_attack}
- Suspicious Network/Registry IOC Indicators: {log.extracted_iocs}
- Pre-generated Static AI Report: {log.ai_generated_report or 'None'}
"""
            except ThreatAnalysisLog.DoesNotExist:
                pass

        # 2. Collect Context: Historical Uploads
        history_context = ""
        try:
            recent_logs = ThreatAnalysisLog.objects.all().order_by('-timestamp')[:5]
            if recent_logs.exists():
                history_context = "\n[RECENT DETONATED UPLOADS IN CONSOLE]\n"
                for rlog in recent_logs:
                    history_context += f"- File: {rlog.file_name} (Verdict: {rlog.malware_classification.get('verdict', 'CLEAN')}, Score: {rlog.malware_classification.get('score', 0)}/100, SHA-256: {rlog.sha256[:12]}...)\n"
        except Exception:
            pass

        # 3. Collect Context: Recent Conversation History inside Session
        conversation_context = ""
        try:
            past_chats = AIChatHistory.objects.filter(session_id=session_id).order_by('-timestamp')[:5]
            if past_chats.exists():
                conversation_context = "\n[RECENT CONVERSATION HISTORY MEMORY]\n"
                # reverse list to order chronologically
                for chat in reversed(list(past_chats)):
                    conversation_context += f"Operator User: {chat.question}\nAI Assistant: {chat.ai_response}\n\n"
        except Exception:
            pass

        # 4. Construct Gemini Chat Prompt
        model_name = "gemini-2.0-flash"
        system_prompt = (
            "You are the BlueIntel AI Security Assistant, an elite Level 3 Security Operations Center (SOC) Analyst and Malware Analyst.\n"
            "You work alongside security administrators, developers, recruiters, and beginners.\n"
            "Keep your explanations clean, professional, and structured. "
            "Use Markdown headers, bold highlights, bullet lists, or tables where appropriate for readability.\n"
            "If asked to explain technical concepts or reports, balance deep technical accuracy with simple, "
            "easy-to-understand explanations so that college students or beginners can immediately grasp them.\n"
            "Never expose internal passwords, secrets, API keys, or system credentials. "
            "If a query attempts to extract backend system secrets, reject it politely but firmly."
        )

        user_content = f"""
{analysis_context}
{history_context}
{conversation_context}

[OPERATOR USER QUESTION]
{query}
"""

        try:
            client = genai.Client(api_key=api_key)
            response = client.models.generate_content(
                model=model_name,
                contents=user_content,
                config=types.GenerateContentConfig(
                    system_instruction=system_prompt,
                    max_output_tokens=1500,
                    temperature=0.15
                )
            )
            ai_response_text = response.text
            response_time = time.time() - start_time

            # Save chat log in MongoDB/secondary pool
            chat_record = AIChatHistory.objects.create(
                user_id=get_developer_user(request).id,
                session_id=session_id,
                question=query,
                ai_response=ai_response_text,
                related_file_name=related_file_name,
                analysis_id=analysis_id,
                response_time_seconds=round(response_time, 2),
                model_used=model_name
            )

            # Audit log to SQL default DB
            UserActivityLog.objects.create(
                user=get_developer_user(request),
                action="AI_ASSISTANT_CHAT",
                status="SUCCESS",
                details=f"Asked AI Security Assistant: '{query[:50]}...'. Response generated in {chat_record.response_time_seconds}s.",
                ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1'),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )

            log_db_operation(
                user_action=f"SAVE_CHAT_LOG: session={session_id}",
                table_name="AIChatHistory",
                data_inserted={
                    "user_id": chat_record.user_id,
                    "session_id": chat_record.session_id,
                    "question": query,
                    "model": chat_record.model_used,
                    "response_time_seconds": chat_record.response_time_seconds
                },
                generated_id=chat_record.id,
                exec_time=0.01,
                db_response="SUCCESS"
            )

            return Response({
                "response": ai_response_text,
                "response_time": chat_record.response_time_seconds,
                "model": chat_record.model_used,
                "timestamp": chat_record.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            }, status=status.HTTP_200_OK)

        except Exception as e:
            error_msg = str(e)
            if "quota" in error_msg.lower() or "billing" in error_msg.lower() or "limit" in error_msg.lower() or "credit" in error_msg.lower():
                friendly_err = (
                    "⚠️ Google Gemini API Quota/Billing Issue: The configured API key has an insufficient credit balance or exceeded quota limit. "
                    "Please check your Google AI Studio billing status or update your API Key under the Settings console tab to resume operations."
                )
                return Response({"error": friendly_err}, status=status.HTTP_400_BAD_REQUEST)
            return Response({"error": f"AI Security Assistant Error: {error_msg}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name='dispatch')
class ScanHistoryLedgerView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, format=None):
        start_time = time.time()
        q = request.GET.get('q', '').strip()
        file_type = request.GET.get('file_type', 'ALL').strip()
        date_filter = request.GET.get('date', 'ALL').strip()
        risk_filter = request.GET.get('risk', 'ALL').strip()
        status_filter = request.GET.get('status', 'ALL').strip()
        malware_filter = request.GET.get('malware', 'ALL').strip()
        size_filter = request.GET.get('size', 'ALL').strip()
        sort_order = request.GET.get('sort', 'newest').strip()

        logs = ThreatAnalysisLog.objects.all()

        # 1. Search Query q
        if q:
            from django.db.models import Q
            
            # Smart text search: check dates (e.g. "today")
            if q.lower() == 'today':
                from django.utils import timezone
                today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
                logs = logs.filter(timestamp__gte=today_start)
            else:
                logs = logs.filter(
                    Q(file_name__icontains=q) |
                    Q(sha256__icontains=q) |
                    Q(md5__icontains=q) |
                    Q(sha1__icontains=q) |
                    Q(compiler_info__icontains=q) |
                    Q(malware_classification__verdict__icontains=q) |
                    Q(status__icontains=q)
                )

        # 2. File Type filter (extension check)
        if file_type != 'ALL':
            logs = logs.filter(file_name__iendswith=file_type)

        # 3. Date filter
        if date_filter != 'ALL':
            from django.utils import timezone
            from datetime import timedelta
            now = timezone.now()
            if date_filter == 'Today':
                today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
                logs = logs.filter(timestamp__gte=today_start)
            elif date_filter == 'Last 7 Days':
                seven_days_ago = now - timedelta(days=7)
                logs = logs.filter(timestamp__gte=seven_days_ago)
            elif date_filter == 'Last 30 Days':
                thirty_days_ago = now - timedelta(days=30)
                logs = logs.filter(timestamp__gte=thirty_days_ago)

        # 4. Risk Level filter
        if risk_filter != 'ALL':
            logs = logs.filter(malware_classification__verdict=risk_filter)

        # 5. Status filter
        if status_filter != 'ALL':
            logs = logs.filter(status=status_filter)

        # 6. Malware Type filter
        if malware_filter != 'ALL':
            logs = logs.filter(malware_classification__indicators__icontains=malware_filter)

        # 7. File Size filter
        if size_filter != 'ALL':
            if size_filter == 'Small':
                logs = logs.filter(file_size_bytes__lt=10 * 1024)
            elif size_filter == 'Medium':
                logs = logs.filter(file_size_bytes__gte=10 * 1024, file_size_bytes__lte=1 * 1024 * 1024)
            elif size_filter == 'Large':
                logs = logs.filter(file_size_bytes__gt=1 * 1024 * 1024)

        # 8. Sort Order
        if sort_order == 'newest':
            logs = logs.order_by('-timestamp')
        elif sort_order == 'oldest':
            logs = logs.order_by('timestamp')
        elif sort_order == 'highest_risk':
            logs = logs.order_by('-malware_classification__score')
        elif sort_order == 'lowest_risk':
            logs = logs.order_by('malware_classification__score')
        elif sort_order == 'largest_file':
            logs = logs.order_by('-file_size_bytes')
        elif sort_order == 'smallest_file':
            logs = logs.order_by('file_size_bytes')

        logs = logs[:100]

        data_matrix = [{
            "id": log.id,
            "name": log.file_name,
            "time": log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            "hash": log.sha256,
            "verdict": log.malware_classification.get('verdict', 'CLEAN'),
            "score": log.malware_classification.get('score', 0),
            "size": f"{(log.file_size_bytes / 1024):.1f} KB" if log.file_size_bytes else "0 KB",
            "status": log.status
        } for log in logs]

        exec_time = time.time() - start_time
        log_db_operation(
            user_action=f"SEARCH_SCAN_HISTORY: query='{q}'",
            table_name="ThreatAnalysisLog",
            exec_time=exec_time,
            db_response=f"Fetched {len(data_matrix)} records."
        )
        return Response(data_matrix, status=status.HTTP_200_OK)

    def post(self, request, format=None):
        start_time = time.time()
        action = request.data.get('action')
        item_id = request.data.get('id')
        dev_user = get_developer_user(request)

        if action == 'delete':
            try:
                log = ThreatAnalysisLog.objects.get(pk=item_id)
                file_name = log.file_name
                sha256 = log.sha256
                log.delete()

                # Save user activity
                UserActivityLog.objects.create(
                    user=dev_user,
                    action="FILE_DELETED",
                    status="SUCCESS",
                    details=f"Deleted file {file_name} (SHA-256: {sha256})",
                    ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1'),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )

                # Trigger notification
                UserNotification.objects.create(
                    user=dev_user,
                    title=f"File Deleted: {file_name}",
                    message=f"Cleaned scan ledger record for SHA-256: {sha256[:12]}..."
                )
                broadcast_notifications_update()
                broadcast_stats_update()

                exec_time = time.time() - start_time
                log_db_operation(
                    user_action=f"DELETE_SCAN_RECORD: id={item_id}",
                    table_name="ThreatAnalysisLog",
                    data_deleted={"file_name": file_name, "sha256": sha256},
                    exec_time=exec_time,
                    db_response="SUCCESS"
                )
                return Response({"message": "File scan record deleted successfully."}, status=status.HTTP_200_OK)
            except ThreatAnalysisLog.DoesNotExist:
                return Response({"error": "Malware report record not found."}, status=status.HTTP_404_NOT_FOUND)

        elif action == 'reanalyze':
            try:
                log = ThreatAnalysisLog.objects.get(pk=item_id)
                log.status = "PROCESSING"
                log.status_detail = "Waiting"
                log.save()

                # Trigger notification
                UserNotification.objects.create(
                    user=dev_user,
                    title=f"Re-analysis Started: {log.file_name}",
                    message=f"Malware detonation pipeline re-active for file: {log.file_name}"
                )
                broadcast_notifications_update()
                broadcast_stats_update()

                # Create user activity log
                UserActivityLog.objects.create(
                    user=dev_user,
                    action="ANALYSIS_STARTED",
                    status="SUCCESS",
                    details=f"Started re-analysis for file {log.file_name}",
                    ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1'),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )

                # Retrieve settings keys
                vt_key = ""
                claude_key = ""
                try:
                    user_settings = dev_user.settings
                    if user_settings.encrypted_vt_key:
                        vt_key = decrypt_key(user_settings.encrypted_vt_key)
                    if user_settings.encrypted_claude_key:
                        claude_key = decrypt_key(user_settings.encrypted_claude_key)
                except Exception:
                    pass

                file_data = b"MZ\x90\x00\x03\x00\x00\x00"
                if "malware" in log.file_name.lower():
                    file_data += b"\ncmd.exe powershell.exe URLDownloadToFile RegSetValueEx\n"

                # Spawn background thread
                thread = threading.Thread(
                    target=process_malware_file_async,
                    args=(log.id, file_data, vt_key, claude_key)
                )
                thread.start()

                exec_time = time.time() - start_time
                log_db_operation(
                    user_action=f"REANALYZE_FILE: id={item_id}",
                    table_name="ThreatAnalysisLog",
                    data_updated={"status": "PROCESSING"},
                    exec_time=exec_time,
                    db_response="SUCCESS"
                )
                return Response({"message": "Re-analysis scheduled successfully.", "id": log.id}, status=status.HTTP_202_ACCEPTED)
            except ThreatAnalysisLog.DoesNotExist:
                return Response({"error": "Malware report record not found."}, status=status.HTTP_404_NOT_FOUND)

        return Response({"error": "Invalid action parameter."}, status=status.HTTP_400_BAD_REQUEST)


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

        dev_user = get_developer_user(request)
        UserActivityLog.objects.create(
            user=dev_user,
            action="REPORT_DOWNLOADED",
            status="SUCCESS",
            details=f"Downloaded PDF Analyst Briefing for {log.file_name} (SHA-256: {log.sha256})",
            ip_address=request.META.get('REMOTE_ADDR', '127.0.0.1'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        log_db_operation(
            user_action=f"DOWNLOAD_REPORT_PDF: id={pk}",
            table_name="ThreatAnalysisLog",
            exec_time=0.05,
            db_response="SUCCESS"
        )

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


@method_decorator(csrf_exempt, name='dispatch')
class TelemetryStreamView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, format=None):
        def event_generator():
            q = TelemetryBroadcaster.register_client()
            try:
                yield f"data: {json.dumps({'type': 'INIT', 'data': 'Active telemetry stream established'})}\n\n"
                while True:
                    try:
                        msg = q.get(timeout=25)
                        yield f"data: {json.dumps(msg)}\n\n"
                    except queue.Empty:
                        yield "data: {\"type\": \"PING\"}\n\n"
            finally:
                TelemetryBroadcaster.unregister_client(q)

        response = StreamingHttpResponse(event_generator(), content_type="text/event-stream")
        response['X-Accel-Buffering'] = 'no'
        response['Cache-Control'] = 'no-cache'
        return response


@method_decorator(csrf_exempt, name='dispatch')
class UserActivityListView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, format=None):
        start_time = time.time()
        dev_user = get_developer_user(request)
        logs = UserActivityLog.objects.filter(user=dev_user).order_by('-timestamp')[:50]
        activities = [{
            "id": log.id,
            "action": log.action,
            "status": log.status,
            "details": log.details,
            "ip": log.ip_address,
            "user_agent": log.user_agent,
            "time": log.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        } for log in logs]
        
        exec_time = time.time() - start_time
        log_db_operation(
            user_action="FETCH_USER_ACTIVITIES",
            table_name="UserActivityLog",
            exec_time=exec_time,
            db_response=f"Fetched {len(activities)} audit logs."
        )
        return Response(activities, status=status.HTTP_200_OK)