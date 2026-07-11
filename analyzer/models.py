from django.db import models
from django.contrib.auth.models import User

class ThreatAnalysisLog(models.Model):
    # Core File Metadata
    file_name = models.CharField(max_length=255)
    file_size_bytes = models.BigIntegerField()
    sha256 = models.CharField(max_length=64, unique=True)
    md5 = models.CharField(max_length=32, blank=True, null=True)
    sha1 = models.CharField(max_length=40, blank=True, null=True)
    entropy = models.FloatField()
    is_pe = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    # Processing state and duration
    status = models.CharField(max_length=50, default='COMPLETED')  # PENDING, PROCESSING, COMPLETED, FAILED
    status_detail = models.CharField(max_length=255, default='Completed successfully.')  # E.g. 'Running YARA Rules'
    scan_duration_seconds = models.FloatField(default=0.0)
    
    # Extra static binary headers
    compiler_info = models.CharField(max_length=255, blank=True, null=True)
    digital_signature = models.CharField(max_length=255, blank=True, null=True)
    embedded_strings = models.JSONField(default=list, blank=True)
    suspicious_apis = models.JSONField(default=list, blank=True)
    mitre_attack = models.JSONField(default=list, blank=True)
    persistence_techniques = models.JSONField(default=list, blank=True)
    
    # Complex Telemetry Payload Fields (Stored securely as structural JSON)
    pe_metadata = models.JSONField(default=dict, blank=True)
    yara_matches = models.JSONField(default=list, blank=True)
    extracted_iocs = models.JSONField(default=dict, blank=True)
    malware_classification = models.JSONField(default=dict, blank=True)
    
    # VirusTotal Scanning Intel Integration Field
    virus_total_report = models.JSONField(default=dict, blank=True)
    
    # AI Executive Knowledge Base Store
    ai_generated_report = models.TextField(blank=True, null=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.file_name} - {self.malware_classification.get('verdict', 'UNKNOWN')}"


class ThreatIntelligenceFeed(models.Model):
    indicator_value = models.CharField(max_length=255, unique=True)  # Hash, IP, or Domain
    indicator_type = models.CharField(max_length=50)  # HASH, IP, DOMAIN
    threat_actor = models.CharField(max_length=100, default='UNKNOWN')
    malware_family = models.CharField(max_length=100, default='UNKNOWN')
    severity = models.CharField(max_length=20, default='HIGH')  # CRITICAL, HIGH, MEDIUM, LOW
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.indicator_type}: {self.indicator_value} ({self.malware_family})"


# --- NEW ENTERPRISE TELEMETRY AUDIT MODELS ---

class UserOTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='otps')
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    resend_attempts = models.IntegerField(default=0)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"OTP for {self.user.email} (Expires: {self.expires_at})"


class UserActivityLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name='activities')
    action = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        caller = self.user.username if self.user else "Anonymous"
        return f"{caller} - {self.action} at {self.timestamp}"


class UserNotification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    title = models.CharField(max_length=255)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Notification for {self.user.username}: {self.title}"


class UserSetting(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='settings')
    theme = models.CharField(max_length=20, default='dark')
    enable_notifications = models.BooleanField(default=True)
    
    # Encrypted API Keys stored via AES Cryptography Fernet blocks
    encrypted_vt_key = models.TextField(blank=True, null=True)
    encrypted_claude_key = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"Settings for {self.user.username}"