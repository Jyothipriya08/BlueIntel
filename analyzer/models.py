from django.db import models

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
    
    # Complex Telemetry Payload Fields (Stored securely as structural JSON)
    pe_metadata = models.JSONField(default=dict, blank=True)
    yara_matches = models.JSONField(default=list, blank=True)
    extracted_iocs = models.JSONField(default=dict, blank=True)
    malware_classification = models.JSONField(default=dict, blank=True)
    
    # AI Executive Knowledge Base Store
    ai_generated_report = models.TextField(blank=True, null=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.file_name} - {self.malware_classification.get('verdict', 'UNKNOWN')}"