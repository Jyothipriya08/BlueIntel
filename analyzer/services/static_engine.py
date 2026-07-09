import hashlib
import re
import pefile
import math

class StaticAnalysisEngine:
    @staticmethod
    def calculate_hashes(file_bytes):
        """Generates a complete cryptographic fingerprint registry."""
        return {
            "md5": hashlib.md5(file_bytes).hexdigest(),
            "sha1": hashlib.sha1(file_bytes).hexdigest(),
            "sha256": hashlib.sha256(file_bytes).hexdigest()
        }

    @staticmethod
    def calculate_entropy(data):
        """Calculates Shannon Entropy to discover packed or encrypted code blocks."""
        if not data:
            return 0.0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return round(entropy, 4)

    @staticmethod
    def extract_strings_and_iocs(file_bytes):
        """Parses raw text strings and automatically classifies host/network IOCs."""
        # Extract readable ASCII/Unicode strings (minimum 4 characters)
        strings = re.findall(b"[ -~]{4,}", file_bytes)
        decoded_strings = [s.decode('ascii', errors='ignore') for s in strings]

        # Standard regex maps for IOC extraction
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        domain_pattern = r'\b(?:[a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}\b'
        registry_pattern = r'\b(HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[a-zA-Z0-9_\\]+\b'

        iocs = {
            "ips": list(set(re.findall(ip_pattern, "\n".join(decoded_strings)))),
            "domains": list(set([d for d in re.findall(domain_pattern, "\n".join(decoded_strings)) if not d.endswith(('.dll', '.exe', '.sys'))])),
            "registry_keys": list(set(re.findall(registry_pattern, "\n".join(decoded_strings))))
        }
        return decoded_strings[:100], iocs  # Return first 100 strings to keep payload fast

    @classmethod
    def analyze(cls, file_bytes, filename):
        """Master orchestration framework for static payload parsing."""
        hashes = cls.calculate_hashes(file_bytes)
        entropy = cls.calculate_entropy(file_bytes)
        strings, iocs = cls.extract_strings_and_iocs(file_bytes)
        
        is_pe = file_bytes.startswith(b'MZ')
        pe_metadata = {}

        if is_pe:
            try:
                pe = pefile.PE(data=file_bytes)
                pe_metadata = {
                    "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                    "subsystem": pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, "UNKNOWN"),
                    "sections": [
                        {
                            "name": sec.Name.decode('utf-8', errors='ignore').strip('\x00'),
                            "virtual_size": hex(sec.Misc_VirtualSize),
                            "raw_size": hex(sec.SizeOfRawData)
                        } for sec in pe.sections
                    ]
                }
            except Exception:
                pe_metadata = {"error": "Corrupt or unparseable PE header structures."}

        # Simple classification heuristics rule logic
        malware_score = 0
        malware_indicators = []

        if entropy > 7.2:
            malware_score += 40
            malware_indicators.append("High entropy detected (Likely Packed/Obfuscated)")
        if len(iocs["ips"]) > 0 or len(iocs["domains"]) > 0:
            malware_score += 35
            malware_indicators.append("Embedded hardcoded C2 Network configurations discovered")
        if is_pe and pe_metadata.get("subsystem") == "IMAGE_SUBSYSTEM_NATIVE":
            malware_score += 20
            malware_indicators.append("Executes as a kernel driver asset block")

        return {
            "file_name": filename,
            "file_size_bytes": len(file_bytes),
            "hashes": hashes,
            "entropy": entropy,
            "is_pe": is_pe,
            "pe_metadata": pe_metadata,
            "iocs": iocs,
            "malware_classification": {
                "verdict": "MALICIOUS" if malware_score >= 50 else "SUSPICIOUS" if malware_score >= 20 else "CLEAN",
                "score": min(malware_score, 100),
                "indicators": malware_indicators
            }
        }