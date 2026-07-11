import requests
import os

class VirusTotalService:
    @staticmethod
    def query_file_reputation(file_hash: str, api_key: str = None) -> dict:
        """
        Queries the VirusTotal V3 API to retrieve threat reputation data for a file hash.
        If no API key is provided, check environment variables.
        """
        vt_key = api_key or os.getenv('VIRUSTOTAL_API_KEY', '')
        if not vt_key:
            return {
                "status": "unconfigured",
                "message": "VirusTotal API key is not configured. Add it in operator Settings to activate real-world reputation checks."
            }

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {
            "accept": "application/json",
            "x-apikey": vt_key
        }

        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                json_data = response.json()
                attributes = json_data.get("data", {}).get("attributes", {})
                last_analysis_stats = attributes.get("last_analysis_stats", {})
                reputation = attributes.get("reputation", 0)
                
                # Parse engine detections
                malicious = last_analysis_stats.get("malicious", 0)
                harmless = last_analysis_stats.get("harmless", 0)
                suspicious = last_analysis_stats.get("suspicious", 0)
                undetected = last_analysis_stats.get("undetected", 0)
                
                return {
                    "status": "success",
                    "reputation": reputation,
                    "stats": {
                        "malicious": malicious,
                        "harmless": harmless,
                        "suspicious": suspicious,
                        "undetected": undetected
                    },
                    "type_description": attributes.get("type_description", "Unknown Type"),
                    "tags": attributes.get("tags", [])[:5]
                }
            elif response.status_code == 404:
                return {
                    "status": "not_found",
                    "message": "File signature was not found in VirusTotal's threat database repository."
                }
            else:
                return {
                    "status": "error",
                    "message": f"VirusTotal API responded with status code: {response.status_code}"
                }
        except requests.exceptions.Timeout:
            return {
                "status": "error",
                "message": "VirusTotal API query timed out. Check network proxy filters."
            }
        except requests.exceptions.RequestException as e:
            return {
                "status": "error",
                "message": f"VirusTotal network connection error: {str(e)}"
            }
