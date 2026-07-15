import os
import random
import string

def main():
    # Safe simulated IOCs and YARA signatures
    safe_text = """
    %PDF-1.4
    % BlueIntel Malware Infiltration & Detonation Ingest Test File.
    % This is a safe educational threat emulation payload.
    % 
    % INDICATORS OF COMPROMISE:
    % C2 Network Host: 185.220.101.44
    % C2 DNS Hostname: threat-detonation-gateway.org
    % Persistent registry key: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware_trigger
    % 
    % SYSTEM CALL STRINGS:
    % CMD_TRIGGER: cmd.exe
    % POWERSHELL_TRIGGER: powershell.exe
    % NETWORK_DOWNLOAD_API: URLDownloadToFile
    % REGISTRY_MUTATION_API: RegSetValueEx
    """

    # Generate a large high-entropy block to simulate packer / encryption noise
    # This triggers the high entropy static heuristic rules (> 7.2 Shannon entropy)
    random.seed(42)
    random_pool = string.ascii_letters + string.digits + "+/="
    high_entropy_data = "".join(random.choice(random_pool) for _ in range(8000))

    # Compile bytes
    pdf_bytes = f"{safe_text}\n%--ENTROPY_BUFFER--\n%{high_entropy_data}\n%%EOF".encode('utf-8')

    output_filename = "safe_malware_education.pdf"
    with open(output_filename, "wb") as f:
        f.write(pdf_bytes)

    print(f"Generated simulated threat file: {os.path.abspath(output_filename)}")
    print(f"File Size: {len(pdf_bytes)} bytes")

if __name__ == "__main__":
    main()
