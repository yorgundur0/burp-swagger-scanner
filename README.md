# Burp Swagger Scanner

This Burp Suite extension automatically discovers Swagger (OpenAPI) documentation endpoints during passive scans (analyzing each host only once) and reports them as custom issues. Issues appear in the **Issues** or **Live Issues** tab with medium severity and clear remediation advice.  

## Features

- **Single Parse per Host**  
  Analyzes each host only once for Swagger/OpenAPI JSON or documentation during passive scans.
- **Custom Issue Reporting**  
  Flags “Swagger Endpoint Found” or “Possible Swagger Documentation Found,” with medium severity.
- **Confidence & Visibility**  
  Uses `getConfidence()` = `"Certain"` and a non-zero `getIssueType()`, ensuring findings are visible in Live Issues.
- **Remediation Advice**  
  Advises users to restrict or remove public Swagger documentation for better security.

## Installation

1. **Download**  
   Clone or download this repository, then locate the `swagger-scanner.py` file.
2. **Load into Burp**  
   - Go to **Extender** → **Extensions** → **Add**  
   - Select **Extension type** = **Python** and choose `swagger-scanner.py`
3. **Configuration**  
   Ensure Jython standalone is configured in Burp if necessary. Check **Extender** → **Extensions** → **Output** for logs.

## Usage

1. **Passive Scan**  
   Start Burp’s passive scanning (e.g., by proxying traffic). For each new host, the extension attempts to parse Swagger paths once.
2. **Issues Tab**  
   Swagger docs discovered are reported as custom medium-severity issues with “Certain” confidence.
3. **Remediation**  
   Remove or restrict access to these docs. Use authentication, IP whitelisting, or remove them from production altogether.

## License

```text
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software") ...
(Include full MIT text here)
