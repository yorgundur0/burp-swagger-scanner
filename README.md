# Dynamic Swagger Scanner

This Burp Suite extension performs **passive scanning** to locate publicly accessible Swagger (OpenAPI) documentation. Once discovered, it flags the domain with a custom security issue labeled “Swagger Endpoint Found” or “Possible Swagger Documentation Found.” The extension uses a **single pass** approach per host, preventing repeated checks and infinite path nesting.

## Features

- **Passive Scanner**  
  Implements `IBurpExtender` and `IScannerCheck` with `doPassiveScan()` to passively discover Swagger files.
- **One-Time Parsing**  
  Tracks whether Swagger has been found for a given host, avoiding repeated scans or loops.
- **Remediation Advice**  
  Adds medium-severity issues with suggestions to restrict or remove sensitive Swagger endpoints.

## Installation

1. **Obtain**  
   Download the `swagger-scanner.py` file from this repository or your local source.
2. **Load into Burp**  
   - Open **Extender** → **Extensions** → **Add**  
   - Select **Extension type** = **Python** and choose `swagger-scanner.py`
3. **Confirm Setup**  
   - If using Python-based extensions, verify Jython is configured.  
   - Watch **Extender** → **Extensions** → **Output** for logs or errors.

## Usage

1. **Enable Passive Scanning**  
   Start a normal crawl or browse through Burp Proxy. Each new host is parsed once in the background.
2. **Check Issues**  
   Found Swagger docs appear in **Issues** (Live Issues) with “Medium” severity and “Certain” confidence.
3. **Remediation**  
   Limit or remove public access to discovered Swagger files. Use authentication, IP restrictions, or remove from production.

## Code Snippet

```python
from burp import IBurpExtender, IScannerCheck, IScanIssue
from java.net import URL
from array import array
import json
import threading

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.extension_name = "Dynamic Swagger Scanner (Passive Scan)"
        self._callbacks.setExtensionName(self.extension_name)
        self._callbacks.registerScannerCheck(self)
        self.found_swaggers = set()
        self.no_swagger_paths = set()
        self.lock = threading.RLock()

    def doPassiveScan(self, baseRequestResponse):
        analyzed_req = self._helpers.analyzeRequest(baseRequestResponse)
        host = analyzed_req.getUrl().getHost()
        path = analyzed_req.getUrl().getPath() or "/"
        with self.lock:
            if host in self.found_swaggers:
                return None
            if (host, path) in self.no_swagger_paths:
                return None
            self.try_parse_swagger_with_path(baseRequestResponse, host, path)
        return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return []

    def try_parse_swagger_with_path(self, baseRequestResponse, host, path):
        # ...
        # (shortened for brevity)
        pass

    def create_issue_manual(self, baseRequestResponse, full_url, issue_name, issue_detail, severity):
        # ...
        pass

    def fetch_url(self, url):
        # ...
        pass

    def parse_swagger(self, swagger_data):
        # ...
        pass

    def is_json(self, txt):
        # ...
        pass

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return 0

class CustomScanIssue(IScanIssue):
    # ...
    pass
