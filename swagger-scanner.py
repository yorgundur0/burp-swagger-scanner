# -*- coding: utf-8 -*-
from burp import IBurpExtender, IScannerCheck, IScanIssue
from java.net import URL
import json

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        # Integration with Burp API
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Dynamic Swagger Scanner")

        # Register the plugin to ScannerCheck
        self._callbacks.registerScannerCheck(self)

        # To store Swagger endpoints
        self.swagger_endpoints = {}

        # List that tracks issues created for duplicate issue control
        self.created_issues = []

    def doPassiveScan(self, baseRequestResponse):
        analyzed_request = self._helpers.analyzeRequest(baseRequestResponse)
        host = analyzed_request.getUrl().getHost()

        # Check if Swagger JSON is crawled
        if host not in self.swagger_endpoints:
            self.find_and_parse_swagger(host)

        # Check if there are any matches during passive scanning
        url = analyzed_request.getUrl().toString()
        if host in self.swagger_endpoints:
            for endpoint in self.swagger_endpoints[host]:
                if endpoint["path"] in url:
                    return [self.create_issue(baseRequestResponse, endpoint["path"], "Passive Swagger Scan")]

        return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        analyzed_request = self._helpers.analyzeRequest(baseRequestResponse)
        host = analyzed_request.getUrl().getHost()

        # Scan if Swagger endpoints are not present
        if host not in self.swagger_endpoints:
            self.find_and_parse_swagger(host)

        # Test Swagger endpoints during active scanning
        issues = []
        if host in self.swagger_endpoints:
            for endpoint in self.swagger_endpoints[host]:
                payload = 'test_payload_for_{}'.format(endpoint["path"])
                attack_request = insertionPoint.buildRequest(payload.encode())
                attack_response = self._callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), attack_request
                )

                # Yanıtta belirli bir anahtar kelimeyi kontrol et
                if "vulnerability" in self._helpers.bytesToString(attack_response.getResponse()):
                    issues.append(self.create_issue(baseRequestResponse, endpoint["path"], "Active Swagger Scan"))

        return issues

    def find_and_parse_swagger(self, host_or_url):
        print("[Dynamic Swagger Scanner] Searching for Swagger JSON on {}".format(host_or_url))

        possible_paths = [
            "/swagger.json",
            "/openapi.json",
            "/v2/api-docs",
            "/documentation/swagger.json",
            "/documentation/openapi.json",
            "/documentation/api-docs"
        ]

        for path in possible_paths:
            url = "https://{}{}".format(host_or_url, path)
            response = self.fetch_url(url)
            if response:
                if self.is_json(response):
                    try:
                        swagger_data = json.loads(response)
                        endpoints = self.parse_swagger(swagger_data)
                        self.swagger_endpoints[host_or_url] = endpoints
                        print("[Dynamic Swagger Scanner] Found Swagger JSON at {}".format(url))

                        # Create an issue when Swagger JSON is found
                        self.create_issue_manual(
                            url, "Swagger Endpoint Found",
                            "The Swagger JSON endpoint at {} exposes API documentation.".format(url),
                            "Medium"
                        )
                        return
                    except Exception as e:
                        print("[Dynamic Swagger Scanner] Error parsing JSON at {}: {}".format(url, e))
                elif "swagger" in response.lower():
                    print("[Dynamic Swagger Scanner] Found possible Swagger documentation at: {}".format(url))

                    # Create an issue when Swagger documentation is found
                    self.create_issue_manual(
                        url, "Possible Swagger Documentation Found",
                        "The endpoint at {} might expose Swagger documentation.".format(url),
                        "Medium"
                    )
                else:
                    print("[Dynamic Swagger Scanner] Non-JSON content found at: {}".format(url))

        print("[Dynamic Swagger Scanner] No Swagger JSON found on {}".format(host_or_url))

    def create_issue_manual(self, url, issue_name, issue_detail, severity):
        """Burp Suite'te manuel bir issue oluştur."""
        if url in self.created_issues:
            print("[Dynamic Swagger Scanner] Duplicate issue ignored for: {}".format(url))
            return  # Duplicate kontrolü: Aynı URL için issue oluşturma

        try:
            # Create HTTP service
            parsed_url = URL(url)
            host = parsed_url.getHost()
            port = 443 if parsed_url.getProtocol() == "https" else 80
            http_service = self._helpers.buildHttpService(host, port, parsed_url.getProtocol() == "https")

            # Create an issue
            issue = CustomScanIssue(
                httpService=http_service,
                url=parsed_url,  # URL nesnesi doğrudan kullanılabilir
                httpMessages=[],  # İlgili HTTP mesajı yok
                name=issue_name,
                detail=issue_detail,
                severity=severity
            )
            self._callbacks.addScanIssue(issue)
            self.created_issues.append(url)
            print("[Dynamic Swagger Scanner] Issue created: {} at {}".format(issue_name, url))
        except Exception as e:
            print("[Dynamic Swagger Scanner] Error creating issue for {}: {}".format(url, e))

    def is_json(self, response):
        try:
            json.loads(response)
            return True
        except ValueError:
            return False

    def fetch_url(self, url):
        try:
            print("[Debug] Fetching URL: {}".format(url))

            # Separate URL parts
            parsed_url = URL(url)
            host = parsed_url.getHost()
            path = parsed_url.getPath() or "/"

            # Manually create the HTTP request
            http_request = "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n".format(path, host)
            byte_request = self._helpers.stringToBytes(http_request)

            # Make HTTP request with Burp API
            http_service = self._helpers.buildHttpService(host, 443, True)
            response = self._callbacks.makeHttpRequest(http_service, byte_request)

            # Return the response
            return self._helpers.bytesToString(response.getResponse())
        except Exception as e:
            print("[Dynamic Swagger Scanner] Error fetching {}: {}".format(url, e))
            return None

    def parse_swagger(self, swagger_data):
        endpoints = []
        for path, methods in swagger_data.get("paths", {}).items():
            for method in methods.keys():
                endpoints.append({"path": path, "method": method.upper()})
        print("[Dynamic Swagger Scanner] Parsed endpoints: {}".format(endpoints))
        return endpoints

    def create_issue(self, baseRequestResponse, endpoint, issue_name):
        return CustomScanIssue(
            baseRequestResponse.getHttpService(),
            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
            [baseRequestResponse],
            "{} at {}".format(issue_name, endpoint),
            "The endpoint {} may be vulnerable.".format(endpoint),
            "Information"
        )


class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
