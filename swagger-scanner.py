from burp import IBurpExtender, IScannerCheck, IScanIssue
from java.net import URL
from array import array
import json
import threading

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.extension_name = "Dynamic Swagger Scanner"
        self._callbacks.setExtensionName(self.extension_name)
        self._callbacks.registerScannerCheck(self)
        self.swagger_endpoints = {}
        self.parsed_hosts = set()
        self.lock = threading.RLock()

    def doPassiveScan(self, baseRequestResponse):
        analyzed_request = self._helpers.analyzeRequest(baseRequestResponse)
        host = analyzed_request.getUrl().getHost()
        with self.lock:
            if host not in self.parsed_hosts:
                self.parsed_hosts.add(host)
                self.find_and_parse_swagger(host)
        return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return []

    def find_and_parse_swagger(self, host):
        paths = [
            "/swagger.json",
            "/openapi.json",
            "/v2/api-docs",
            "/documentation/swagger.json",
            "/documentation/openapi.json",
            "/documentation/api-docs"
        ]
        for path in paths:
            url = "https://{}{}".format(host, path)
            response = self.fetch_url(url)
            if response:
                lower_resp = response.lower()
                if self.is_json(response):
                    try:
                        swagger_data = json.loads(response)
                        eps = self.parse_swagger(swagger_data)
                        self.swagger_endpoints[host] = eps
                        self.create_issue_manual(
                            url,
                            "Swagger Endpoint Found",
                            "The Swagger JSON endpoint at {} exposes API documentation.".format(url),
                            "Medium"
                        )
                    except:
                        pass
                elif "swagger" in lower_resp:
                    self.create_issue_manual(
                        url,
                        "Possible Swagger Documentation Found",
                        "The endpoint at {} might expose Swagger documentation.".format(url),
                        "Medium"
                    )

    def create_issue_manual(self, url, issue_name, issue_detail, severity):
        try:
            parsed_url = URL(url)
            host = parsed_url.getHost()
            path = parsed_url.getPath() or ""
            port = 443 if parsed_url.getProtocol() == "https" else 80
            http_service = self._helpers.buildHttpService(host, port, parsed_url.getProtocol() == "https")
            req = "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: DynamicSwaggerScanner/1.0\r\nAccept: application/json\r\nConnection: close\r\n\r\n".format(path, host)
            byte_req = self._helpers.stringToBytes(req)
            resp = self._callbacks.makeHttpRequest(http_service, byte_req)
            resp_bytes = resp.getResponse()
            info = self._helpers.analyzeResponse(resp_bytes)
            body = self._helpers.bytesToString(resp_bytes)[info.getBodyOffset():]
            markers = []
            lw = body.lower()
            if "swagger" in lw:
                idx = lw.index("swagger")
                end_idx = idx + len("swagger")
                markers.append(array('i', [info.getBodyOffset() + idx, info.getBodyOffset() + end_idx]))
            marked = self._callbacks.applyMarkers(resp, None, markers)
            issue = CustomScanIssue(
                http_service,
                parsed_url,
                [marked],
                issue_name,
                issue_detail,
                severity
            )
            self._callbacks.addScanIssue(issue)
        except:
            pass

    def fetch_url(self, url):
        try:
            parsed_url = URL(url)
            host = parsed_url.getHost()
            path = parsed_url.getPath() or "/"
            port = 443 if parsed_url.getProtocol() == "https" else 80
            http_service = self._helpers.buildHttpService(host, port, parsed_url.getProtocol() == "https")
            req = "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: DynamicSwaggerScanner/1.0\r\nAccept: application/json\r\nConnection: close\r\n\r\n".format(path, host)
            byte_req = self._helpers.stringToBytes(req)
            resp = self._callbacks.makeHttpRequest(http_service, byte_req)
            return self._helpers.bytesToString(resp.getResponse())
        except:
            return None

    def parse_swagger(self, swagger_data):
        eps = []
        p_obj = swagger_data.get("paths", {})
        for p, methods in p_obj.items():
            for m in methods.keys():
                eps.append({"path": p, "method": m.upper()})
        return eps

    def is_json(self, r):
        try:
            json.loads(r)
            return True
        except:
            return False

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
        return 0x08000003

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return "Publicly accessible Swagger/OpenAPI documentation can reveal internal endpoints."

    def getRemediationBackground(self):
        return "Restrict or remove access to Swagger/OpenAPI docs in production."

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return "Ensure these sensitive API docs are not publicly accessible."

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
