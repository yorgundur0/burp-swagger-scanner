from burp import IBurpExtender, IScannerCheck, IScanIssue
from java.net import URL
from array import array
import threading

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.extension_name = "Dynamic Swagger Scanner (Passive Scan, 200 Check)"
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
        guess_paths = [
            "/swagger.json",
            "/openapi.json",
            "/v2/api-docs",
            "/documentation/swagger.json",
            "/documentation/openapi.json",
            "/documentation/api-docs"
        ]
        if path == "/" or not path:
            for guess in guess_paths:
                full_url = "https://{}{}".format(host, guess)
                status_code = self.fetch_status_code(full_url)
                if status_code == 200:
                    self.found_swaggers.add(host)
                    self.create_issue_manual(
                        baseRequestResponse,
                        full_url,
                        "Swagger Endpoint Found",
                        "A Swagger endpoint at {} returned 200 OK.".format(full_url),
                        "Medium"
                    )
                    return
            self.no_swagger_paths.add((host, path))
        else:
            combined_urls = []
            base_url = "https://{}{}".format(host, path)
            if not self.path_has_swagger(path):
                combined_urls.append(base_url)
                for guess in guess_paths:
                    if not self.path_has_swagger(path + guess):
                        combined_urls.append(base_url + guess)
            for url in combined_urls:
                if host in self.found_swaggers:
                    return
                status_code = self.fetch_status_code(url)
                if status_code == 200:
                    self.found_swaggers.add(host)
                    self.create_issue_manual(
                        baseRequestResponse,
                        url,
                        "Swagger Endpoint Found",
                        "A Swagger endpoint at {} returned 200 OK.".format(url),
                        "Medium"
                    )
                    return
            if host not in self.found_swaggers:
                self.no_swagger_paths.add((host, path))

    def path_has_swagger(self, path_str):
        bad_segments = [
            "swagger.json",
            "openapi.json",
            "v2/api-docs",
            "documentation/swagger.json",
            "documentation/openapi.json",
            "documentation/api-docs"
        ]
        path_lower = path_str.lower()
        for seg in bad_segments:
            if seg in path_lower:
                return True
        return False

    def create_issue_manual(self, baseRequestResponse, full_url, issue_name, issue_detail, severity):
        try:
            parsed_url = URL(full_url)
            host = parsed_url.getHost()
            path = parsed_url.getPath() or "/"
            port = 443 if parsed_url.getProtocol() == "https" else 80
            http_service = self._helpers.buildHttpService(host, port, parsed_url.getProtocol() == "https")
            req_str = "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: DynamicSwaggerScanner/1.0\r\nAccept: application/json\r\nConnection: close\r\n\r\n".format(path, host)
            byte_req = self._helpers.stringToBytes(req_str)
            resp = self._callbacks.makeHttpRequest(http_service, byte_req)
            resp_bytes = resp.getResponse()
            info = self._helpers.analyzeResponse(resp_bytes)
            marked_resp = resp
            issue = CustomScanIssue(
                baseRequestResponse.getHttpService(),
                parsed_url,
                [marked_resp],
                issue_name,
                issue_detail,
                severity
            )
            self._callbacks.addScanIssue(issue)
        except:
            pass

    def fetch_status_code(self, url):
        try:
            parsed_url = URL(url)
            host = parsed_url.getHost()
            path = parsed_url.getPath() or "/"
            port = 443 if parsed_url.getProtocol() == "https" else 80
            http_service = self._helpers.buildHttpService(host, port, parsed_url.getProtocol() == "https")
            req_str = "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: DynamicSwaggerScanner/1.0\r\nAccept: application/json\r\nConnection: close\r\n\r\n".format(path, host)
            byte_req = self._helpers.stringToBytes(req_str)
            resp = self._callbacks.makeHttpRequest(http_service, byte_req)
            analyzed = self._helpers.analyzeResponse(resp.getResponse())
            return analyzed.getStatusCode()
        except:
            return -1

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return 0

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
        return "Publicly accessible Swagger/OpenAPI endpoints may reveal internal API details."

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
