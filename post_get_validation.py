from urllib import urlencode
from urlparse import urlparse, parse_qs
from burp import IBurpExtender, IHttpListener, IScanIssue, IExtensionHelpers
from java.net import URL


class BurpExtender(IBurpExtender, IHttpListener, IExtensionHelpers):
    def registerExtenderCallbacks(self, callbacks):
        # Initial configs of the extension
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("POST to GET Validation")
        callbacks.registerHttpListener(self)
        print("POST to GET Validation was correctly installed!")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            req_bytes = messageInfo.getRequest()
            http_service = messageInfo.getHttpService()
            req = self._helpers.analyzeRequest(http_service, req_bytes)
            method = req.getMethod()

            if method == "POST":
                url = req.getUrl()

                port = http_service.getPort()
                host = http_service.getHost()
                protocol = http_service.getProtocol

                # Read the body offset
                body_offset = req.getBodyOffset()

                # Extract the body from the raw request bytes
                body_bytes = req_bytes[body_offset:]

                # Convert the body bytes to a string (assuming it's text data)
                body_string = self._helpers.bytesToString(body_bytes)

                # Parse the original URL
                components = urlparse(url.toString())
                print("Original URL: %s" % url)
                # Extract the query string from the URL
                qs = parse_qs(components.query)
                # Merge the query string with the body parameters
                qs.update(parse_qs(body_string))
                # Rebuild the URL with the new query string
                new_url = components._replace(query=urlencode(qs, doseq=True)).geturl()

                # Build the new request, casting the URL to a Java URL object
                new_request = self._helpers.buildHttpRequest(URL(new_url))

                response = self._callbacks.makeHttpRequest(
                    host, port, protocol == "https", new_request
                )

                resp = self._helpers.analyzeResponse(response)
                status = resp.getStatusCode()

                if status >= 200 and status <= 209:
                    print("New URL: %s" % new_url)
                    http_service = messageInfo.getHttpService()
                    issue_name = "URL is possible vulnerable to XSS"
                    # %s is a placeholder that will be replaced by the CPF number
                    issue_detail = (
                        "The URL is answering to GET method when it shouldn't, being possible to be used for XSS exploitation. URL: %s "
                        % url
                    )
                    # Considering that it's a possibility, this is should be considered a Medium Risk finding and since it's not confirmed, it's a tentative
                    severity = "Medium"
                    confidence = "Tentative"
                    remediation = "Don't allow POST endpoints to positively answer to GET requests."

                    issue = CustomScanIssue(
                        http_service,
                        url,
                        [messageInfo],
                        issue_name,
                        issue_detail,
                        severity,
                        confidence,
                        remediation,
                    )

                    self._callbacks.addScanIssue(issue)


class CustomScanIssue(IScanIssue):
    def __init__(
        self,
        http_service,
        url,
        http_messages,
        name,
        detail,
        severity,
        confidence,
        remediation,
    ):
        self._http_service = http_service
        self._url = url
        self._http_messages = http_messages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence
        self._remediation = remediation

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return self._remediation

    def getHttpMessages(self):
        return self._http_messages

    def getHttpService(self):
        return self._http_service
