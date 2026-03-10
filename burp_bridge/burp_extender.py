# Burp Suite Jython Extension
from burp import IBurpExtender, IHttpListener
import json
import urllib2

BRIDGE_URL = "http://127.0.0.1:8765/ingest"
MAX_BODY = 500000

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("SAT Burp Bridge")
        callbacks.registerHttpListener(self)
        print("[SAT Burp Bridge] loaded")

    def _post(self, payload):
        data = json.dumps(payload)
        req = urllib2.Request(BRIDGE_URL, data, {"Content-Type": "application/json"})
        urllib2.urlopen(req, timeout=2.0).read()

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            req = messageInfo.getRequest()
            req_info = self._helpers.analyzeRequest(messageInfo)
            req_headers = list(req_info.getHeaders())
            req_body_off = req_info.getBodyOffset()
            req_body = self._helpers.bytesToString(req[req_body_off:])
            if len(req_body) > MAX_BODY:
                req_body = req_body[:MAX_BODY] + "...<truncated>"

            url = req_info.getUrl()
            method = req_info.getMethod()
            path = url.getPath() or "/"
            query = url.getQuery() or ""
            host = url.getHost()

            hdr_map = {}
            for h in req_headers[1:]:
                if ":" in h:
                    k, v = h.split(":", 1)
                    hdr_map[k.strip()] = v.strip()

            payload = {
                "id": "{}:{}:{}".format(method, path, messageInfo.hashCode()),
                "host": host,
                "url": str(url),
                "path": path,
                "method": method,
                "query": query,
                "headers": hdr_map,
                "body": req_body,
                "source": "burp",
                "kind": "request" if messageIsRequest else "response",
                "toolFlag": int(toolFlag),
            }

            if not messageIsRequest:
                resp = messageInfo.getResponse()
                if resp:
                    resp_info = self._helpers.analyzeResponse(resp)
                    resp_headers = list(resp_info.getHeaders())
                    resp_body_off = resp_info.getBodyOffset()
                    resp_body = self._helpers.bytesToString(resp[resp_body_off:])
                    if len(resp_body) > MAX_BODY:
                        resp_body = resp_body[:MAX_BODY] + "...<truncated>"
                    payload["status"] = int(resp_info.getStatusCode())
                    payload["response_headers"] = resp_headers
                    payload["response_body"] = resp_body

            self._post(payload)
        except Exception as e:
            print("[SAT Burp Bridge] error: {}".format(e))
