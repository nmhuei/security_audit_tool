# Burp Suite Jython Extension
# Load in Burp: Extender -> Extensions -> Add -> Type: Python -> File: burp_extender.py
# Requires Jython standalone jar configured in Burp (Extender -> Options -> Python Environment)

from burp import IBurpExtender, IHttpListener
import json
import urllib2

BRIDGE_URL = "http://127.0.0.1:8765/ingest"
MAX_BODY = 4000

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("SAT Burp Bridge")
        callbacks.registerHttpListener(self)
        print("[SAT Burp Bridge] loaded")
        print("[SAT Burp Bridge] forwarding to {}".format(BRIDGE_URL))

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # only process requests from Proxy/Repeater/Intruder/Scanner
        if not messageIsRequest:
            return

        try:
            req = messageInfo.getRequest()
            req_info = self._helpers.analyzeRequest(messageInfo)
            headers = list(req_info.getHeaders())
            body_off = req_info.getBodyOffset()
            body = req[body_off:]
            body_str = self._helpers.bytesToString(body)
            if len(body_str) > MAX_BODY:
                body_str = body_str[:MAX_BODY] + "...<truncated>"

            url = req_info.getUrl()
            method = req_info.getMethod()
            path = url.getPath() or "/"
            query = url.getQuery() or ""
            host = url.getHost()

            hdr_map = {}
            for h in headers[1:]:
                if ":" in h:
                    k, v = h.split(":", 1)
                    hdr_map[k.strip()] = v.strip()

            event = {
                "id": "{}:{}:{}".format(method, path, messageInfo.hashCode()),
                "host": host,
                "url": str(url),
                "path": path,
                "method": method,
                "query": query,
                "headers": hdr_map,
                "body": body_str,
                "source": "burp"
            }

            data = json.dumps(event)
            req = urllib2.Request(BRIDGE_URL, data, {"Content-Type": "application/json"})
            resp = urllib2.urlopen(req, timeout=1.5)
            _ = resp.read()
        except Exception as e:
            print("[SAT Burp Bridge] error: {}".format(e))
