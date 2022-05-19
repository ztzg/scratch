#!/usr/bin/env python
"""
Read a mitmproxy dump file.
"""
from mitmproxy import io, http
from mitmproxy.exceptions import FlowReadException
import pprint
import sys
import hashlib

with open(sys.argv[1], "rb") as logfile:
    freader = io.FlowReader(logfile)
    pp = pprint.PrettyPrinter(indent=4)
    try:
        for f in freader.stream():
            if not isinstance(f, http.HTTPFlow):
                print("!not_http " + repr(f))
            elif not f.request.url:
                print("!no_url " + f.request.host)
            else:
                data = f.response.data
                digest = "!no_digest"
                if data.content is not None and len(data.content) > 0:
                    m = hashlib.sha256()
                    m.update(data.content)
                    digest = m.hexdigest()
                print(f"{digest} {f.response.status_code} {f.request.url}")
    except FlowReadException as e:
        print(f"Flow file corrupted: {e}")
