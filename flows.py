#!/usr/bin/env python
"""
Read a mitmproxy dump file.
"""
from mitmproxy import io, http
from mitmproxy.exceptions import FlowReadException
import pprint
import sys

with open(sys.argv[1], "rb") as logfile:
    freader = io.FlowReader(logfile)
    pp = pprint.PrettyPrinter(indent=4)
    try:
        for f in freader.stream():
            if not isinstance(f, http.HTTPFlow):
                print("??? " + repr(f))
            elif not f.request.url:
                print("??? " + f.request.host)
            else:
                print(f"{f.response.status_code} {f.request.url}")
    except FlowReadException as e:
        print(f"Flow file corrupted: {e}")
