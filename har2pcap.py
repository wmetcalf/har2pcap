#!/usr/bin/env python3
# This is probably useful to like 4 people.
# Some of the packet inection stuff is taken from
# rule2alert https://code.google.com/p/rule2alert/
# which is GPLv2 so I guess this is well.
# This ultra alpha if everything isn't right it will
# fall on its face and probably cause you to run away
# from it screaming into the night

# TODO:
# 1. Optionally trim request line to start with uripath
# 2. Better error checking... Well any error checking really.

import scapy
from scapy.all import *
from scapy.utils import PcapWriter

if sys.version_info < (3, 0):
    from urlparse import urlparse
else:
    from urllib.parse import urlparse

import argparse

try:
    import pybase64 as base64
except:
    print("couldn't import pybase64 falling back to normal base64")
    import base64

import json
import os
import io
import random
import sys
import traceback


def build_handshake(pktdump, src, dst, sport, dport):
    #  We don't deal with session wrap around so make the range smaller for now
    #  client_isn = random.randint(1024, (2**32)-1)
    #  server_isn = random.randint(1024, (2**32)-1)
    client_isn = random.randint(1024, 10000)
    server_isn = random.randint(1024, 10000)
    syn = IP(src=src, dst=dst) / TCP(flags="S", sport=sport, dport=dport, seq=client_isn)
    synack = IP(src=dst, dst=src) / TCP(flags="SA", sport=dport, dport=sport, seq=server_isn, ack=syn.seq + 1)
    ack = IP(src=src, dst=dst) / TCP(flags="A", sport=sport, dport=dport, seq=syn.seq + 1, ack=synack.seq + 1)
    pktdump.write(syn)
    pktdump.write(synack)
    pktdump.write(ack)
    return (ack.seq, ack.ack)


def build_finshake(pktdump, src, dst, sport, dport, seq, ack):
    finAck = IP(src=src, dst=dst) / TCP(flags="FA", sport=sport, dport=dport, seq=seq, ack=ack)
    finalAck = IP(src=dst, dst=src) / TCP(flags="A", sport=dport, dport=sport, seq=finAck.ack, ack=finAck.seq + 1)
    pktdump.write(finAck)
    pktdump.write(finalAck)


def chunkstring(string, length):
    """from https://stackoverflow.com/a/18854817"""
    return (string[0 + i : length + i] for i in range(0, len(string), length))


def make_poop(pktdump, src, dst, sport, dport, seq, ack, payload):
    segments = []
    if len(payload) > 1460:
        segments = chunkstring(payload, 1460)
    else:
        segments.append(payload)
    for segment in segments:
        p = IP(src=src, dst=dst) / TCP(flags="PA", sport=sport, dport=dport, seq=seq, ack=ack) / segment
        returnAck = IP(src=dst, dst=src) / TCP(flags="A", sport=dport, dport=sport, seq=p.ack, ack=(p.seq + len(p[Raw])))
        seq = returnAck.ack
        ack = returnAck.seq
        pktdump.write(p)
        pktdump.write(returnAck)
    return (returnAck.seq, returnAck.ack)


def main(input_file, output_pcap):
    pktdump = PcapWriter(output_pcap, sync=True)
    har_data = {}
    with io.open(input_file, encoding="utf-8") as fh:
        try:
            har_data = json.load(fh)
            json_str = json.dumps(har_data)
            json_str.encode("utf-8")
        except Exception as e:
            print("failed to jsonload the HAR file {0}".format(e))
            sys.exit(1)

    pages = har_data.get("log", {}).get("entries", [])
    for entry in pages:
        try:
            sport = random.randint(1024, 65535)
            parts = None
            dport = 80
            path = "/"
            src = "192.168.1.100"
            dst = entry.get("serverIPAddress", "192.0.2.1")
            url = entry.get("request", {}).get("url", "")
            reqmethod = entry.get("request", {}).get("method", "GET")
            if reqmethod == "CONNECT":
                print("skipping connect request. noise from some proxy products")
                continue
            reqversion = entry.get("request", {}).get("httpVersion", "HTTP/1.1")
            # fake it till you make it
            if reqversion in ["h2", "h2c"]:
                reqversion = "HTTP/1.1"
            reqbody = entry.get("request", {}).get("postData", {}).get("text", "")
            if not reqbody:
                reqbody = entry.get("request", {}).get("PostData", {}).get("text", "")
            stat_code = entry.get("response", {}).get("status", -1)
            if url:
                try:
                    parts = urlparse(url)
                    if parts:
                        port = parts.port
                        if not port:
                            scheme = parts.scheme
                            if scheme == "http":
                                dport = 80
                            elif scheme == "https":
                                dport = 443
                        if parts.path:
                            path = parts.path

                        if parts.query:
                            path = path + "?" + parts.query

                except Exception as e:
                    print("failed to parse url {0}".format(e))
                    pass
            req = b""
            resp = b""
            req = "{0} {1} {2}\r\n".format(reqmethod, path, reqversion)
            headers_arr = entry.get("request", {}).get("headers")
            if headers_arr:
                for header in headers_arr:
                    hname = header.get("name", "")
                    if hname and hname not in [":method", ":scheme", ":path", ":authority"]:
                        req = req + hname
                        value = header.get("value", "")
                        if value:
                           if hname.lower() == "content-length":
                               if reqbody:
                                   value = len(reqbody)
                           req = req + ": {0}".format(value)
                        req = req + "\r\n"
                req = req + "\r\n"
            else:
                req = req + "\r\n\r\n"
            if reqbody:
                req = req + reqbody
            req = req.encode("utf-8")
            if entry.get("response", {}):
                body = ""
                respversion = entry.get("response", {}).get("httpVersion", "HTTP/1.1")
                # fake it till you make it
                if respversion in ["h2", "h2c"]:
                    respversion = "HTTP/1.1"
                respstatus = entry.get("response", {}).get("status", None)
                respstattxt = entry.get("response", {}).get("statusText", "")
                if entry.get("response", {}).get("content", {}).get("encoding", "") == "base64":
                    body = base64.b64decode(entry.get("response", {}).get("content", {}).get("text", ""))
                else:
                    body = entry.get("response", {}).get("content", {}).get("text", "")
                if not isinstance(body, bytes):
                    body = body.encode("utf-8")  # uses 'utf-8' for encoding
                else:
                    body = body

                if respversion and respstatus:
                    resp = "{0} {1} {2}\r\n".format(respversion, respstatus, respstattxt)
                    headers_arr = entry.get("response", {}).get("headers")
                    if headers_arr:
                        for header in headers_arr:
                            hname = header.get("name", "")
                            if hname:
                                if hname.lower() == "x-twinwave-remote-server-ip":
                                    if header.get("value", ""):
                                        dst = header.get("value")
                                if hname.lower() == "x-twinwave-remote-server-port":
                                    if header.get("value", ""):
                                        dport = int(header.get("value"))
                                if hname.lower() == "transfer-encoding" and body:
                                    if body:
                                        resp = resp + "Content-Length"
                                        value = len(body)
                                        resp = resp + ": {0}".format(value)
                                # most browsers/mitm proxies decode gzip,br etc for you.
                                elif hname.lower() not in ["content-encoding", ":status"]:
                                    resp = resp + hname
                                    value = header.get("value", "")
                                    if value:
                                        if hname.lower() == "content-length":
                                            if body:
                                                value = len(body)
                                        resp = resp + ": {0}".format(value)
                                resp = resp + "\r\n"
                    resp = resp + "\r\n"
                    resp = resp.encode("utf-8")
                    resp = resp + body
            print("src: %s dst: %s sport: %s dport: %s" % (src, dst, sport, dport))
            (seq, ack) = build_handshake(pktdump, src, dst, sport, dport)
            if req:
                (seq, ack) = make_poop(pktdump, src, dst, sport, dport, seq, ack, req)
            if resp:
                (seq, ack) = make_poop(pktdump, dst, src, dport, sport, seq, ack, resp)
            build_finshake(pktdump, src, dst, sport, dport, seq, ack)
        except Exception as e:
            print("Failed to handle session skipping {0}".format(e))
            exc_type, exc_value, exc_tb = sys.exc_info()
            traceback.print_exception(exc_type, exc_value, exc_tb)

    pktdump.close()


if __name__ == "__main__":
    # if sys.version_info < (3, 0):
    #    print("Need newer snakes.. requires Python 3.x")
    #    sys.exit(1)
    parser = argparse.ArgumentParser(description="har2pcap")
    parser.add_argument("input_target", help="path to fiddler raw directory we will read from glob format or path to saz file")
    parser.add_argument("output_pcap", help="path to output PCAP file")
    args = parser.parse_args()
    input_file = args.input_target
    if not os.path.exists(input_file):
        print("file %s does not exist" % (input_file,))
        sys.exit(1)
    main(input_file, args.output_pcap)
