#!/usr/bin/python
# This is probably useful to like 4 people. Some of the packet inection stuff is taken from rule2alert https://code.google.com/p/rule2alert/ which is GPLv2 so I guess this is well.
# This ultra alpha if everything isn't right it will fall on its face and probably cause you to run away from it screaming into the night

#TODO:
# 1. Optionally trim request line to start with uripath 
# 2. Better error checking... Well any error checking really.

import random
import os
import sys
import json
import re
import zipfile
import tempfile
import shutil
from scapy.utils import PcapWriter
from scapy.all import *
import glob
import traceback
import base64
from optparse import OptionParser
try:
    from urllib.parse import urlparse
except:
    from urlparse import urlparse

if sys.version_info < (3,0):
    print("Need newer snakes.. requires Python 3.x")
    sys.exit(1)

parser = OptionParser()
parser.add_option("-i", dest="input_target", type="string", help="path to fiddler raw directory we will read from glob format or path to saz file")
parser.add_option("-o", dest="output_pcap", type="string", help="path to output PCAP file")
 
src = None
dst = None

def validate_ip(ip):
    if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",ip) != None:
        return True
    else:
        print("The ip address you provides is invalid %s exiting" % (ip))
        sys.exit(-1)


(options, args) = parser.parse_args()
if options == []:
   print(parser.print_help())
   sys.exit(-1)
if not options.input_target or options.input_target == "":
   print(parser.print_help())
   sys.exit(-1)
if not options.output_pcap or options.output_pcap == "":
   print(parser.print_help())
   sys.exit(-1)

#Open our packet dumper
pktdump = PcapWriter(options.output_pcap, sync=True)

def build_handshake(src,dst,sport,dport):
    ipsrc   = src
    ipdst   = dst
    portsrc = sport
    portdst = dport

#    We don't deal with session wrap around so lets make the range smaller for now
#    client_isn = random.randint(1024, (2**32)-1)
#    server_isn = random.randint(1024, (2**32)-1)
    client_isn = random.randint(1024, 10000)
    server_isn = random.randint(1024, 10000)
    syn = IP(src=ipsrc, dst=ipdst)/TCP(flags="S", sport=portsrc, dport=portdst, seq=client_isn)
    synack = IP(src=ipdst, dst=ipsrc)/TCP(flags="SA", sport=portdst, dport=portsrc, seq=server_isn, ack=syn.seq+1)
    ack = IP(src=ipsrc, dst=ipdst)/TCP(flags="A", sport=portsrc, dport=portdst, seq=syn.seq+1, ack=synack.seq+1)
    pktdump.write(syn)
    pktdump.write(synack)
    pktdump.write(ack)
    return(ack.seq,ack.ack)

def build_finshake(src,dst,sport,dport,seq,ack):
    ipsrc   = src
    ipdst   = dst
    portsrc = sport
    portdst = dport
    finAck = IP(src=ipsrc, dst=ipdst)/TCP(flags="FA", sport=sport, dport=dport, seq=seq, ack=ack)
    finalAck = IP(src=ipdst, dst=ipsrc)/TCP(flags="A", sport=dport, dport=sport, seq=finAck.ack, ack=finAck.seq+1)
    pktdump.write(finAck)
    pktdump.write(finalAck)

#http://stackoverflow.com/questions/18854620/whats-the-best-way-to-split-a-string-into-fixed-length-chunks-and-work-with-the
def chunkstring(string, length):
    return (string[0+i:length+i] for i in range(0, len(string), length))

def make_poop(src,dst,sport,dport,seq,ack,payload):
    segments = [] 
    if len(payload) > 1460:
        segments=chunkstring(payload,1460)
    else:
        segments.append(payload)    
    ipsrc   = src
    ipdst   = dst
    portsrc = sport
    portdst = dport
    for segment in segments:
        p = IP(src=ipsrc, dst=ipdst)/TCP(flags="PA", sport=sport, dport=dport, seq=seq, ack=ack)/segment
        returnAck = IP(src=ipdst, dst=ipsrc)/TCP(flags="A", sport=dport, dport=sport, seq=p.ack, ack=(p.seq + len(p[Raw])))
        seq = returnAck.ack
        ack = returnAck.seq
        pktdump.write(p)
        pktdump.write(returnAck)
    return(returnAck.seq,returnAck.ack)

if options.input_target and os.path.exists(options.input_target):
    with open(options.input_target, encoding='utf-8') as fh:
        try:
            har_data = json.load(fh)
            json_str = json.dumps(har_data)
            json_bytes = json_str.encode('utf-8')
        except Exception as e:
            print('failed to jsonload the HAR file {0}'.format(e))

    pages = har_data.get("log", {}).get('entries', [])
    for entry in pages:
        try:
            sport = random.randint(1024, 65535)
            parts = None
            dport = 80
            path = "/"
            src = '192.168.1.100'
            dst  = entry.get('serverIPAddress')
            url = entry.get("request", {}).get("url", '')
            reqmethod = entry.get("request", {}).get("method", "GET")
            reqversion = entry.get("request",{}).get("httpVersion","HTTP/1.1")
            stat_code = entry.get("response", {}).get('status', -1)
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
            req = b''
            req = "{0} {1} {2}\r\n".format(reqmethod,path,reqversion)
            headers_arr = entry.get("request", {}).get("headers")
            if headers_arr:
                for header in headers_arr:
                    hname = header.get("name", "")
                    if hname:
                        req = req + hname
                        value = header.get("value", "")
                        if value:
                            req = req + ": {0}".format(value)
                        req = req + "\r\n"
                req = req + "\r\n"        
            else:
                req = req + "\r\n\r\n"
            if entry.get("PostData",{}).get("text",""):
                req = req = entry.get("PostData",{}).get("text","")
            req = req.encode()
            if entry.get("response", {}):
                body = ''
                respversion = entry.get("response",{}).get("httpVersion","") 
                respstatus = entry.get("response",{}).get("status",None)
                respstattxt = entry.get("response",{}).get("statusText","")
                if entry.get("response", {}).get("content", {}).get("encoding", "") == 'base64':
                     body = base64.b64decode(entry.get("response", {}).get("content", {}).get("text", ""))
                else:
                     body = entry.get("response", {}).get("content", {}).get("text", "")
                if not isinstance(body, bytes):
                    body = body.encode() # uses 'utf-8' for encoding
                else:
                    body = body
                
                if respversion and respstatus:
                    resp = "{0} {1} {2}\r\n".format(respversion,respstatus,respstattxt)
                    headers_arr = entry.get("response", {}).get("headers")
                    if headers_arr:
                        for header in headers_arr:
                            hname = header.get("name", "")
                            if hname:
                                if hname.lower() == "transfer-encoding" and body:
                                    if body:
                                        resp = resp + "Content-Length"
                                        value = len(body)
                                        resp = resp + ": {0}".format(value)
                                else:        
                                    resp = resp + hname
                                    value = header.get("value", "")
                                    if value:
                                        if hname.lower() == "content-length":
                                            if body:
                                                value = len(body)
                                        resp = resp + ": {0}".format(value)
                                resp = resp+ "\r\n"
                    resp = resp + "\r\n"
                    resp = resp.encode()
                    resp = resp + body
            print("src: %s dst: %s sport: %s dport: %s" % (src, dst, sport, dport))
            (seq,ack)=build_handshake(src,dst,sport,dport)
            (seq,ack)=make_poop(src,dst,sport,dport,seq,ack,req)
            (seq,ack)=make_poop(dst,src,dport,sport,seq,ack,resp)
            build_finshake(src,dst,sport,dport,seq,ack)
        except Exception as e:
            print("Failed to handle session skipping {0}".format(e))
            exc_type, exc_value, exc_tb = sys.exc_info()
            traceback.print_exception(exc_type, exc_value, exc_tb)

    pktdump.close()
