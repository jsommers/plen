#!/usr/bin/env python

# 
#  topodata_parse.py
#  j.sommers.  jsommers@colgate.edu
# 

import re
import sys
from collections import defaultdict
import ipaddr
#from pytricia import PyTricia
import SubnetTree
import gzip
import math
import subprocess

# maxlines = -1 # process all lines
maxlines = 1000000

class TrEof(Exception):
  pass

traceroute_header_re = re.compile(r"traceroute from (\d+\.\d+\.\d+\.\d+) to (\d+\.\d+\.\d+\.\d+)")
hop_header_re = re.compile(r"hop\s+(\d+)\s+(\d+\.\d+\.\d+\.\d+)")
hop_rtt_re = re.compile(r"rtt: (\d+\.\d+)s,")
blank_line_re = re.compile(r"^\s*$")
hop_reply_re = re.compile(r"reply-size:\s+\d+,\s+reply-ttl:\s+(\d+),\s+reply-ipid:\s+0x([a-f\d]+), reply-tos 0x([a-f\d]+)")
hop_reply2_re = re.compile(r"reply-size:\s+\d+,\s+reply-ipid:\s+0x([a-f\d]+), reply-tos 0x([a-f\d]+)")
hop_quote_re = re.compile(r"q-ttl:\s+(\d+), q-len:\s\d+,\s+q-tos\s+([a-f\d]+)")
hop_mpls_re = re.compile(r"ttl:\s+(\d+),\s+s:\s+(\d+),\s+exp:\s+(\d+),\s+label:\s+(\d+)")
hop_typecode_re = re.compile(r"^\s*icmp-type:\s+\d+,\s+icmp-code:\s+\d+\s*$")


class LineReader(object):
  def __init__(self, instream):
      self.buffer = ''
      self.instream = instream
      self.maxlines = maxlines
      self.linesread = 0

  def inspect(self):
    return "Line buffer state: {}".format(self.buffer)

  def consume(self):
    if len(self.buffer) > 0:
      rv = self.buffer
      self.buffer = ""
      return rv

    self.linesread += 1    
    if self.maxlines > 0 and self.linesread >= self.maxlines:
        raise TrEof("Testing EOF (hit maxlines)")

    line = self.instream.readline()
    if not line:
      raise TrEof("End of input file")
    return line

  def unconsume(self, line):
    self.buffer = line


class MplsLabelInfo(object):
  def __init__(self, ttl, label, exp):
    self.ttl = ttl
    self.label = label
    self.exp = exp

  def __str__(self):
    return 'mpls <{},{},{}>'.format(self.ttl, self.label, self.exp)

class Layer3Hop(object):
  def __init__(self):
    self.ip_address = '0.0.0.0'
    self.asn = '?'
    self.hop_number = 0
    self.rtt = 0.0
    self.reply_ttl = 0
    self.reply_ipid = 0
    self.reply_tos = 0
    self.quoted_ttl = 0
    self.quoted_tos = 0
    self.mpls_info = []

  def add_mpls(self, minfo):
    self.mpls_info.append(minfo)

  def __str__(self):
    s = '{}: {}/{} {:3.3f} {} {:x} {:x} {} {:x} '.format(self.hop_number, self.ip_address, self.asn,
        self.rtt, self.reply_ttl, self.reply_ipid, self.reply_tos, self.quoted_ttl, self.quoted_tos)
    s += ' '.join([str(minfo) for minfo in self.mpls_info])
    return s

class Layer3Trace(object):
  def __init__(self, src, dst):
      self.hop_vector = []
      self.src = src
      self.dst = dst
      self.end_reason = 'unknown'

  def add_hop(self, hop):
      self.hop_vector.append(hop)

  def hops(self):
      return self.hop_vector

  def hop_length(self):
      return len(self.hop_vector)

  def rtt_length(self):
      return self.hop_vector[-1].rtt

  def __str__(self):
    hops =  ' :: '.join([str(hop) for hop in self.hop_vector])
    return '{}->{} ({}) {}'.format(self.src, self.dst, self.end_reason, hops)

def still_in_trace(input_reader):
  this_line = input_reader.consume()
  input_reader.unconsume(this_line)

  header_match = re.search(traceroute_header_re, this_line)
  blank_line = re.match(blank_line_re, this_line)
  return not (header_match or blank_line)


def end_of_current_hop(current_line):
  if re.search(hop_header_re, current_line):
    return True
  if re.search(traceroute_header_re, current_line):
    return True
  if re.match(blank_line_re, current_line):
    return True
  return False

def read_next_hop_info(input_reader):
  hop_lines = []
  current_line = input_reader.consume()

  if not re.search(hop_header_re, current_line):
    print >>sys.stderr,"Expecting next line to be a hop-header for a traceroute, but got {}".format(current_line)
    return hop_lines

  hop_lines.append(current_line)

  while True:
    current_line = input_reader.consume()
    if end_of_current_hop(current_line):
      input_reader.unconsume(current_line)
      break

    hop_lines.append(current_line)

  return hop_lines


def process_hop(hop_info):
  hop_data = Layer3Hop()
  for hop_line in hop_info:
    mobj = re.search(hop_header_re, hop_line)
    if mobj:
      hop_data.hop_number = int(mobj.groups()[0])
      hop_data.ip_address = mobj.groups()[1]
      continue

    mobj = re.search(hop_rtt_re, hop_line)
    if mobj:
      hop_data.rtt = float(mobj.groups()[0])
      continue

    mobj = re.match(hop_typecode_re, hop_line)
    if mobj:
      continue

    if hop_line.find('flags: 0x') > -1:
      continue

    mobj = re.match(blank_line_re, hop_line)
    if mobj:
      continue

    mobj = re.search(hop_reply_re, hop_line)
    if mobj:
      hop_data.reply_ttl = int(mobj.groups()[0])
      hop_data.reply_ipid = int(mobj.groups()[1], 16)
      hop_data.reply_tos = int(mobj.groups()[2], 16)
      continue

    mobj = re.search(hop_reply2_re, hop_line)
    if mobj:
      hop_data.reply_ipid = int(mobj.groups()[0], 16)
      hop_data.reply_tos = int(mobj.groups()[1], 16)
      continue

    mobj = re.search(hop_quote_re, hop_line)
    if mobj:
      hop_data.quoted_ttl = int(mobj.groups()[0])
      hop_data.quoted_tos = int(mobj.groups()[1], 16)
      continue

    mobj = re.search(hop_mpls_re, hop_line)
    if mobj:
      minfo = MplsLabelInfo(int(mobj.groups()[0]), int(mobj.groups()[3]), int(mobj.groups()[2]))
      hop_data.add_mpls(minfo)
      continue

    print >>sys.stderr, "\t*** Unrecognized line in hop info: ", hop_line
  return hop_data;


def skip_trace_header_section(input_reader):
  reason = 'unknown'
  while True:
    current_line = input_reader.consume()
    if current_line.find('stop reason') > -1:
      reason = current_line.split(':')[1].strip()

    if re.search(hop_header_re, current_line):
      input_reader.unconsume(current_line)
      return reason

def process_one_traceroute(ipsrc, ipdst, input_reader):
  end_reason = skip_trace_header_section(input_reader)
  trace = Layer3Trace(ipsrc, ipdst)
  trace.end_reason = end_reason
  # print "in proc one", input_reader.inspect()
  current_line = ''
  while still_in_trace(input_reader):
    # print "proc one while loop", input_reader.inspect()
    hop_info = read_next_hop_info(input_reader)
    if len(hop_info):
      hop = process_hop(hop_info)
      trace.add_hop(hop)
  return trace

def close_to_destination(trace_last_ip, destip):
  ipint = int(ipaddr.IPv4Address(destip))
  if (ipint & 0xf0000000) == 0xf000000:
    # class E
    prefix = '32'
  elif (ipint & 0xe0000000) == 0xe0000000:
    # class D
    prefix = '32'
  elif (ipint & 0xa0000000) == 0xa0000000:
    # class C
    prefix = '24'
  elif (ipint & 0x80000000) == 0x80000000:
    # class B
    prefix = '16'
  else:
    # class A
    prefix = '8'

  ipneta = ipaddr.IPv4Network('/'.join([trace_last_ip, prefix]))
  ipnetb = ipaddr.IPv4Network('/'.join([destip, prefix]))
  return ipneta.network == ipnetb.network


def read_tr_file(topodata_cmdline, ip2as):
  input_pipe = subprocess.Popen(topodata_cmdline, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout

  reader = LineReader(input_pipe)
  tracecount = 0
  badtrace = 0
  hop_lens = defaultdict(int)
  rtt_lens = []

  while True:
    try:
        current_line = reader.consume()
    except TrEof,e:
        print >>sys.stderr, "TrEof:",str(e)
        break

    # print current_line, reader.inspect()
    mobj = re.search(traceroute_header_re, current_line)
    if mobj:
      # print "Got tr header: ", current_line

      ipsrc = mobj.groups()[0]
      ipdst = mobj.groups()[1]
      try:
        l3t = process_one_traceroute(ipsrc, ipdst, reader)
        # print "Full tr: ", l3t
      except TrEof,e:
        print >>sys.stderr,"TrEof while processing a TR:",str(e)
        break

      matchok = False
      lasthop = l3t.hops()[-1]

      if ip2as:
        for hop in l3t.hops():
          if hop.ip_address in ip2as:
            hop.asn = ip2as[hop.ip_address]
   
        dstas = None
        if ipdst in ip2as:
          dstas = ip2as[ipdst]

        matchok = dstas == lasthop.asn
      else:
        matchok = close_to_destination(lasthop.ip_address, ipdst)

      if matchok:
        tracecount += 1;
        hop_lens[l3t.hop_length()] += 1
        rtt_lens.append(l3t.rtt_length())
      else:
        # print "Didn't reach destination: ",str(l3t)
        badtrace += 1

  print >>sys.stderr, "Done.  Processed {} traces, ignored {}.".format(tracecount, badtrace)
  return hop_lens, rtt_lens

def load_ip_to_as(routeviews_file):
  # pyt = PyTricia()
  pyt = SubnetTree.SubnetTree()
  infile = gzip.GzipFile(routeviews_file)
  for line in infile:
    ipnet,prefixlen,autonomous_system = line.split()
    ipnet = '{}/{}'.format(ipnet, prefixlen)
    pyt[ipnet] = autonomous_system
  infile.close()
  return pyt

def main(topodata_cmdline, routeviews_file):
  ip2as = None
  if routeviews_file:
    ip2as = load_ip_to_as(routeviews_file)
  hops, rtts = read_tr_file(topodata_cmdline, ip2as)
  return hops, rtts


if __name__ == '__main__':
  h,r = main('gzip -dc daily.l7.t1.c002503.20130502.hkg-cn.wd.gz', 'routeviews-rv2-20130501-1200.pfx2as.gz')
  print h,r
