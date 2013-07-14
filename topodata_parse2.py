#!/usr/bin/env python

# 
#  topodata_parse.py
#  j.sommers.  jsommers@colgate.edu
# 

check_routeviews = False

import re
import sys
from collections import defaultdict, namedtuple
import ipaddr
import math
import subprocess

if check_routeviews:
  import gzip
  #from pytricia import PyTricia
  import SubnetTree

# maxlines = -1 # process all lines
maxlines = 100

traceroute_header_re = re.compile(r"traceroute from (\d+\.\d+\.\d+\.\d+) to (\d+\.\d+\.\d+\.\d+) hops (\d+)")

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

Hop = namedtuple('Hop', ('hopnum', 'ipaddr', 'attempt', 'rtt', 'probe_size', 'reply_size', 'reply_ttl', 'reply_ipid', 'reply_tos', 'icmp_type', 'icmp_code', 'q_ttl', 'q_len', 'q_tos', 'flags', 'mpls') )

def mktuple(hopfields):
  if len(hopfields) < 4:
    return None

  hopnum = hopfields.pop(0)
  ipaddr = hopfields.pop(0)
  hdict = {'hopnum':hopnum, 'ipaddr':ipaddr, 'attempt':0, 'rtt':'0','probe_size':0, 'reply_size':0,'reply_ipid':0, 'reply_tos':0, 'icmp_type':0, 'icmp_code':0, 'q_ttl':0, 'q_len':0, 'q_tos':0, 'flags':0, 'mpls':0}
  for component in hopfields:
    fields = component.split()
    hdict[fields[0].strip(':').replace('-','_')] = fields[1]
  return Hop(**hdict)

def read_hop_info(input_stream, numhops):
  hops = []
  for i in xrange(numhops):
    hopline = input_stream.readline()
    if not hopline:
      break
    hop = mktuple([ s.strip() for s in hopline.split(',') ])
    if not hop:
      break
    hops.append(hop)
  return hops

def parse_rtt(rttstr):
  return '{:.3f}'.format(float(rttstr.strip('s')))

def read_tr_file(topodata_cmdline, ip2as):
  global maxlines # forgive me, for i have sinned.
  input_pipe = subprocess.Popen(topodata_cmdline, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout

  tracecount = 0
  badtrace = 0
  hop_lens = defaultdict(int)
  rtt_lens = defaultdict(int)

  while True:
    current_line = input_pipe.readline()
    if not current_line:
      break
    mobj = re.search(traceroute_header_re, current_line)
    if not mobj:
      continue

    ipsrc = mobj.groups()[0]
    ipdst = mobj.groups()[1]
    numhops = int(mobj.groups()[2])

    stopinfo = input_pipe.readline()
    if not stopinfo:
      break
    hops = read_hop_info(input_pipe, numhops)
    if len(hops) != numhops:
      continue

    # print hops

    lasthop = hops[-1]
    if ip2as:
      dstas = lastas = None

      if lastas in ip2as:
        lastas = ip2as[lasthop.ipaddr]
      if ipdst in ip2as:
        dstas = ip2as[ipdst]

      matchok = (lastas is not None) and (dstas == lastas)
    else:
      matchok = close_to_destination(lasthop.ipaddr, ipdst)

    if matchok:
      tracecount += 1;
      hop_lens[len(hops)] += 1
      rttval = parse_rtt(lasthop.rtt) 
      rtt_lens[rttval] += 1
    else:
      # print "Didn't reach destination: ",str(l3t)
      badtrace += 1

    maxlines -= 1
    if maxlines == 0:
      break

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
  if check_routeviews and routeviews_file:
    ip2as = load_ip_to_as(routeviews_file)
  hops, rtts = read_tr_file(topodata_cmdline, ip2as)
  return hops, rtts


if __name__ == '__main__':
  # h,r = main('gzip -dc daily.l7.t1.c002503.20130502.hkg-cn.wd.gz', 'routeviews-rv2-20130501-1200.pfx2as.gz')
  h,r = main('gzip -dc daily.l7.t2.c002270.20121205.cbg-uk.warts.gz| ./scamper-cvs-20111202c/utils/sc_wartsdump/sc_wartsdump warts', '')
  print h,r
