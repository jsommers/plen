#!/usr/bin/env python

import os
import sys
import math
import re
import optparse
import subprocess
import json
from collections import defaultdict

skitterv1_range =  ( (1998,7), (2004,6) )
skitterv2_range =  ( (2004,6), (2008,2) )
ark_range =        ( (2007,9), (2013,6) )
routeviews_range = ( (2005,5), (2013,6) )

def median(xlist):
  if not xlist:
    return -1.0

  xlist.sort()
  n = len(xlist)
  if n % 2 == 1:
    return xlist[n/2]
  else:
    return (xlist[n/2-1] + xlist[n/2])/2.0

def avgvar_list(xlist):
  if len(xlist) < 2:
    return 0.0,0.0,0.0

  n = xsum = xsqsum = 0.0
  for val in xlist:
    xsum += val
    xsqsum += val**2.0
    n += 1.0
  avg = xsum / n
  var = (( xsqsum * n ) - ( xsum ** 2.0 )) / (n * (n - 1))
  return avg,math.sqrt(var),median(xlist)

def avgvar_dict(xdict, floatit=False):
  xlist = []
  for val,count in xdict.iteritems():
    if floatit:
        xlist.extend([float(val)]*count)
    else:
        xlist.extend([val]*count)
  return avgvar_list(xlist)

def get_skitter_v1(year, month):
    names = []
    if date_out_of_range(year, month, skitterv1_range):
        return names
    try:
        for name in os.listdir('../skitter_data/{:04d}/{:02d}'.format(year, month)):
            if re.match(r'^[a-z0-9-]+\.\d{8}\.arts\.gz$', name):
                names.append('../skitter_data/{:04d}/{:02d}/{}'.format(year, month, name))
    except OSError,e:
        pass

    return names

def get_skitter_v2(year, month):
    names = []
    if date_out_of_range(year, month, skitterv2_range):
        return names

    try:
        for name in os.listdir('../skitter_data/{:04d}/{:02d}'.format(year, month)):
            if re.match(r'^l006\.[a-z0-9-]+\.\d{8}_\d{3}\.arts\.gz$', name):
                names.append('../skitter_data/{:04d}/{:02d}/{}'.format(year, month, name))
    except OSError,e:
        pass
        
    return names


def get_ark(year, month):
    names = []
    if date_out_of_range(year, month, ark_range):
        return names

    for team in [1,2,3]:
        try:
            for name in os.listdir('../data/team{}/{:04d}/{:02d}'.format(team, year, month)):
                if re.match(r'^daily\.l7\.t\d\.c\d{6}\.\d{8}\.[a-z0-9-]+\.warts\.gz$', name):
                    names.append('../data/team{}/{:04d}/{:02d}/{}'.format(team, year, month, name))
        except OSError, e:
            pass

    return names


def get_files(year, month):
    names = []
    for name in get_skitter_v1(year, month):
        names.append( (name,'arts') )
    for name in get_skitter_v2(year, month):
        names.append( (name,'arts') )
    for name in get_ark(year, month):
        names.append( (name,'warts') )

    print "Reading files:",names
    return names

def date_out_of_range(year, month, daterange):
    rangebegin = daterange[0]        
    rangeend = daterange[1] 
    year = int(year)
    month = int(month)
    print "testing out of range",year, month,daterange
    
    if year < rangebegin[0] or year > rangeend[0]:
        return True
    if year == rangebegin[0] and month < rangebegin[1]:
        return True
    if year == rangeend[0] and month > rangeend[1]:
        return True
    return False

def get_routeviews(year, month):
    if date_out_of_range(year, month, routeviews_range):
        return ''
    for fname in os.listdir('../routeviews/{:04d}/{:02d}'.format(year, month)):
        if 'pfx2as.gz' in fname:
            # just looking for one particular file
            return '../routeviews/{:04d}/{:02d}/{}'.format(year, month, fname)
    return ''


def post_process(outbase, y, m, input_file):
    infile = open(input_file)
    dictpair = { 'hops':defaultdict(int), 'rtts':defaultdict(int), 'aspaths':defaultdict(int) }
    for line in infile:
        if line[0] == '#':
            continue

        space1 = line.find(' ')
        space2 = line.find(' ', space1+1)
        name = line[:space1]
        xtype = line[space1+1:space2]
        xdict = eval(line[space2:])
        masterdict = dictpair[xtype]
        for key,val in xdict.iteritems():
            masterdict[key] += val
    outfile = open('{}_{:04d}{:02d}_full.txt'.format(outbase, y, m), 'w')
    print >>outfile,json.dumps(dictpair['hops'])
    print >>outfile,json.dumps(dictpair['rtts'])
    print >>outfile,json.dumps(dictpair['aspaths'])
    print >>outfile,avgvar_dict(dictpair['hops'])
    print >>outfile,avgvar_dict(dictpair['rtts'], floatit=True)
    print >>outfile,avgvar_dict(dictpair['aspaths'])
    outfile.close()


def main():
    parser = optparse.OptionParser()
    parser.add_option("-o", "--outbase", default="hopsrtts", dest="outbase")
    parser.add_option("-y", "--year", type="int", default=0, dest="year")
    parser.add_option("-m", "--month", type="int", default=0, dest="month")
    (options,args) = parser.parse_args()

    if options.year == 0 or options.month == 0:
        print "Need a year and month"
        return 0

    year,month = options.year,options.month

    for year in [year]:
        for month in [month]:
            outfile_name = '{}_{:04d}{:02d}_pre.txt'.format(options.outbase, year, month)
            filelist = get_files(year, month)
            routeviews = get_routeviews(year, month)

            remaining = len(filelist)
            print "Doing",outfile_name,">>>",
            for xfile,xtype in filelist:
                if routeviews:
                    cmdline = 'gzip -dc {} | ./topodata_parse2 -t {} -r {} -o {} -n {}'.format(xfile, xtype, routeviews, outfile_name, xfile)
                else:
                    cmdline = 'gzip -dc {} | ./topodata_parse2 -t {} -o {} -n {}'.format(xfile, xtype, outfile_name, xfile)
                print remaining,
                sys.stdout.flush()
                p = subprocess.Popen(cmdline, shell=True)
                pid, status = os.waitpid(p.pid, 0)
                remaining -= 1
            print ">>> postprocessing...",
            sys.stdout.flush()

            post_process(options.outbase, year, month, outfile_name)
            print "done"
            sys.stdout.flush()

main()
