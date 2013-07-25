/*
 * topodata_parse.cc.
 * some code borrowed from warts-dump (the parts that don't crash :-/).
 * j.sommers.  jsommers@colgate.edu
 */

#include <iostream> 
#include <sstream>
#include <fstream>
#include <iomanip>
#include <string>
#include <vector>
#include <list>
#include <map>

#include <zlib.h>
#include <string.h>
extern "C" {
  #include "patricia.h"

  #include "scamper_addr.h"
  #include "scamper_list.h"
  #include "scamper_icmpext.h"
  #include "trace/scamper_trace.h"
  #include "ping/scamper_ping.h"
  #include "tracelb/scamper_tracelb.h"
  #include "dealias/scamper_dealias.h"
  #include "neighbourdisc/scamper_neighbourdisc.h"
  #include "tbit/scamper_tbit.h"
  #include "sting/scamper_sting.h"
  #include "sniff/scamper_sniff.h"
  #include "scamper_file.h"
}
#include <unistd.h>
#include <arpa/inet.h>

using namespace std;

struct MplsInfo {
  int ttl;
  int label;
  int exp;
  bool eos;
};

struct HopData {
  int hop_num; // hop_probe_ttl
  uint8_t icmp_type;
  uint8_t icmp_code;
  uint16_t reply_ipid;
  struct timeval rtt;
  string ipaddr;
  string dns;
  string asn;
  int quoted_ttl;
  vector<MplsInfo> labelstack;

  bool ismpls() const {
    return (labelstack.size() > 0);
  }
};


class TrStats {
private:
  map<string, int> rtts;
  map<int, int> hops;
  map<int, int> aspathlens;
  string thisname;
  string outname;
  int filtered;
  int included;
  bool truncate_ends;

public:
  TrStats(const string &scenario_name, const string &outfile_name, bool trunc_ends) {
    thisname = scenario_name;
    outname = outfile_name;
    hops.clear();
    rtts.clear();
    aspathlens.clear();
    filtered = 0;
    included = 0;
    truncate_ends = trunc_ends;
  }

  void incr_filtered() { ++filtered; }

  void add_troute(const vector<HopData> &hopdata) {
    ++included;

    int firsthop_index = 0;
    int lasthop_index = hopdata.size()-1;
    int hopcount = hopdata[lasthop_index].hop_num;


    if (truncate_ends) {
      // path trimming at each endpoint...
      int i = 1;
      while (i < hopdata.size() && hopdata[i].asn == hopdata[0].asn) {
        ++i;
      }

      int lastidx = hopdata.size() - 1;
      int j = 1;
      while ((lastidx - j > 0) && hopdata[lastidx - j].asn == hopdata[lastidx].asn) {
        ++j;
      }

      if (hopcount - (i-1) - (j-1) > 0) { // sanity check
        firsthop_index = i-1;
        lasthop_index = lasthop_index - (j-1);
        hopcount = hopdata[lasthop_index].hop_num - hopdata[firsthop_index].hop_num + 1;
      }
    }

    map<string,int> ases;
    for (auto hd : hopdata) {
      if (hd.asn != "?") {
        ases[hd.asn] = 1; 
      }
    }
    int aspathlength = ases.size();
    auto asnit = aspathlens.find(aspathlength);
    if (asnit == aspathlens.end()) {
      aspathlens[aspathlength] = 1;
    } else {
      aspathlens[aspathlength] = 1 + asnit->second;
    }

    auto hopit = hops.find(hopcount);
    if (hopit == hops.end()) {
      hops[hopcount] = 1;
    } else {
      hops[hopcount] = 1 + hopit->second;
    }

    struct timeval rtt = hopdata[lasthop_index].rtt;
    ostringstream ostr;
    ostr << rtt.tv_sec << '.' << setw(4) << setfill('0') << (rtt.tv_usec / 100);
    string rttstr = ostr.str();
    auto rttit = rtts.find(rttstr);
    if (rttit == rtts.end()) {
      rtts[rttstr] = 1;
    } else {
      rtts[rttstr] = 1 + rttit->second;
    }
  }

  void dump() {
    ostream *outstream = nullptr;
    bool usestdout = (outname == "");

    if (usestdout) {
      outstream = &cout;
    } else {
      outstream = new ofstream(outname.c_str(), ofstream::app);
    }

    *outstream << thisname << " hops {";
    for (auto it = hops.begin(); it != hops.end(); ++it) {
      *outstream << it->first << ":" << it->second << ", ";
    }
    *outstream << "}\n";

    *outstream << thisname << " rtts {";
    for (auto it = rtts.begin(); it != rtts.end(); ++it) {
      *outstream << "'" << it->first << "':" << it->second << ", ";
    }
    *outstream << "}\n";

    *outstream << thisname << " aspaths {";
    for (auto it = aspathlens.begin(); it != aspathlens.end(); ++it) {
      *outstream << it->first << ":" << it->second << ", ";
    }
    *outstream << "}\n";

    *outstream << "# " << thisname << " included " << included << " filtered " << filtered << endl;

    if (!usestdout) {
      delete outstream;
    }
  }
};

class DestinationChecker {
public:
  virtual bool check_dest(const char *trace_last_ip, const char *destip) = 0;
  virtual bool same_network(const char *, const char *) = 0;
  virtual string get_asn(const char *) = 0;
};


static void dealloc_string(prefix_t *pfx, void *data) {
  char *asn = reinterpret_cast<char *>(data);
  free(asn);
}

class RouteviewsDestinationChecker : public DestinationChecker {
private:
  patricia_tree_t *ptree;

  char *ip_to_asn(const string &pfx) {
    string tmppfx = pfx + "/32";
    // cout << "ip2asn " << tmppfx << endl;
    prefix_t *pfxt = ascii2prefix(AF_INET, const_cast<char *>(tmppfx.c_str()));
    char buffer[128];
    prefix_toa2x(pfxt, buffer, 128);
    // cout << "prefix " << buffer << endl;
    patricia_node_t *pnode = patricia_search_best(ptree, pfxt);
    // cout << "pnode " << pnode << endl;
    Deref_Prefix(pfxt); 
    if (pnode) {
      return reinterpret_cast<char *>(pnode->data);
    } 
    return NULL;
  }

public:
  RouteviewsDestinationChecker(const char *pfx2asfile) {
    ptree = New_Patricia(32);
    gzFile gzf = gzopen(pfx2asfile, "r");
    char buffer[1024];
    while (gzgets(gzf, buffer, 1024) != NULL) {
      char *tmpbuf = &buffer[0];
      char *iprange = strsep(&tmpbuf, "\t\n ");
      char *prefixlen = strsep(&tmpbuf, "\t\n ");
      char *asstr = strsep(&tmpbuf, "\t\n ");
      if (iprange != NULL && prefixlen != NULL && asstr != NULL) {
        string prefix = iprange;
        prefix += "/";
        prefix += prefixlen;      
        char *asn = strdup(asstr);
        patricia_node_t *node = addroute(ptree, const_cast<char *>(prefix.c_str()));
        node->data = reinterpret_cast<void*>(asn);
      }    
    }
    gzclose(gzf);
  }

  virtual ~RouteviewsDestinationChecker() {
    Clear_Patricia(ptree, reinterpret_cast<void_fn_t>(dealloc_string)); 
  }

  bool same_network(const char *srcip, const char *dstip) {
    const char *asn1 = ip_to_asn(srcip);
    const char *asn2 = ip_to_asn(dstip);
    return (asn1 != NULL && asn2 != NULL && strcmp(asn1, asn2) == 0);
  }

  string get_asn(const char *ipaddr) {
    string s = "?";
    char *asnstr = ip_to_asn(ipaddr);
    if (asnstr != NULL) {
      s = asnstr;
    }
    return s;
  }

  bool check_dest(const char *trace_last_ip, const char *destip) {
    const char *asn1 = ip_to_asn(trace_last_ip);
    const char *asn2 = ip_to_asn(destip);
    return (asn1 != NULL && asn2 != NULL && strcmp(asn1, asn2) == 0);
  }
};

class ClassfulDestinationChecker : public DestinationChecker {
public:
  bool same_network(const char *srcip, const char *dstip) {
    struct in_addr srcinaddr, dstinaddr;
    inet_aton(srcip, &srcinaddr);
    inet_aton(dstip, &dstinaddr);
    return ((static_cast<uint32_t>(srcinaddr.s_addr) & 0xffffff00) ==
            (static_cast<uint32_t>(dstinaddr.s_addr) & 0xffffff00));
  }

  string get_asn(const char *ipaddr) {
    string s = "?";
    return s;
  }

  bool check_dest(const char *trace_last_ip, const char *destip) {
    struct in_addr destinaddr, lastinaddr;
    inet_aton(trace_last_ip, &lastinaddr);
    inet_aton(destip, &destinaddr);

    uint32_t ipintdest = static_cast<uint32_t>(destinaddr.s_addr);
    ipintdest = htonl(ipintdest);
    uint32_t prefixlen = 0;

    if ((ipintdest & 0xf0000000) == 0xf000000) // class E
      prefixlen = 32;
    else if ((ipintdest & 0xe0000000) == 0xe0000000) // class D
      prefixlen = 32;
    else if ((ipintdest & 0xa0000000) == 0xa0000000) // class C
      prefixlen = 24;
    else if ((ipintdest & 0x80000000) == 0x80000000) // class B
      prefixlen = 16;
    else  // class A
      prefixlen = 8;

    // cout << prefixlen << endl;
    // cout << hex << ipintdest << dec << endl;
    uint32_t ipintlast = static_cast<uint32_t>(lastinaddr.s_addr);
    ipintlast = htonl(ipintlast);

    uint32_t mask = 0xffffffff << (32 - prefixlen);
    return (ipintdest & mask) == (ipintlast & mask);
  }
};



int pfxcount = 0;

void process_fn(prefix_t *pfx, void *data) {
  char *asn = reinterpret_cast<char *>(data);
  char buffer[128];
  prefix_toa2x(pfx, buffer, 128);
  cout << buffer << "->" << asn << endl;
  ++pfxcount;
}

void usage(const char *progname) {
  cerr << "Usage: " << progname << " -t <warts|arts> -n scenario_name -o outfilename -d dnsmapping -r routeviews_file" << endl;
  exit(0);
}

scamper_file_filter_t *init_scamper(void) {
  scamper_file_filter_t *filter;
  uint16_t filter_types[] = {
    SCAMPER_FILE_OBJ_LIST,
    SCAMPER_FILE_OBJ_CYCLE_START,
    SCAMPER_FILE_OBJ_CYCLE_DEF,
    SCAMPER_FILE_OBJ_CYCLE_STOP,
    SCAMPER_FILE_OBJ_TRACE,
    SCAMPER_FILE_OBJ_PING,
    SCAMPER_FILE_OBJ_TRACELB,
    SCAMPER_FILE_OBJ_DEALIAS,
    SCAMPER_FILE_OBJ_NEIGHBOURDISC,
    SCAMPER_FILE_OBJ_TBIT,
    SCAMPER_FILE_OBJ_STING,
    SCAMPER_FILE_OBJ_SNIFF,
  };
  uint16_t filter_cnt = sizeof(filter_types)/sizeof(uint16_t);
  if((filter = scamper_file_filter_alloc(filter_types, filter_cnt)) == NULL) {
    cerr << "Couldn't allocate scamper filter" << endl;
    exit(0);
  }
  return filter;
}


class DnsMapper {
public:
  virtual ~DnsMapper() {}

  virtual string map_dns(const char *ipaddr) const {
    return string("-");
  };
};

class CaidaDnsMapper : public DnsMapper {
public:
  CaidaDnsMapper(const vector<string> &dns_filelist) {
    for (string dns_file : dns_filelist) {
      cerr << "Loading DNS file " << dns_file << endl;
      gzFile gzf = gzopen(dns_file.c_str(), "r");
      char buffer[1024];
      while (gzgets(gzf, buffer, 1024) != NULL) {
        char *tmpbuf = &buffer[0];
        char *timestamp = strsep(&tmpbuf, "\t\n ");
        char *ipaddr = strsep(&tmpbuf, "\t\n ");
        char *dnsname = strsep(&tmpbuf, "\t\n ");
        if (timestamp != NULL && ipaddr != NULL && dnsname != NULL) {
          ipdns_mappings[ipaddr] = dnsname;
        }    
      }
      gzclose(gzf);
    }
  }  

  virtual string map_dns(const char *ipaddr) const {
    string ipstr {ipaddr};
    auto iter = ipdns_mappings.find(ipstr);
    return iter == ipdns_mappings.end() ? string() : iter->second;
  }

private:
  map<string,string> ipdns_mappings;
};


DnsMapper *load_dns_mapper(const vector<string> &dns_filelist) {
  if (dns_filelist.size() == 0) {
    return new DnsMapper();
  }
  return new CaidaDnsMapper(dns_filelist);
}

void process_traceroute(DestinationChecker *, DnsMapper *, TrStats *, const string &, scamper_file_filter_t *);

int main(int argc, char * const *argv) {
  int ch = 0;
  const char *routeviews_file = nullptr;
  vector<string> dnsfiles;
  string outfile_name;
  string file_type = "none";
  string thisname = "unknown";
  bool truncate_ends = false;

  while ((ch = getopt(argc, argv, "cd:ho:r:t:n:")) != -1) {
    switch (ch) {
      case 'c':
        truncate_ends = true;
        break;

      case 'd':
        dnsfiles.push_back(string(optarg));
        break;

      case 'n':
        thisname = optarg;
        break;

      case 'r':
        routeviews_file = optarg;
        break;

      case 'o':
        outfile_name = optarg;
        break;

      case 't':
        file_type = optarg;
        break;

      default:
      case 'h':
        usage(argv[0]);
        break;
    }
  }

  if (!(file_type == "warts" || file_type == "arts")) {
    cerr << "File type must be specified as warts or arts (-t option)" << endl;
    exit(0);
  }

  DnsMapper *dnsmapper = load_dns_mapper(dnsfiles);

  DestinationChecker *checker = nullptr;
  if (routeviews_file != nullptr) {
    checker = new RouteviewsDestinationChecker(routeviews_file);
  } else {
    checker = new ClassfulDestinationChecker();
  }

  scamper_file_filter_t *filter = init_scamper();
  TrStats trstats(thisname, outfile_name, truncate_ends);
  process_traceroute(checker, dnsmapper, &trstats, file_type, filter);
  trstats.dump();
  delete dnsmapper;
  return 0;
}

static vector<HopData> convert_one_trace(scamper_trace_t *trace, DestinationChecker *checker, DnsMapper *dnsmapper) {
  vector<HopData> hop_data;

  for (int i = 0; i < trace->hop_count; ++i) {
    scamper_trace_hop_t *hop = trace->hops[i];
    if (hop != NULL) {
      HopData hd {};
      hd.hop_num = hop->hop_probe_ttl;

      hd.rtt = hop->hop_rtt;

      char addrstr[128];
      scamper_addr_tostr(hop->hop_addr, addrstr, sizeof(addrstr));
      hd.ipaddr = addrstr;

      hd.asn = checker->get_asn(addrstr);
      hd.dns = dnsmapper->map_dns(addrstr);

      hd.icmp_type = hop->hop_icmp_type;
      hd.icmp_code = hop->hop_icmp_code;

      if(SCAMPER_TRACE_HOP_IS_ICMP_Q(hop)) {
        hd.quoted_ttl = hop->hop_icmp_q_ttl;
      } else {
        hd.quoted_ttl = -1;
      }

      hd.reply_ipid = hop->hop_reply_ipid;

      if (SCAMPER_TRACE_HOP_IS_ICMP(hop)) {
        for(auto ie = hop->hop_icmpext; ie != NULL; ie = ie->ie_next) {
          if(SCAMPER_ICMPEXT_IS_MPLS(ie)) {
            for(int j = 0; j<SCAMPER_ICMPEXT_MPLS_COUNT(ie); j++) {
              MplsInfo minfo {};
              minfo.label = SCAMPER_ICMPEXT_MPLS_LABEL(ie, j);
              minfo.ttl = SCAMPER_ICMPEXT_MPLS_TTL(ie, j);
              minfo.exp = SCAMPER_ICMPEXT_MPLS_EXP(ie, j);
              minfo.eos = SCAMPER_ICMPEXT_MPLS_S(ie, j);
              hd.labelstack.push_back(minfo);
            }
          }
        }
      }
      hop_data.push_back(hd);
    }
  }

  return hop_data;
}

ostream &operator<<(ostream &os, const MplsInfo &minfo) {
  os << minfo.label << ':' << minfo.ttl << ":0x" << hex << minfo.exp << dec << ':' << minfo.eos;
  return os;
}

ostream &operator<<(ostream &os, const HopData &hd) {
  os << hd.hop_num << ' ' << hd.rtt.tv_sec << '.' << setw(6) << setfill('0') << hd.rtt.tv_usec 
     << ' ' << hd.ipaddr << ' ' << hd.asn << ' ' << hd.dns << ' ' 
     << static_cast<int>(hd.icmp_type) << '/' << static_cast<int>(hd.icmp_code)
     << ' ' << "0x" << hd.reply_ipid << dec;

  if (hd.quoted_ttl >= 0) {
    os << " qttl " << hd.quoted_ttl;
  } 

  for (auto minfo : hd.labelstack) {
    os << " mpls:" << minfo;
  }

  return os;
}

/*
  - find explicit MPLS tunnels
  - infer any implicit tunnels
  - basic question: is path likely to be longer than explicitly revealed?
*/
static bool is_explicit_mpls(const vector<HopData> &hopdata) {
  for (auto hd : hopdata) {
    if (hd.ismpls()) {
      return true;
    }
  } 
  return false;
}

static bool is_anomalous_qttl(const vector<HopData> &hopdata) {
  for (auto hd : hopdata) {
    if (!hd.ismpls() && (hd.icmp_type == 11 && ((hd.quoted_ttl == 0) || (hd.quoted_ttl > 1)))) {
      return true;
    }
  }
  return false;
}

static bool is_mpls_qttl_nonincreasing(const vector<HopData> &hopdata) {
  bool inmpls = false;
  int lastqttl = 0;
   
  for (auto hd: hopdata) {
    if (hd.ismpls()) {
      if (!inmpls) {
        inmpls = true;
        lastqttl = hd.quoted_ttl;
      } else {
        if (hd.quoted_ttl < lastqttl) {
          return true;
        } 
        lastqttl = hd.quoted_ttl;
      }
    } else {
      inmpls = false;
    }
  }
  return false;
}

static void analyze_hops(const vector<HopData> &hopdata) {
  if (is_mpls_qttl_nonincreasing(hopdata) || is_anomalous_qttl(hopdata)) {
    cout << "trace " << hopdata.size() << endl;
    for (auto hd : hopdata) {
      cout << '\t' << hd << endl;
    }
  }
}

static void handle_trace(scamper_trace_t *trace, DestinationChecker *checker, DnsMapper *dnsmapper, TrStats *stats) {
  char srcip[128];
  char dstip[128];
  if(trace->src != NULL) {
    scamper_addr_tostr(trace->src, srcip, sizeof(srcip));
  }

  scamper_addr_tostr(trace->dst, dstip, sizeof(dstip));

  if (checker->same_network(srcip, dstip)) {
    stats->incr_filtered();
    return;
  }

  bool nullhops = false;
  if (trace->hop_count > 0) {
    scamper_trace_hop_t *hop = trace->hops[trace->hop_count - 1];
    if (hop != NULL) {
      char lasthopaddr[128];
      scamper_addr_tostr(hop->hop_addr, lasthopaddr, sizeof(lasthopaddr));

      if (checker->check_dest(lasthopaddr, dstip) && trace->hop_count < 64) {
        vector<HopData> hopdata = convert_one_trace(trace, checker, dnsmapper);
        analyze_hops(hopdata);
        stats->add_troute(hopdata);
      } else {
        stats->incr_filtered();
      }
    } else {
      stats->incr_filtered();
      nullhops = true;
    }
  }

  if (!nullhops) {
    try {
      scamper_trace_free(trace);
    } catch (...) {
      cerr << "exception while freeing trace" << endl;
    }
  }

  return;
}


void process_traceroute(DestinationChecker *checker, DnsMapper *dnsmapper, TrStats *trstats, 
                        const string &filetype, scamper_file_filter_t *filter) {
  scamper_file_t *infile;
  char filename[] = "-";
  infile = scamper_file_openfd(STDIN_FILENO, filename, 'r', const_cast<char *>(filetype.c_str()));
  if (infile == NULL) {
    cerr << "Failed to open stdin for reading traceroute data" << endl;
    exit(0);
  }

  uint16_t type;
  void *data;

  while(scamper_file_read(infile, filter, &type, &data) == 0) {
    /* hit eof */
    if(data == NULL)
      break;

    switch(type)
      {
      case SCAMPER_FILE_OBJ_TRACE:
        {
          try {
            scamper_trace_t *trace = reinterpret_cast<scamper_trace_t*>(data);
            handle_trace(trace, checker, dnsmapper, trstats);
          } 
          catch (...) {
            cout << "Error/exception reading trace object" << endl;
          }
          break;
        }
      default:
        break;
      }
  }

  scamper_file_close(infile);
  scamper_file_filter_free(filter);
}
