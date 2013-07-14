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


class TrStats {
private:
  map<string, int> rtts;
  map<int, int> hops;
  string thisname;
  string outname;

public:
  TrStats(const string &scenario_name, const string &outfile_name) {
    thisname = scenario_name;
    outname = outfile_name;
    hops.clear();
    rtts.clear();
  }

  void add_troute(int hopcount, const struct timeval &rtt) {
    auto hopit = hops.find(hopcount);
    if (hopit == hops.end()) {
      hops[hopcount] = 1;
    } else {
      hops[hopcount] = 1 + hopit->second;
    }

    ostringstream ostr;
    ostr << rtt.tv_sec << '.' << setw(4) << setfill('0') << rtt.tv_usec / 10000;
    string rttstr = ostr.str();

    auto rttit = rtts.find(rttstr);
    if (rttit == rtts.end()) {
      rtts[rttstr] = 1;
    } else {
      rtts[rttstr] = 1 + rttit->second;
    }

    // cout << rtt.tv_sec << '.' << rtt.tv_usec << ' ' << rttstr << ' ' << hopcount << ' ' << hops.size() << endl;
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

    if (!usestdout) {
      delete outstream;
    }
  }
};

class DestinationChecker {
public:
  virtual bool check_dest(const char *trace_last_ip, const char *destip) = 0;
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

  bool check_dest(const char *trace_last_ip, const char *destip) {
    const char *asn1 = ip_to_asn(trace_last_ip);
    const char *asn2 = ip_to_asn(destip);
    return (asn1 != NULL && asn2 != NULL && strcmp(asn1, asn2) == 0);
  }
};

class ClassfulDestinationChecker : public DestinationChecker {
public:
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
  cerr << "Usage: " << progname << " -t <warts|arts> -n scenario_name -o outfilename -r routeviews_file" << endl;
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

void process_traceroute(DestinationChecker *, TrStats *, const string &, scamper_file_filter_t *);

int main(int argc, char * const *argv) {
  int ch = 0;
  const char *routeviews_file = nullptr;
  string outfile_name;
  string file_type = "none";
  string thisname = "unknown";

  while ((ch = getopt(argc, argv, "ho:r:t:n:")) != -1) {
    switch (ch) {
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

  DestinationChecker *checker = nullptr;
  if (routeviews_file != nullptr) {
    checker = new RouteviewsDestinationChecker(routeviews_file);
  } else {
    checker = new ClassfulDestinationChecker();
  }

  scamper_file_filter_t *filter = init_scamper();
  TrStats trstats(thisname, outfile_name);
  process_traceroute(checker, &trstats, file_type, filter);
  trstats.dump();
  return 0;
}

#if 0
static void dump_list_summary(scamper_list_t *list)
{
  if(list != NULL)
    {
      printf(" list id: %d ", list->id);
      if(list->name != NULL)
  printf("name: %s ", list->name);
      if(list->monitor != NULL)
  printf("monitor: %s ", list->monitor);
      printf("\n");
    }
  return;
}

static void dump_cycle_summary(scamper_cycle_t *cycle)
{
  if(cycle != NULL)
    printf(" cycle id: %d,", cycle->id);
  return;
}

static void dump_tcp_flags(uint8_t flags)
{
  if(flags != 0)
    {
      printf(" (%s%s%s%s%s%s%s%s )",
       (flags & 0x01) ? " fin" : "",
       (flags & 0x02) ? " syn" : "",
       (flags & 0x04) ? " rst" : "",
       (flags & 0x08) ? " psh" : "",
       (flags & 0x10) ? " ack" : "",
       (flags & 0x20) ? " urg" : "",
       (flags & 0x40) ? " ece" : "",
       (flags & 0x80) ? " cwr" : "");
    }
  return;
}

static void dump_timeval(const char *label, struct timeval *start)
{
  time_t tt = start->tv_sec;
  char buf[32];
  memcpy(buf, ctime(&tt), 24); buf[24] = '\0';
  printf(" %s: %s %06d ", label, buf, (int)start->tv_usec);
  return;
}

static void dump_trace_hop(scamper_trace_hop_t *hop) {
  scamper_icmpext_t *ie;
  uint32_t u32;
  char addr[256];
  int i;

  printf(" %2d, %s",
   hop->hop_probe_ttl,
   scamper_addr_tostr(hop->hop_addr, addr, sizeof(addr)));

  printf(", attempt: %d, rtt: %d.%06ds, probe-size: %d",
   hop->hop_probe_id,
   (int)hop->hop_rtt.tv_sec, (int)hop->hop_rtt.tv_usec,
   hop->hop_probe_size);

  printf(", reply-size: %d", hop->hop_reply_size);
  if(hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_REPLY_TTL)
    printf(", reply-ttl: %d", hop->hop_reply_ttl);
  if(hop->hop_addr->type == SCAMPER_ADDR_TYPE_IPV4)
    printf(", reply-ipid: 0x%04x, reply-tos 0x%02x",
     hop->hop_reply_ipid, hop->hop_reply_tos);
  // printf("\n");

  if(SCAMPER_TRACE_HOP_IS_ICMP(hop))
    {
      printf(", icmp-type: %d, icmp-code: %d",
       hop->hop_icmp_type, hop->hop_icmp_code);
      if(SCAMPER_TRACE_HOP_IS_ICMP_Q(hop))
  {
    printf(", q-ttl: %d, q-len: %d",
     hop->hop_icmp_q_ttl, hop->hop_icmp_q_ipl);
    if(hop->hop_addr->type == SCAMPER_ADDR_TYPE_IPV4)
      printf(", q-tos %d", hop->hop_icmp_q_tos);
  }
      if(SCAMPER_TRACE_HOP_IS_ICMP_PTB(hop))
  printf(", nhmtu: %d", hop->hop_icmp_nhmtu);
    }
  else
    {
      printf(", tcp-flags: 0x%02x", hop->hop_tcp_flags);
      dump_tcp_flags(hop->hop_tcp_flags);
    }
  //printf("\n");

  printf(", flags: 0x%02x", hop->hop_flags);
  if(hop->hop_flags != 0)
    {
      printf(" (");
      if(hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_TS_SOCK_RX)
  printf(" sockrxts");
      if(hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_TS_DL_TX)
  printf(" dltxts");
      if(hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_TS_DL_RX)
  printf(" dlrxts");
      if(hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_TS_TSC)
  printf(" tscrtt");
      if(hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_REPLY_TTL)
  printf(" replyttl");
      printf(" )");
    }
  // printf("\n");

  for(ie = hop->hop_icmpext; ie != NULL; ie = ie->ie_next)
    {
      if(SCAMPER_ICMPEXT_IS_MPLS(ie))
  {
    for(i=0; i<SCAMPER_ICMPEXT_MPLS_COUNT(ie); i++)
      {
        u32 = SCAMPER_ICMPEXT_MPLS_LABEL(ie, i);
        printf(", mpls <ttl=%d s=%d exp=%d label=%d>", 
         SCAMPER_ICMPEXT_MPLS_TTL(ie, i),
         SCAMPER_ICMPEXT_MPLS_S(ie, i),
         SCAMPER_ICMPEXT_MPLS_EXP(ie, i), u32);
        /*
        printf(", %9s ttl: %d, s: %d, exp: %d, label: %d\n",
         (i == 0) ? "mpls ext" : "",
         SCAMPER_ICMPEXT_MPLS_TTL(ie, i),
         SCAMPER_ICMPEXT_MPLS_S(ie, i),
         SCAMPER_ICMPEXT_MPLS_EXP(ie, i), u32);
         */
      }
  }
    }

  printf ("\n");
  return;
}
#endif

static void handle_trace(scamper_trace_t *trace, DestinationChecker *checker, TrStats *stats) {
#if 0
  scamper_trace_pmtud_t *pmtud;
  scamper_trace_pmtud_n_t *n;
  uint16_t i;
  uint8_t u8;
  char buf[256];
#endif

  char srcip[128];
  char dstip[128];
  if(trace->src != NULL) {
    scamper_addr_tostr(trace->src, srcip, sizeof(srcip));
  }

  scamper_addr_tostr(trace->dst, dstip, sizeof(dstip));

#if 0
  dump_list_summary(trace->list);
  dump_cycle_summary(trace->cycle);
  printf(" user-id: %d ", trace->userid);
  dump_timeval("start", &trace->start);

  printf(" type: ");
  switch(trace->type)
    {
    case SCAMPER_TRACE_TYPE_ICMP_ECHO:
      printf("icmp, echo id: %d ", trace->sport);
      break;

    case SCAMPER_TRACE_TYPE_ICMP_ECHO_PARIS:
      /*
       * if the byte ordering of the trace->sport used in the icmp csum
       * is unknown -- that is, not known to be correct, print that detail
       */
      printf("icmp paris, echo id: %d ", trace->sport);
      if(SCAMPER_TRACE_IS_ICMPCSUMDP(trace))
  printf(", csum: 0x%04x", trace->dport);
      break;

    case SCAMPER_TRACE_TYPE_UDP:
      printf("udp, sport: %d, base dport: %d ",
       trace->sport, trace->dport);
      break;

    case SCAMPER_TRACE_TYPE_UDP_PARIS:
      printf("udp paris, sport: %d, dport: %d ",
       trace->sport, trace->dport);
      break;

    case SCAMPER_TRACE_TYPE_TCP:
      printf("tcp, sport: %d, dport: %d ", trace->sport, trace->dport);
      break;

    case SCAMPER_TRACE_TYPE_TCP_ACK:
      printf("tcp-ack, sport: %d, dport: %d ",
       trace->sport, trace->dport);
      break;

    default:
      printf("%d ", trace->type);
      break;
    }
  if(trace->offset != 0)
    printf(", offset %d ", trace->offset);
  printf("\n");

  if(trace->dtree != NULL)
    {
      printf(" doubletree firsthop: %d ", trace->dtree->firsthop);
      if(trace->dtree->lss != NULL)
  printf(", lss-name: %s ", trace->dtree->lss);
      if(trace->dtree->lss_stop != NULL)
  printf(", lss-stop: %s ",
         scamper_addr_tostr(trace->dtree->lss_stop, buf, sizeof(buf)));
      if(trace->dtree->gss_stop != NULL)
  printf(", gss-stop: %s ",
         scamper_addr_tostr(trace->dtree->gss_stop, buf, sizeof(buf)));
      printf("\n");
    }

  printf(" attempts: %d, hoplimit: %d, loops: %d, probec: %d\n",
   trace->attempts, trace->hoplimit, trace->loops, trace->probec);
  printf(" gaplimit: %d, gapaction: ", trace->gaplimit);
  if(trace->gapaction == SCAMPER_TRACE_GAPACTION_STOP)
    printf("stop");
  else if(trace->gapaction == SCAMPER_TRACE_GAPACTION_LASTDITCH)
    printf("lastditch");
  else
    printf("0x%02x", trace->gapaction);
  printf("\n");

  printf(" wait-timeout: %ds", trace->wait);
  if(trace->wait_probe != 0)
    printf(", wait-probe: %dms", trace->wait_probe * 10);
  if(trace->confidence != 0)
    printf(", confidence: %d%%", trace->confidence);
  printf("\n");

  printf(" flags: 0x%02x", trace->flags);
  if(trace->flags != 0)
    {
      printf(" (");
      if(trace->flags & SCAMPER_TRACE_FLAG_ALLATTEMPTS)
  printf(" all-attempts");
      if(trace->flags & SCAMPER_TRACE_FLAG_PMTUD)
  printf(" pmtud");
      if(trace->flags & SCAMPER_TRACE_FLAG_DL)
  printf(" dltxts");
      if(trace->flags & SCAMPER_TRACE_FLAG_IGNORETTLDST)
  printf(" ignorettldst");
      if(trace->flags & SCAMPER_TRACE_FLAG_DOUBLETREE)
  printf(" doubletree");
      if(trace->flags & SCAMPER_TRACE_FLAG_ICMPCSUMDP)
  printf(" icmp-csum-dport");
      printf(" )");
    }
  printf("\n");
#endif

#if 0
  printf(" stop reason: ");
  switch(trace->stop_reason)
    {
    case SCAMPER_TRACE_STOP_NONE:
      printf("none");
      break;

    case SCAMPER_TRACE_STOP_COMPLETED:
      printf("done");
      break;

    case SCAMPER_TRACE_STOP_UNREACH:
      printf("icmp unreach %d", trace->stop_data);
      break;

    case SCAMPER_TRACE_STOP_ICMP:
      printf("icmp type %d", trace->stop_data);
      break;

    case SCAMPER_TRACE_STOP_LOOP:
      printf("loop");
      break;

    case SCAMPER_TRACE_STOP_GAPLIMIT:
      printf("gaplimit");
      break;

    case SCAMPER_TRACE_STOP_ERROR:
      printf("errno %d", trace->stop_data);
      break;

    case SCAMPER_TRACE_STOP_HOPLIMIT:
      printf("hoplimit");
      break;

    case SCAMPER_TRACE_STOP_GSS:
      printf("dtree-gss");
      break;

    case SCAMPER_TRACE_STOP_HALTED:
      printf("halted");
      break;

    default:
      printf("reason 0x%02x data 0x%02x",trace->stop_reason,trace->stop_data);
      break;
    }
  printf("\n");
#endif

  if (trace->hop_count > 0) {
    scamper_trace_hop_t *hop = trace->hops[trace->hop_count - 1];
    if (hop != NULL) {
      char lasthopaddr[128];
      scamper_addr_tostr(hop->hop_addr, lasthopaddr, sizeof(lasthopaddr));

      if (checker->check_dest(lasthopaddr, dstip)) {
        stats->add_troute(trace->hop_count, hop->hop_rtt);
      }
    }
  }

#if 0
  for(i=0; i < trace->hop_count; i++) {
    for(hop = trace->hops[i]; hop != NULL; hop = hop->hop_next) {

      dump_trace_hop(hop);

    }
  }

  /* dump any last-ditch probing hops */
  for(hop = trace->lastditch; hop != NULL; hop = hop->hop_next) {
    dump_trace_hop(hop);
  }
#endif

#if 0
  if((pmtud = trace->pmtud) != NULL)
    {
      printf("pmtud: ver %d ifmtu %d, pmtu %d", pmtud->ver, pmtud->ifmtu,
       pmtud->pmtu);
      if(pmtud->outmtu != 0)
  printf(", outmtu %d", pmtud->outmtu);
      if(pmtud->notec != 0)
  printf(", notec %d", pmtud->notec);
      printf("\n");
      for(u8=0; u8<pmtud->notec; u8++)
  {
    n = pmtud->notes[u8];
    hop = n->hop;
    printf(" note %d: nhmtu %d, ", u8, n->nhmtu);

    if(hop != NULL)
      scamper_addr_tostr(hop->hop_addr, buf, sizeof(buf));
    else
      buf[0] = '\0';

    if(n->type == SCAMPER_TRACE_PMTUD_N_TYPE_PTB)
      printf("ptb %s", buf);
    else if(n->type == SCAMPER_TRACE_PMTUD_N_TYPE_PTB_BAD && hop != NULL)
      printf("ptb-bad %s mtu %d", buf, hop->hop_icmp_nhmtu);
    else if(n->type == SCAMPER_TRACE_PMTUD_N_TYPE_SILENCE)
      printf("silence > ttl %d", hop != NULL ? hop->hop_probe_ttl : 0);
    else
      printf("type-%d", n->type);
    printf("\n");
  }
      for(hop = trace->pmtud->hops; hop != NULL; hop = hop->hop_next)
  dump_trace_hop(hop);
    }

  printf("\n");
#endif

  scamper_trace_free(trace);
  return;
}


void process_traceroute(DestinationChecker *checker, TrStats *trstats, const string &filetype, scamper_file_filter_t *filter) {
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
            handle_trace(trace, checker, trstats);
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
