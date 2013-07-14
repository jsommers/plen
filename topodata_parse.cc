/*
 * topodata_parse.cc
 * j.sommers.  jsommers@colgate.edu
 */

#include <iostream> 
#include <iomanip>
#include <string>
#include <regex>
#include <vector>
#include <list>

#include <cstdint>

using namespace std;

const string traceroute_header_re = R"(traceroute from (\d+\.\d+\.\d+\.\d+) to (\d+\.\d+\.\d+\.\d+))";
const regex traceroute_header(traceroute_header_re);

const string hop_header_re = R"(hop\s+(\d+)\s+(\d+\.\d+\.\d+\.\d+))";
const regex hop_header(hop_header_re);

const string hop_rtt_re = R"(rtt: (\d+\.\d+)s,)";
const regex hop_rtt(hop_rtt_re);

const string blank_line_re = R"(^\s*$)";
const regex blank_line(blank_line_re);

const string hop_reply_re = R"(reply-size:\s+\d+,\s+reply-ttl:\s+(\d+),\s+reply-ipid:\s+0x([a-f\d]+), reply-tos 0x([a-f\d]+))";
// reply-size: 56, reply-ttl: 249, reply-ipid: 0x0000, reply-tos 0x00
const string hop_reply_re2 = R"(reply-size:\s+\d+,\s+reply-ipid:\s+0x([a-f\d]+), reply-tos 0x([a-f\d]+))";
// reply-size: 0, reply-ipid: 0x0000, reply-tos 0x00
const regex hop_reply(hop_reply_re);
const regex hop_reply2(hop_reply_re2);

const string hop_quote_re = R"(q-ttl:\s+(\d+), q-len:\s\d+,\s+q-tos\s+([a-f\d]+))";
// icmp-type: 11, icmp-code: 0, q-ttl: 1, q-len: 44, q-tos 224
const regex hop_quote(hop_quote_re);

const string hop_mpls_re = R"(ttl:\s+(\d+),\s+s:\s+(\d+),\s+exp:\s+(\d+),\s+label:\s+(\d+))";
// mpls ext ttl: 1, s: 1, exp: 0, label: 1740
const regex hop_mpls(hop_mpls_re);

const string hop_typecode_re = R"(^\s*icmp-type:\s+\d+,\s+icmp-code:\s+\d+\s*$)";
const regex hop_typecode(hop_typecode_re);


class LineReaderEof {

};


class LineReader {
private:
  string buffer;

public:
  LineReader() {}

  void inspect() {
    cout << "Line buffer state <" << buffer << ">" << endl;
  }

  bool ok() {
    return cin.good();
  }

  string consume() {
    if (buffer.size() > 0) {
      string rv = buffer;
      buffer = "";
      return rv;
    }

    string line;
    if (!cin.good()) {
      throw LineReaderEof();
    }
    getline(cin, line);
    return line;
  }

  void unconsume(string line) {
    buffer = line;
  }
};

struct MplsLabelInfo {
  int ttl;
  int label;
  int exp;

  MplsLabelInfo(int pttl, int plabel, int pexp) : ttl(pttl), label(plabel), exp(pexp) {}
};

class Layer3Hop {
public:
  string ip_address;
  int hop_number;
  double rtt;
  int reply_ttl;
  int reply_ipid;
  int reply_tos;

  int quoted_ttl;
  int quoted_tos;

  vector<MplsLabelInfo> mpls_info;

  void add_mpls(MplsLabelInfo minfo) {
    mpls_info.push_back(minfo);
  }

};

ostream &operator<<(ostream &os, const MplsLabelInfo &minfo) {
  os << "mpls <" << minfo.ttl << ',' << minfo.label << ',' << minfo.exp << "> ";
  return os; 
}

ostream &operator<<(ostream &os, const Layer3Hop &hop_data) {
  os << hop_data.hop_number << ' ' << hop_data.ip_address << ' ' << hop_data.rtt << ' ' 
     << hop_data.reply_ttl << ' ' << hex << hop_data.reply_ipid << dec << ' ' << hex << hop_data.reply_tos << dec << ' '
     << hop_data.quoted_ttl << ' ' << hex << hop_data.quoted_tos << dec;
  for (auto minfo : hop_data.mpls_info) {
    os << ' ' << minfo;
  }
  return os;  
}

class Layer3Trace {
private:
  vector<Layer3Hop> hop_vector;

public:
  void add_hop(Layer3Hop hop) {
    hop_vector.push_back(hop);
  }

  const vector<Layer3Hop> &hops() const {
    return hop_vector;
  }

  int hop_length() const {
    return hop_vector.size();
  }

  double rtt_length() const {
    return hop_vector[hop_vector.size()-1].rtt;
  }

};

bool still_in_trace(LineReader &input_reader) {
  string this_line = input_reader.consume();
  input_reader.unconsume(this_line);

  smatch match_result;
  bool header_match = regex_search(this_line, match_result, traceroute_header);
  bool blank_line = regex_match(this_line, match_result, regex(R"(^\s*$)"));

  bool rv = input_reader.ok() && !header_match && !blank_line;
  return rv;
}

bool end_of_current_hop(const string &current_line) {
  smatch match_result;
  if (regex_search(current_line, match_result, hop_header)) {
    return true;
  }
  if (regex_search(current_line, match_result, traceroute_header)) {
    return true;
  }
  if (regex_match(current_line, match_result, regex(R"(^\s*$)"))) {
    return true;
  }
  return false;
}

vector<string> read_next_hop_info(LineReader &input_reader) {
  vector<string> hop_lines;

  string current_line = input_reader.consume();
  smatch match_result;
  if (!regex_search(current_line, match_result, hop_header)) {
    cerr << "Expecting next line to be a hop-header for a traceroute, but got " << current_line << endl;
    return hop_lines;
  }
  hop_lines.push_back(current_line);

  while (true) {
    current_line = input_reader.consume();
    if (end_of_current_hop(current_line) || !input_reader.ok()) {
      input_reader.unconsume(current_line);
      break;
    }

    hop_lines.push_back(current_line);
  }
  return hop_lines;
}

Layer3Hop process_hop(const vector<string> &hop_info) {
  Layer3Hop hop_data {};
  for (auto hop_line : hop_info) {
    smatch match_result;
    if (regex_search(hop_line, match_result, hop_header)) {
      hop_data.hop_number = stoi(match_result[1]);
      hop_data.ip_address = match_result[2];
    } else if (regex_search(hop_line, match_result, hop_rtt)) {
      hop_data.rtt = stod(match_result[1]);
    } else if (regex_match(hop_line, match_result, hop_typecode)) {
      ; // ignore
    } else if (hop_line.find("flags: 0x") != string::npos) {
      ; // ignore
    } else if (regex_match(hop_line, match_result, blank_line)) { 
      ; // ignore
    } else if (regex_search(hop_line, match_result, hop_reply)) {
      hop_data.reply_ttl = stoi(match_result[1]);
      hop_data.reply_ipid = stoi(match_result[2], nullptr, 16);
      hop_data.reply_tos = stoi(match_result[3], nullptr, 16);
    } else if (regex_search(hop_line, match_result, hop_reply2)) {
      hop_data.reply_ipid = stoi(match_result[1], nullptr, 16);
      hop_data.reply_tos = stoi(match_result[2], nullptr, 16);
    } else if (regex_search(hop_line, match_result, hop_quote)) {
      hop_data.quoted_ttl = stoi(match_result[1]);
      hop_data.quoted_tos = stoi(match_result[2], nullptr, 16);
    } else if (regex_search(hop_line, match_result, hop_mpls)) {
      MplsLabelInfo minfo(stoi(match_result[1]), stoi(match_result[4]), stoi(match_result[3]));
      hop_data.add_mpls(minfo);
    } else {
      cerr << "\t*** Unrecognized line in hop info: " << hop_line << endl;
    }
  }

  return hop_data;
}

void skip_trace_header_section(LineReader &input_reader) {
  while (true) {
    string current_line = input_reader.consume();  
    smatch match_result;
    if (regex_search(current_line, match_result, hop_header)) {
      input_reader.unconsume(current_line);  
      return;
    }
  }
}

Layer3Trace *process_one_traceroute(const string &from, const string &to, LineReader &input_reader) {
  Layer3Trace *trace = new Layer3Trace();

  skip_trace_header_section(input_reader);

  string current_line;
  while (still_in_trace(input_reader)) {
    vector<string> hop_info = read_next_hop_info(input_reader);
    if (hop_info.size()) {
      Layer3Hop hop = process_hop(hop_info);
      trace->add_hop(hop);
    }
  }

  return trace;
}


int main() {
  LineReader reader;
  int tracecount = 0;
  vector<int> hop_lens;
  vector<double> rtt_lens;

  while (reader.ok()) {
    string current_line = reader.consume();
    smatch match_result;
    if (regex_search(current_line, match_result, traceroute_header)) {
      string ipsrc = match_result[1];
      string ipdst = match_result[2];
      Layer3Trace *l3t = nullptr;

      try {
        l3t = process_one_traceroute(ipsrc, ipdst, reader);
      } catch (LineReaderEof e) {
        break; 
      }

      if (l3t != nullptr) {
        tracecount += 1;
        // cout << "Trace from " << ipsrc << " to " << ipdst << ":" << endl;
        // for (auto hop : l3t->hops()) {
        //   cout << "\t" << hop << endl;
        // }
        hop_lens.push_back(l3t->hop_length());
        rtt_lens.push_back(l3t->rtt_length());
        delete l3t;
      }
    }
  }

  for (int i = 0; i < hop_lens.size(); i++) {
    cout << hop_lens[i] << ' ' << rtt_lens[i] << endl;
  }

  cerr << "Done.  Processed " << tracecount << " traces\n";
  return 0;
}
