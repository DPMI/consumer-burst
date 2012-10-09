//we are at ip protocol capinfo

//#define __STDC_FORMAT_MACROS

//#ifdef HAVE_CONFIG_H
//#include "config.h"
//#endif /* HAVE_CONFIG_H */

#include "caputils/caputils.h"
#include "caputils/stream.h"
#include "caputils/filter.h"
#include "caputils/utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <netdb.h>
#include <cstdlib>
#include <map>
#include <vector>
#include <string.h>
#include <cstring>
#include <string>
#include <iostream>
#include <qd/qd_real.h>
#include <math.h>
#include <iomanip>

#define PICODIVIDER (double)1.0e12
#define STPBRIDGES 0x0026
#define CDPVTP 0x016E

using namespace std;
static int keep_running = 1;
static int print_content = 0;
static int print_date = 0;

static int max_packets = 0;
static const char* iface = NULL;
static struct timeval timeout = {1,0};
static const char* program_name = NULL;

qd_real start_time; // has to initialise when the first packet is read
qd_real end_time; //has to initialise till the next interval
qd_real sample_time;
qd_real transfer_time, temp_transfer_time;
long count = 0;
long sample_count = 0;
long sample_bytes = 0;

void handle_sigint(int signum){
  if ( keep_running == 0 ){
    fprintf(stderr, "\rGot SIGINT again, terminating.\n");
    abort();
  }
  fprintf(stderr, "\rAborting capture.\n");
  keep_running = 0;
}


static struct option long_options[]= {
  {"content",  no_argument,       0, 'c'},
  {"packets",  required_argument, 0, 'p'},
  {"iface",    required_argument, 0, 'i'},
  {"timeout",  required_argument, 0, 't'},
  {"calender", no_argument,       0, 'd'},
   {"graph", no_argument,       0, 'g'},
   {"singlepacket", no_argument,       0, 's'},
   {"relativetime", no_argument,       0, 'b'},
   {"noheader", no_argument,       0, 'n'},
  {"help",     no_argument,       0, 'h'},
  {"level",     required_argument,       0, 'q'},
  {"linkCapacity",     required_argument, 0, 'l'},
  {"threshold", required_argument,       0, 'r'},
  {0, 0, 0, 0} /* sentinel */
};

static void show_usage(void){
  //	printf("%s-" VERSION "\n", program_name);
  printf("(C) 2012 Patrik Arlos <patrik.arlos@bth.se>\n");
  printf("(C) 2012 David Sveningsson <david.sveningsson@bth.se>\n");
  printf("(C) 2012 Vamsi Krishna Konakalla <vamsi.krishna.konakalla@bth.se>\n");
  printf("Usage: %s [OPTIONS] STREAM\n", program_name);
  printf("  -c, --content        Write full package content as hexdump. [default=no]\n"
	
	 "  -i, --iface          For ethernet-based streams, this is the interface to listen\n"
	 "                       on. For other streams it is ignored.\n"
	 "  -p, --packets=N      Stop after N packets.\n"
	 "  -t, --timeout=N      Wait for N ms while buffer fills [default: 1000ms].\n"
	 "  -d, --calender       Show timestamps in human-readable format.\n"
	 "  -q, --level 		        Level to calculate packetsize {physical (default), link, network, transport and application}\n"
	 "                         At level N , payload of particular layer is only considered, use filters to select particular streams.\n"
	 "                         To calculate the bitrate at physical , use physical layer, Consider for Network layer use [-q network]\n"
	 "                         It shall contain transport protocol header + payload\n"
	 "                           - link: all bits captured at physical level, i.e link + network + transport + application\n"
	 "                           - network: payload field at link layer , network + transport + application\n"
	 "                           - transport: payload at network  layer, transport + application\n"
	 "                           - application: The payload field at transport leve , ie.application\n"
	 "                         Default is link\n"
	 "  -l, --linkCapacity          Link capacity in bits per second default 10 Mbps, (eg.input 10e6) \n"
	  "  -g, --graph          print values as tab seperated for importing data\n"
	   "  -n, --noheader          print values as tab seperated values without header for importing data\n"
	  "  -s, --singlepacket   It includes single packet as separate burst if the packet is time separated by the given threshold\n"
	  "  -b, --relativetime   Print start and stop time using relative time\n"
	 " -r ( Threshold Inter Arrival Time ( IAT)) specify the threshold IAT consider a new session \n"
	 "  -h, --help           This text.\n\n");
  filter_from_argv_usage();
}

static int payLoadExtraction(int level, const cap_head* caphead) {
  // payload size at physical (ether+network+transport+app)
  if ( level==0 ) {
    return caphead->len;
  };

  // payload size at link  (network+transport+app)
  if ( level==1 ) {
    return caphead->len - sizeof(struct ethhdr);
  };

  const struct ethhdr *ether = caphead->ethhdr;
  const struct ip* ip_hdr = NULL;
  struct tcphdr* tcp = NULL;
  struct udphdr* udp = NULL;
  size_t vlan_offset = 0;

  switch(ntohs(ether->h_proto)) {
  case ETHERTYPE_IP:/* Packet contains an IP, PASS TWO! */
    ip_hdr = (struct ip*)(caphead->payload + sizeof(cap_header) + sizeof(struct ethhdr));
  ipv4:

    // payload size at network  (transport+app)
    if ( level==2 ) {
      return ntohs(ip_hdr->ip_len)-4*ip_hdr->ip_hl;
    };

    switch(ip_hdr->ip_p) { /* Test what transport protocol is present */
    case IPPROTO_TCP: /* TCP */
      tcp = (struct tcphdr*)(caphead->payload + sizeof(cap_header) + sizeof(struct ethhdr) + vlan_offset + 4*ip_hdr->ip_hl);
      if(level==3) return ntohs(ip_hdr->ip_len)-4*tcp->doff-4*ip_hdr->ip_hl;  // payload size at transport  (app)
      break;
    case IPPROTO_UDP: /* UDP */
      udp = (struct udphdr*)(caphead->payload + sizeof(cap_header) + sizeof(struct ethhdr) + vlan_offset + 4*ip_hdr->ip_hl);
      if(level==3) return ntohs(udp->len)-8;                     // payload size at transport  (app)
      break;
    default:
      fprintf(stderr, "Unknown IP transport protocol: %d\n", ip_hdr->ip_p);
      return 0; /* there is no way to know the actual payload size here */
    }
    break;

  case ETHERTYPE_VLAN:
    ip_hdr = (struct ip*)(caphead->payload + sizeof(cap_header) + sizeof(struct ether_vlan_header));
    vlan_offset = 4;
    goto ipv4;

  case ETHERTYPE_IPV6:
    fprintf(stderr, "IPv6 not handled, ignored\n");
    return 0;

  case ETHERTYPE_ARP:
    fprintf(stderr, "ARP not handled, ignored\n");
    return 0;

  case STPBRIDGES:
    fprintf(stderr, "STP not handled, ignored\n");
    return 0;

  case CDPVTP:
    fprintf(stderr, "CDPVTP not handled, ignored\n");
    return 0;

  default:      /* Packet contains unknown link . */
    fprintf(stderr, "Unknown ETHERTYPE 0x%0x \n", ntohs(ether->h_proto));
    return 0; /* there is no way to know the actual payload size here, a zero will ignore it in the calculation */
  }

  fprintf(stderr, "packet wasn't handled by payLoadExtraction, ignored\n");
  return 0;
}


int main(int argc, char **argv){
  /* extract program name from path. e.g. /path/to/MArCd -> MArCd */
  int level;	
  int payLoadSize, payLoadSizeLink;
  int singlepacket = 2;
  qd_real session_time;
  qd_real transfer_time, temp_transfer_time;
  double linkCapacity = 10e6;
  int graph = 0;
  int rel = 0;
  long packetcounter = 0;
  qd_real ref_time ;
  long burstcounter = 0;
  int noheader = 0;
  const char* separator = strrchr(argv[0], '/');
  if ( separator ){
    program_name = separator + 1;
  } else {
    program_name = argv[0];
  }

  struct filter filter;
  if ( filter_from_argv(&argc, argv, &filter) != 0 ){
    return 0; /* error already shown */
  }

  filter_print(&filter, stderr, 0);

  int op, option_index = -1;
  while ( (op = getopt_long(argc, argv, "hcgsbndi:p:t:q:l:r:", long_options, &option_index)) != -1 ){
    switch (op){
    case 0:   /* long opt */
    case '?': /* unknown opt */
      break;

    case 'd':
      print_date = 1;
      break;

    case 'g':
      graph = 1;
      break;

    case 'n':
      noheader = 1;
      break;
     
    case 's':
      singlepacket = 1;
      break; 

     case 'b':
      rel = 1;
      break;

    case 'p':
      max_packets = atoi(optarg);
      break;

    case 't':
      {
	int tmp = atoi(optarg);
	timeout.tv_sec  = tmp / 1000;
	timeout.tv_usec = tmp % 1000 * 1000;
      }
      break;

    case 'c':
      print_content = 1;
      break;

    case 'i':
      iface = optarg;
      break;

    case 'h':
      show_usage();
      return 0;
    case 'q': /* --level */
      if (strcmp (optarg, "link") == 0)
	level = 0;
      else if ( strcmp (optarg, "network" ) == 0)
	level = 1;
      else if (strcmp (optarg ,"transport") == 0)
	level = 2;
      else if (strcmp (optarg , "application") == 0)
	level = 3;
      else {
	fprintf(stderr, "unrecognised level arg %s \n", optarg);
	exit(1);
      }
      break;
    case 'l': /* --link */
      linkCapacity = atof (optarg);
      //cout << " Link Capacity input = " << linkCapacity << " bps\n";
      break;	
    case 'r':
      sample_time = optarg;
      break;
	
    default:
      printf ("?? getopt returned character code 0%o ??\n", op);
    }
  }

  int ret;

  /* Open stream(s) */
  struct stream* stream;
  if ( (ret=stream_from_getopt(&stream, argv, optind, argc, iface, "-", program_name, 0)) != 0 ) {
    return ret; /* Error already shown */
  }
  const stream_stat_t* stat = stream_get_stat(stream);
  stream_print_info(stream, stderr);

  /* handle C-c */
  signal(SIGINT, handle_sigint);
  sample_bytes = 0;
  qd_real pkt1, pkt2, diffTime;
  while ( keep_running ) {
    /* A short timeout is used to allow the application to "breathe", i.e
     * terminate if SIGINT was received. */
    struct timeval tv = timeout;

    /* Read the next packet */
    cap_head* cp;
    ret = stream_read(stream, &cp, &filter, &tv);
    if ( ret == EAGAIN ){
      continue; /* timeout */
    } else if ( ret != 0 ){
      //cout <<"hello\n";
      // print accumulators
      burstcounter = burstcounter + 1;
       session_time = pkt1 - start_time;
       if (graph == 0) {
      cout<< "SESSIONSTARTTIME:"<< setiosflags(ios::fixed) << setprecision(12)<<to_double(start_time)<<":";
      cout<< "SESSIONENDTIME:"<< setiosflags(ios::fixed) << setprecision(12)<<to_double(pkt1)<<":";	
      cout <<"SESSIONPACKETS:"<<(sample_count) <<":";
      cout <<"SESSIONBYTES:";
      cout <<sample_bytes<<":";     
      cout << setiosflags(ios::fixed) << setprecision(12)<<"SESSIONTIME:"<<to_double(session_time) << endl;
       }
       else {
	 if ((burstcounter == 1)&& (noheader == 0)) {
	   cout <<"SESSIONSTART\tSESSIONEND\tPACKETCOUNT\tBYTECOUNT\tSESSIONDURATION(s)\n";
	 }
	 cout<<setiosflags(ios::fixed) << setprecision(12)<<to_double(start_time)<<"\t";
      cout<< setiosflags(ios::fixed) << setprecision(12)<<to_double(pkt1)<<"\t";	
      cout <<(sample_count) <<"\t";
     
      cout <<sample_bytes<<"\t";     
      cout << setiosflags(ios::fixed) << setprecision(12)<<to_double(session_time) << endl; 
       }
       sample_bytes =0;
      start_time = pkt2;
      sample_count = 1;
      diffTime = diffTime - diffTime; 
      break; /* shutdown or error */
    } 
    count++;
    payLoadSizeLink = payLoadExtraction(0, cp);
    payLoadSize = payLoadExtraction(level, cp);
    temp_transfer_time = 	(payLoadSizeLink - payLoadSize)*8 /  linkCapacity ;
    transfer_time =  payLoadSize*8 /  linkCapacity ;
    // cout <<payLoadSize<<"--"<<count<<"--";
    if (payLoadSize == 0) {
      continue;
    }
    packetcounter = packetcounter +1 ;		
    sample_count++;
    if (sample_count == 1) {
      pkt1=(qd_real)(double)cp->ts.tv_sec+(qd_real)(double)(cp->ts.tv_psec/PICODIVIDER);
      pkt1 = pkt1 + temp_transfer_time; // adding correction to desired layer
      start_time = pkt1;
      if ((packetcounter == 1)&& (rel == 1)) {
	ref_time = pkt1;
	pkt1 = pkt1 - ref_time;
	start_time = pkt1 ;
      }
    }
    pkt2=(qd_real)(double)cp->ts.tv_sec+(qd_real)(double)(cp->ts.tv_psec/PICODIVIDER);
    pkt2 = pkt2 + temp_transfer_time; // adding correction to desired layer
    if (rel == 1) {
    pkt2 = pkt2 -ref_time ;
    }
    diffTime = pkt2 - pkt1;	
    // cout<< "PacketSTARTTIME:"<< setiosflags(ios::fixed) << setprecision(12)<<to_double(pkt2)<<"--";
    //cout<< "DIFFTIME:"<< setiosflags(ios::fixed) << setprecision(12)<<to_double(diffTime)<<"--";
    //cout<< "temptransferTIME:"<< setiosflags(ios::fixed) << setprecision(12)<<to_double(temp_transfer_time)<<"--";
    //cout<< "transferTIME:"<< setiosflags(ios::fixed) << setprecision(12)<<to_double(transfer_time)<<endl;
    if ((diffTime > sample_time) && (sample_count > singlepacket)) {
      burstcounter = burstcounter + 1;
       session_time = pkt1 - start_time;
       if (graph == 0) {
      cout<< "SESSIONSTARTTIME:"<< setiosflags(ios::fixed) << setprecision(12)<<to_double(start_time)<<":";
      cout<< "SESSIONENDTIME:"<< setiosflags(ios::fixed) << setprecision(12)<<to_double(pkt1)<<":";	
      cout <<"SESSIONPACKETS:"<<(sample_count -1) <<":";
      cout <<"SESSIONBYTES:";
      cout <<sample_bytes<<":";     
      cout << setiosflags(ios::fixed) << setprecision(12)<<"SESSIONTIME:"<<to_double(session_time) << endl;
       }
       else {
	 if ((burstcounter == 1)&& (noheader == 0)) {
	   cout <<"SESSIONSTART\tSESSIONEND\tPACKETCOUNT\tBYTECOUNT\tSESSIONDURATION(s)\n";
	 }
	 cout<<setiosflags(ios::fixed) << setprecision(12)<<to_double(start_time)<<"\t";
      cout<< setiosflags(ios::fixed) << setprecision(12)<<to_double(pkt1)<<"\t";	
      cout <<(sample_count -1) <<"\t";
     
      cout <<sample_bytes<<"\t";     
      cout << setiosflags(ios::fixed) << setprecision(12)<<to_double(session_time) << endl; 
       }
       sample_bytes =0;
      start_time = pkt2;
      sample_count = 1;
      diffTime = diffTime - diffTime;
    }
    if ((diffTime > sample_time) ) { 
      sample_bytes =0;
      session_time = pkt1 - start_time;
	
      start_time = pkt2;
      sample_count = 1;
      diffTime = diffTime - diffTime;
		  
    }
    time_t time = (time_t)cp->ts.tv_sec;
    //cout << payLoadSize <<endl;
    sample_bytes = sample_bytes + payLoadSize;
    /*if (sample_count > 1) {
      cout << setiosflags(ios::fixed) << setprecision(12)<< to_double(pkt2-start_time)<<"\t"<<to_double(diffTime) <<"\t";
      }*/	
    pkt1=pkt2 + transfer_time ;

    //fprintf(stdout, "[%4"PRIu64"]:%.4s:%.8s:", stat->matched, cp->nic, cp->mampid);
    if( print_date == 0 ) {
      //fprintf(stdout, "%u.", cp->ts.tv_sec);
    } else {
      static char timeStr[25];
      struct tm tm = *gmtime(&time);
      strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &tm);
      //	fprintf(stdout, "%s.", timeStr);
    }

    //int packetlength = cp->len;
		

    if ( max_packets > 0 && stat->matched >= max_packets) {
      /* Read enough pkts lets break. */
      printf("read enought packages\n");
      break;
    }
  }

  /* if ret == -1 the stream was closed properly (e.g EOF or TCP shutdown)
   * In addition EINTR should not give any errors because it is implied when the
   * user presses C-c */
  if ( ret > 0 && ret != EINTR ){
    fprintf(stderr, "stream_read() returned 0x%08X: %s\n", ret, caputils_error_string(ret));
  }

	
  /* Release resources */
  stream_close(stream);
  filter_close(&filter);
       
  return 0;
}




