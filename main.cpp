#include <pcap.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <array>
#include <iostream>
#include <boost/json/src/json.hpp>
#include <bprinter/include/bprinter/table_printer.h>
#include <boost/program_options.hpp>

#ifndef ETHER_HDRLEN
#define ETHER_HDRLEN 14
#endif

using namespace std;
using json = nlohmann::json;
using TablePrinter = bprinter::TablePrinter;
namespace po = boost::program_options;

json handle_ethernet(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
json handle_IP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
json handle_TCP(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
json handle_UDP(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
json handle_ICMP(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);

typedef struct _configuration Configuration;
struct _configuration {
    TablePrinter *tp;
    char* format;
};

/**
 * Структура ip-пакета
 */
struct my_ip
{
    u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
    u_int8_t	ip_tos;		/* type of service */
    u_int16_t	ip_len;		/* total length */
    u_int16_t	ip_id;		/* identification */
    u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    u_int8_t	ip_ttl;		/* time to live */
    u_int8_t	ip_p;		/* protocol */
    u_int16_t	ip_sum;		/* checksum */
    struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

/*
 * Колбэк для анализа заголовка ethernet-кадра
 */
void my_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    try {
        json js, jsether;
        jsether = handle_ethernet(args,pkthdr,packet);
        u_int16_t type = jsether["type"];

        Configuration *conf = (Configuration *) args;
        TablePrinter *tp = conf->tp;
        char* format = conf->format;

        js["ether"] = jsether;
        string srcmac = jsether["srcmac"];
        string dstmac = jsether["dstmac"];

        if(type == ETHERTYPE_IP)
        {
            /* handle IP packet */
            json jsudp;
            json jstcp;
            json jsHandle = handle_IP(args,pkthdr,packet);
            js["ip"] = jsHandle;
            u_int8_t ip_prot = jsHandle["prot"];
            string prot;
            int srcport = 0;
            int dstport = 0;
            string ssrcport;
            string sdstport;
            string srcip = jsHandle["src"];
            string dstip = jsHandle["dst"];
            prot = "ip";
            switch(ip_prot)
            {
                case IPPROTO_ICMP:
                    prot = "icmp";
                    js["icmp"] = handle_ICMP(args,pkthdr,packet);
                    ssrcport = js["icmp"]["type"];
                    if((ssrcport == "ICMP_UNREACH") || (ssrcport == "ICMP_REDIRECT") ||(ssrcport == "ICMP_TIMXCEED"))
                        sdstport = js["icmp"]["code"];
                    srcport = 0;
                    dstport = 0;
                    break;
                case IPPROTO_TCP:
                    prot = "tcp";
                    js["tcp"] = handle_TCP(args,pkthdr,packet);
                    srcport = (js["tcp"]["srcport"]);
                    dstport = (js["tcp"]["dstport"]);
                    break;
                case IPPROTO_UDP:
                    prot = "udp";
                    js["udp"] = handle_UDP(args,pkthdr,packet);
                    srcport = (js["udp"]["srcport"]);
                    dstport = (js["udp"]["dstport"]);
                    break;
            }
            if(strcmp(format, "json") == 0)
                cout << js << endl;
            else
            {
                if(ip_prot == IPPROTO_ICMP)
                    *tp << srcmac << dstmac << prot << srcip << dstip << ssrcport << sdstport;
                else
                    *tp << srcmac << dstmac << prot << srcip << dstip << srcport << dstport;
            }
        }
        else if(type == ETHERTYPE_ARP)
        {
            /* handle arp packet */
        }
        else if(type == ETHERTYPE_REVARP)
        {
            /* handle reverse arp packet */
        }
    }
    catch(exception &e)
    {
        cerr << e.what() << endl;
    }


}

/**
 * Анализ tcp-пакета
 */
json handle_TCP(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    const struct ip* ipHeader;
    const struct tcphdr* tcpHeader;
    u_int sourcePort, destPort;
    u_char *data;
    int dataLength = 0;
    string dataStr = "";
    json js;

    ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
    if (ipHeader->ip_p == IPPROTO_TCP)
    {
        tcpHeader = (tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        sourcePort = ntohs(tcpHeader->source);
        destPort = ntohs(tcpHeader->dest);
        data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
        dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));

        js["srcport"] = sourcePort;
        js["dstport"] = destPort;

        for (int i = 0; i < dataLength; i++)
        {
            if ((data[i] >= 32 && data[i] <= 126) || data[i] == 10 || data[i] == 11 || data[i] == 13)
            {
                dataStr += (char)data[i];
            } else
            {
                dataStr += ".";
            }
        }
        if (dataLength > 0)
        {
            js["data"] = dataStr;
        }
    }
    return js;
}

/**
 * Анализ udp-пакета
 */
json handle_UDP(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    const struct ip* ipHeader;
    const struct udphdr* udpHeader;
    json js;

    u_int sourcePort, destPort;
    u_char *data;
    int dataLength = 0;
    string dataStr = "";

    ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
    if (ipHeader->ip_p == IPPROTO_UDP)
    {
        udpHeader = (udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        sourcePort = ntohs(udpHeader->uh_sport);
        destPort = ntohs(udpHeader->uh_dport);
        data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
        dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));

        js["srcport"] = sourcePort;
        js["dstport"] = destPort;

        for (int i = 0; i < dataLength; i++)
        {
            if ((data[i] >= 32 && data[i] <= 126) || data[i] == 10 || data[i] == 11 || data[i] == 13)
            {
                dataStr += (char)data[i];
            } else
            {
                dataStr += ".";
            }
        }
        if (dataLength > 0)
        {
            js["data"] = dataStr;
        }
    }
    return js;
}

/**
 * Анализ ip-пакета
 */
json handle_IP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    const struct my_ip* ip;
    u_int length = pkthdr->len;
    u_int hlen,off,version;
    int i;
    u_int8_t prot;
    json js;

    int len;

    /* jump pass the ethernet header */
    ip = (struct my_ip*)(packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header);

    /**
     * Protocol number
     */
    prot = ip->ip_p;

    /* check to see we have a packet of valid length */
    if (length < sizeof(struct my_ip))
    {
        printf("truncated ip %d",length);
        return -1;
    }

    len     = ntohs(ip->ip_len);
    hlen    = IP_HL(ip); /* header length */
    version = IP_V(ip);/* ip version */

    /* check version */
    if(version != 4)
    {
        fprintf(stdout,"Unknown version %d\n",version);
        return -1;
    }

    /* check header length */
    if(hlen < 5 )
    {
        fprintf(stdout,"bad-hlen %d \n",hlen);
    }

    /* see if we have as much packet as we should */
    if(length < len)
        printf("\ntruncated IP - %d bytes missing\n",len - length);

    /* Check to see if we have the first fragment */
    off = ntohs(ip->ip_off);
    if((off & 0x1fff) == 0 )/* aka no 1's in first 13 bits */
    {
        js["src"] = inet_ntoa(ip->ip_src);
        js["dst"] = inet_ntoa(ip->ip_dst);
        js["hlen"] = hlen;
        js["prot"] = prot;
        js["version"] = version;
        js["len"] = len;
        js["offset"] = off;
        /* print SOURCE DESTINATION hlen version len offset */
        /*fprintf(stdout,"IP: ");
        fprintf(stdout,"[srcip: %s] -> ",
                inet_ntoa(ip->ip_src));
        fprintf(stdout,"[dstip:%s] [header_length:%d] [version:%d] [packet_lenght:%d] [offset:%d]\n",
                inet_ntoa(ip->ip_dst),
                hlen,version,len,off);*/
    }
    return js;
}

/**
 * Анализ icmp-пакета
 */
json handle_ICMP(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    const struct icmp* icmpHeader;
    json js;
    u_char icmpType;
    u_char	icmpCode;		/* type sub code */
    u_short	icmpCksum;		/* ones complement cksum of struct */

    icmpHeader = (icmp*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    icmpType = icmpHeader->icmp_type;
    icmpCode = icmpHeader->icmp_code;
    icmpCksum = icmpHeader->icmp_cksum;
    js["chsum"] = icmpCksum;
    switch(icmpType)
    {
        case ICMP_ECHOREPLY:
            js["type"] = "ICMP_ECHOREPLY";
            break;
        case ICMP_UNREACH:
            js["type"] = "ICMP_UNREACH";
            switch(icmpCode)
            {
                case ICMP_UNREACH_NET:
                    js["code"] = "ICMP_UNREACH";
                    break;
                case ICMP_UNREACH_HOST:
                    js["code"] = "ICMP_UNREACH_HOST";
                    break;
                case ICMP_UNREACH_PROTOCOL:
                    js["code"] = "ICMP_UNREACH_PROTOCOL";
                    break;
                case ICMP_UNREACH_PORT:
                    js["code"] = "ICMP_UNREACH_PORT";
                    break;
                case ICMP_UNREACH_NEEDFRAG:
                    js["code"] = "ICMP_UNREACH_NEEDFRAG";
                    break;
                case ICMP_UNREACH_SRCFAIL:
                    js["code"] = "ICMP_UNREACH_SRCFAIL";
                    break;
            }
            break;
        case ICMP_SOURCEQUENCH:
            js["type"] = "ICMP_SOURCEQUENCH";
            break;
        case ICMP_REDIRECT:
            js["type"] = "ICMP_REDIRECT";
            switch(icmpCode)
            {
                case ICMP_REDIRECT_NET:
                    js["code"] = "ICMP_REDIRECT_NET";
                    break;
                case ICMP_REDIRECT_HOST:
                    js["code"] = "ICMP_REDIRECT_HOST";
                    break;
                case ICMP_REDIRECT_TOSNET:
                    js["code"] = "ICMP_REDIRECT_TOSNET";
                    break;
                case ICMP_REDIRECT_TOSHOST:
                    js["code"] = "ICMP_REDIRECT_TOSHOST";
                    break;
            }
            break;
        case ICMP_ECHO:
            js["type"] = "ICMP_ECHO";
            break;
        case ICMP_PARAMPROB:
            js["type"] = "ICMP_PARAMPROB";
            break;
        case ICMP_TSTAMP:
            js["type"] = "ICMP_TSTAMP";
            break;
        case ICMP_TSTAMPREPLY:
            js["type"] = "ICMP_TSTAMPREPLY";
            break;
        case ICMP_IREQ:
            js["type"] = "ICMP_IREQ";
            break;
        case ICMP_IREQREPLY:
            js["type"] = "ICMP_IREQREPLY";
            break;
        case ICMP_MASKREQ:
            js["type"] = "ICMP_MASKREQ";
            break;
        case ICMP_MASKREPLY:
            js["type"] = "ICMP_MASKREPLY";
            break;
        case ICMP_TIMXCEED:
            js["type"] = "ICMP_TIMXCEED";
            switch(icmpCode)
            {
                case ICMP_TIMXCEED_INTRANS:
                    js["code"] = "ICMP_TIMXCEED_INTRANS";
                    break;
                case ICMP_TIMXCEED_REASS:
                    js["code"] = "ICMP_TIMXCEED_REASS";
                    break;
            }
            break;
    }
    return js;
}

/*
 * Анализ ethernet-кадра
 */
json handle_ethernet (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    json js;
    u_int caplen = pkthdr->caplen;
    u_int length = pkthdr->len;
    js["caplen"] = caplen;
    js["length"] = length;
    struct ether_header *eptr;  /* net/ethernet.h */
    u_short ether_type;

    if (caplen < ETHER_HDRLEN)
    {
        fprintf(stdout,"Packet length less than ethernet header length\n");
        return -1;
    }

    eptr = (struct ether_header *) packet;
    ether_type = ntohs(eptr->ether_type);
    js["type"] = ether_type;


    js["srcmac"] = ether_ntoa((struct ether_addr*)eptr->ether_shost);
    js["dstmac"] = ether_ntoa((struct ether_addr*)eptr->ether_dhost);

    /* check to see if we have an ip packet */
    if (ether_type == ETHERTYPE_IP)
    {
        //fprintf(stdout,"(IP)");
    }
    else  if (ether_type == ETHERTYPE_ARP)
    {
        //fprintf(stdout,"(ARP)");
    }
    else  if (eptr->ether_type == ETHERTYPE_REVARP)
    {
        //fprintf(stdout,"(RARP)");
    }
    else {
        //fprintf(stdout,"(?)");
    }

    return js;
}

/**
 * Main function
 */
int main(int argc,char **argv)
{
    /*Options of boost*/
    po::options_description desc("Allowed options");
    desc.add_options()
            ("help,h", "produce help message")
            ("dev,d", po::value<string>(), "set device")
            ("count,c", po::value<int>(), "set count of sniffing packets")
            ("json", "set json output format")
            ;
    po::variables_map vm;
    po::store(po::parse_command_line(argc, (const char**)argv, desc), vm);
    po::notify(vm);

    /*In case if help*/
    if(vm.count("help"))
    {
        cout << desc << "\n";
        return 1;
    }

    string dev;
    /*In case if dev*/
    if(vm.count("dev"))
    {
        dev = vm["dev"].as<string>();
    }
    else
    {
        cout << "Please specify device" << endl << "Use prefix -h" << endl;
        return 1;
    }

    string format = "table";
    /*In case if output format is json*/
    if(vm.count("json"))
    {
        format = "json";
    }

    int count = -1;
    /*Set count of packets*/
    if(vm.count("count"))
    {
        count = vm["count"].as<int>();
    }

    Configuration conf;
    TablePrinter tp(&cout);
    if(strcmp(format.c_str(), "json") != 0)
    {
        tp.AddColumn("SRCMAC", 20);
        tp.AddColumn("DSTMAC", 20);
        tp.AddColumn("PROTOCOL", 5);
        tp.AddColumn("SRCIP", 15);
        tp.AddColumn("DSTIP", 15);
        tp.AddColumn("SRCPORT", 15);
        tp.AddColumn("DSTPORT", 15);
        tp.PrintHeader();
    }


    conf.tp = &tp;
    conf.format = (char*)format.c_str();

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    bpf_u_int32 maskp;          /* subnet mask               */
    bpf_u_int32 netp;           /* ip                        */

    /* Options must be passed in as a string because I am lazy */
    if(argc < 2)
    {
        fprintf(stdout,"Usage: %s numpackets \"options\"\n",argv[0]);
        return 0;
    }

    /* ask pcap for the network address and mask of the device */
    pcap_lookupnet(dev.c_str(),&netp,&maskp,errbuf);

    /*
     * open device for reading. NOTE: defaulting to
     * promiscuous mode
     */
    descr = pcap_open_live(dev.c_str(),BUFSIZ,1,-1,errbuf);
    if(descr == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }

    /* ... and loop */
    pcap_loop(descr,count,my_callback,(u_char*)&conf);
    if(strcmp(format.c_str(), "json") != 0)
        tp.PrintFooter();

    fprintf(stdout,"\nfinished\n");
    return 0;
}
