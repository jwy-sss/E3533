#include<iostream>
#include<sstream>
#include<string>
#include<map>
#include<fstream>
#include <pcap.h>
#pragma warning(disable:4996)
using namespace std;
time_t beg;
/* 4 bytes IP address */
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
	u_int	op_pad;			// Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;

/*数据链路层帧格式*/
typedef struct mac_header
{
	u_char dest_addr[6];
	u_char src_addr[6];
	u_char type[2];
}mac_header;

/* prototype of the packet handler */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

long datalength = 0;     //数据长度
#define FROM_NIC
int main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	clock_t start = clock();
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "tcp";     //设置过滤器为TCP
	struct bpf_program fcode;
#ifdef FROM_NIC	
	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	/* Check if the user specified a valid adapter */
	if (inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");

		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter 适配器*/
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture. 
					   // 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Check the link layer. We support only Ethernet for simplicity. */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;


	//compile编译 the filter 过滤器
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//set the filter过滤器
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	//生成csv文件
	FILE* fp1;
	fp1 = fopen("result.csv", "wb");
	fputs("日期,时间,srcMAC,srcIP,destMAC,destIP,信息\n", fp1);
	fclose(fp1);

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);
#else
	/* Open the capture file */
	if ((adhandle = pcap_open_offline("E:\\1\\dns2.pcap",			// name of the device
		errbuf					// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the file.\n");
		return -1;
	}

	/* read and dispatch packets until EOF is reached */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	pcap_close(adhandle);
#endif
	return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	struct tm* ltime;
	char timestr[16];
	mac_header* mh;
	ip_header* ih;
	udp_header* uh;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;
	time_t timep;
	/*
	 * unused parameter
	 */
	(VOID)(param);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	int head = 54;     //略过文件头54位,提取user部分
	int writeflag = 0;  //是否要写入
	string user="-1";
	string password = "-1";
	string resultflag = "-1";
	string com;
	for (int i = 0; i < 4; i++)
	{
		com += (char)pkt_data[head + i];
	}
	if (com == "USER")
	{
		writeflag = 1;
		ostringstream sout;
		for (int i = head + 5; pkt_data[i] != 13; i++)//连接产生user名
		{
			sout << pkt_data[i];      
		}
		user = sout.str();
	}
	if (com == "PASS")
	{
		writeflag = 1;
		ostringstream sout;
		for (int i = head + 5; pkt_data[i] != 13; i++)//连接产生user名
		{
			sout << pkt_data[i];
		}
		password = sout.str();
	}
	if (com == "230 ")
	{
		writeflag = 1;
		resultflag = "succeed";
	}
	if (com == "530 ")
	{
		writeflag = 1;
		resultflag = "failed";
	}
	if (writeflag == 0)return;
	/* print timestamp and length of the packet */
	//printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);
	datalength += header->len;      //累加数据长度

	/*按二进制输出数据*/
	//printf("\n");
	int length = sizeof(mac_header) + sizeof(ip_header);
	//for (int i = 0; i < length; i++)
	//{
		//printf("%02X ", pkt_data[i]);
		//if ((i & 0xF) == 0xF)
		//	printf("\n");
	//}
	//printf("\n");
	mh = (mac_header*)pkt_data;
	//printf("mac_header:\n");
	//printf("\tdest_addr:");

	/* retireve the position of the ip header */
	ih = (ip_header*)(pkt_data +
		sizeof(mac_header)); //length of ethernet header

	/* retireve the position of the udp header */
	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header*)((u_char*)ih + ip_len);

	/* convert from network byte order to host byte order */
	sport = ntohs(uh->sport);
	dport = ntohs(uh->dport);

	/* print ip addresses and udp ports */
	if (writeflag == 1)
	{
		FILE* fp;
		freopen_s(&fp, "result.csv", "ab", stdout); //打开文件
		//输出时间
		printf("%d-%d-%d ,", 1900 + ltime->tm_year, 1 + ltime->tm_mon, ltime->tm_mday);
		printf("%s,", timestr);
		//源MAC
		for (int i = 0; i < 6; i++)
		{
			printf("%02X ", mh->src_addr[i]);
		}
		//源IP
		printf(",%d.%d.%d.%d,",
			ih->saddr.byte1,
			ih->saddr.byte2,
			ih->saddr.byte3,
			ih->saddr.byte4);
		//目的MAC
		for (int i = 0; i < 6; i++)
			printf("%02X ", mh->dest_addr[i]);
		//目的IP
		printf(",%d.%d.%d.%d,",
			ih->daddr.byte1,
			ih->daddr.byte2,
			ih->daddr.byte3,
			ih->daddr.byte4
			//dport
		);
		if (user != "-1")
			cout << user;
		if (password != "-1")
			cout << password;
		if (resultflag != "-1")
			cout << resultflag;
		printf("\n");
		fclose(fp);
	}
}