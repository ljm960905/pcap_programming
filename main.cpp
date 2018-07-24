#include <pcap.h>
#include <stdio.h>
#include <libnet.h>

struct libnet_ipv4_hdr *iph;
struct libnet_tcp_hdr *tcph;

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	static int count =1;
	struct libnet_ethernet_hdr *ep;
	unsigned short ether_type;
	int chcnt = 0;
	int length = pkthdr->len;
	int i;
	u_char *ptr;

	ep = (struct libnet_ethernet_hdr *)packet;
	packet += sizeof(struct libnet_ethernet_hdr);
	ether_type = ntohs(ep->ether_type);
	
	printf("--------------------------------------------------------\n");

	i = ETHER_ADDR_LEN;
	printf("Src mac address :");
	ptr = ep->ether_shost;
	do{
		printf("%s%x",(i==ETHER_ADDR_LEN)? " " : ":",*ptr++);
	}while(--i>0);
	printf("\n");

	i = ETHER_ADDR_LEN;
	printf("Dst mac address :");
	ptr = ep->ether_dhost;
	do{
		printf("%s%x",(i==ETHER_ADDR_LEN)? " " : ":",*ptr++);
	}while(--i>0);
	printf("\n");

	if(ether_type == ETHERTYPE_IP)
	{
		iph = (struct libnet_ipv4_hdr *)packet;
		printf("Src address : %s\n", inet_ntoa(iph->ip_src));
		printf("Dst address : %s\n", inet_ntoa(iph->ip_dst));
	
		if(iph->ip_p == IPPROTO_TCP)
		{
			tcph = (struct libnet_tcp_hdr *)(packet + iph->ip_hl*4);
			printf("Src port : %d\n", ntohs(tcph->th_sport));
			printf("Dst port : %d\n", ntohs(tcph->th_dport));
		}
		
		
		for(int j=0;j<16;j++){
			printf("%02x", *(packet++));
			if((++chcnt % 16) == 0)
				printf("\n");
		}
	}
}

int main(int argc, char* argv[]) {

  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1]; //get dev_name
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  pcap_loop(handle,0,callback,NULL);
  pcap_close(handle);
  return 0;
}
