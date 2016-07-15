#include <stdio.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void packet_view(unsigned char *, const struct pcap_pkthdr *, const unsigned char *);

int main(int argc, char *argv[])
{
 char *dev; 
 char errbuf[PCAP_ERRBUF_SIZE]; 
 bpf_u_int32 net, mask; 
 struct in_addr net_addr, mask_addr; 
 pcap_t *pd;     // 패킷 캡쳐 디스크립터
 
 if((dev = pcap_lookupdev(errbuf)) == NULL) { 
  fprintf(stdout, "\nerror : pcap_lookupdev()\n");
  perror(errbuf);
  exit(1);
 }
 
  if(pcap_lookupnet(dev, &net, &mask, errbuf) < 0) { 
   fprintf(stdout, "\nerror : pcap_lookupnet()\n");
   perror(errbuf);
   exit(1);
  }
   if((pd = pcap_open_live(dev, 1024, 1, 100, errbuf)) == NULL) {   //패킷 캡쳐 디스크립터를 얻음
    fprintf(stdout, "\nerror : pcap_open_live()\n");
    perror(errbuf);
    exit(1);
   }
   
   if(pcap_loop(pd, 0, packet_view, 0) < 0) {   //패킷을 하나 잡을때 마다 packet_view 함수 호출해서 넘겨줌
    fprintf(stdout, "\nerror : pcap_loop()\n");  // PCAP_CNT : 5로 선언=> 패킷 잡는 수 / -1로 주면 무한 반복
    fprintf(stdout, "%s\n", pcap_geterr(dev));
    exit(1);
   }
   
   pcap_close(pd);
   
   return 1;
}

void packet_view(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *p)  // *p : 내가 잡은 패킷의 처음
{
 if(*(p+23) == 6){
 printf("TCP\n");
 printf("Source IP : %d.%d.%d.%d\n", *(p+26), *(p+27), *(p+28), *(p+29));
 printf("Source Mac : %02x:%02x:%02x:%02x:%02x:%02x\n", *(p+6), *(p+7), *(p+8), *(p+9), *(p+10), *(p+11));
 printf("Source Port : %d\n", *(p+34) * 256 + *(p+35));
 printf("Destination IP : %d.%d.%d.%d\n", *(p+30), *(p+31), *(p+32), *(p+33));
 printf("Destination Mac : %02x:%02x:%02x:%02x:%02x:%02x\n", *(p), *(p+1), *(p+2), *(p+3), *(p+4), *(p+5));
 printf("Destination Port : %d\n", *(p+36) * 256 + *(p+37));
 printf("=======================================================\n\n");
 }
 else{
	printf("==========================\n");
	printf("%d\n", *(p+23));
	printf("==========================\n");
 } 
 return ;
}
