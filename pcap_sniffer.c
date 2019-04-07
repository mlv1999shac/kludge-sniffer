//programm to capture all the packets 

#include<stdio.h>
#include<string.h>
#include<pcap.h>
#include<netinet/in.h>
#include<netinet/if_ether.h>
#include<time.h>
#include<net/ethernet.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <stdlib.h>

void my_pac_callback( u_char * user , 
const  struct pcap_pkthdr * pac_header ,
const u_char* packet
 );




void get_payload_in_ASCII(
 const u_char *payload;
int len;


);

void segment_details(char proc[] ,
 int tcp_len,
 int s,
 int d,
 int pac_len
);

struct sniff_ether {

u_char ether_dhost[ETHER_ADDR_LEN];
u_char ether_shost[ETHER_ADDR_LEN];
u_char ether_type;
struct  in_addr mac_src,mac_dst;
};


struct sniff_ip{
u_short ip_len;        
u_short ip_id; 
u_char  ip_p;
 struct  in_addr ip_src,ip_dst; 


 //u_char  ip_vhl;               

};
typedef u_int tcp_seq;

struct sniff_tcp{

        u_short sport;       
        u_short dport;
        tcp_seq th_seq;  
        tcp_seq th_ack; 


}; 
int main( int argc, char *argv[] )  {

char *iface;
char err_buf[PCAP_ERRBUF_SIZE];bpf_u_int32 net;

bpf_u_int32 mask;
pcap_t *handler;
struct pcap_pkthdr pac_header;
int timestamp=10000; 
const u_char *packet; 
struct bpf_program fb;
char filter[20]="port 23";


iface = pcap_lookupdev(err_buf);

if(iface== NULL){

printf("No interfaces found");
return 1;
}

iface=argv[1];

if ( pcap_lookupnet( iface, &net, &mask, err_buf) == -1 ) {
printf("Device details not found");
net=0;
mask=0;

}


handler= pcap_open_live(iface, BUFSIZ, 1, 1000,err_buf);


if(packet==NULL){

printf("No packet found");
return 2;

}

/*
if ( pcap_compile(handler, &fb , filter, 0, mask ) == -1){

printf("Complilation failed, couldnt parse filter");
return 2;

}


if( pcap_setfilter(handler,&fb) == -1 ){

printf("Not able to filter it out ");
return 2;
}

*/

pcap_loop(handler, 0,my_pac_callback , NULL);


return 0;
}



void my_pac_callback
(
            u_char * user, 
            const struct pcap_pkthdr * pac_header,
            const u_char *packet

){

static int count = 1;
printf("*****Packet Begins*****\n");  
printf("Packet Number : %d \n",count);
count++;

const struct sniff_ether *ether;
const struct sniff_ip *ip;
const struct sniff_tcp *tcp;

const u_char *ip_header;
const u_char *tcp_header;
const u_char *payload;
int ip_pac_len;
int tcp_pac_len;
int payload_len;

ether= (struct sniff_ether *)packet;
ip =(struct sniff_ip * ) (packet + 14);

if( ntohs(ether->ether_type) == ETHERTYPE_IP){
printf("**Frame\n");
printf("src mac : %s; ",inet_ntoa(ether->mac_src));
printf("dst mac : %s; ",inet_ntoa(ether->mac_dst));
printf("Type : IP\n");
printf("**Packet\n");
printf("IP protocol\n");
printf("Header length : %d; ",ip_pac_len);


}else if (ntohs(ether->ether_type) == ETHERTYPE_ARP){
printf("ARP : \n");
printf("\nSorry No arp spoofing availabel right now");
return;

}else if (ntohs(ether->ether_type) == ETHERTYPE_REVARP){
printf("REVARP: \n");
printf("\nNo REVARP available..............");
return;
}
const int ether_packet_len =14;

ip_header= packet + ether_packet_len; 
ip_pac_len =  ((*ip_header)& 0x0F);
ip_pac_len*=4;




printf("Src : %s; ",  inet_ntoa(ip->ip_src));
printf("Dst : %s; ",  inet_ntoa(ip->ip_dst));


tcp= (struct sniff_tcp *)(packet + 14 + ip_pac_len);

u_char  protocol = *(ip_header + 9);
tcp_header= packet+ether_packet_len+ip_pac_len;
tcp_pac_len =  (  *( tcp_header+12) & 0xF0 )>>4;
tcp_pac_len*=4;




printf("Protocol value :  %d ",protocol);
payload_len = (pac_header->caplen - (14 + ip_pac_len + tcp_pac_len));
payload = packet + 14 + ip_pac_len + tcp_pac_len;




switch(protocol) {
		case 6:
		
segment_details("TCP",tcp_pac_len, ntohs(tcp->sport), ntohs(tcp->dport), pac_header->caplen);
get_payload_in_ASCII(payload, payload_len);
	break;
		case 17:
			printf("Protocol: UDP\n");
			break;
		case 1:
			printf("Protocol: ICMP\n");
			break;
		case 4:
			printf("Protocol: IP IN IP\n");
			break;
		default:
			printf("Protocol: unknown\n");
			break;
	}


printf("Total lenght is %d\n",pac_header->len);
printf("Payload length : %d",payload_len);

printf("\n**********\n\n");


}

void get_payload_in_ASCII(const  u_char * payload, int len){
const u_char *temp =payload;
int byte_count =0;

if(len >0){
printf("Payload : ");
while (byte_count++ < len){

printf("%c",*temp);//in string format or converting asc2 to string
//printf("%d",*temp); in ascii 
//printf("%02X",*temp); in hex 
temp++;
}
return;
}else{
return;
}

}


void segment_details (char proc[],int tcp_len , int s, int d, int pac_len){

printf("\n**Segment\n");
printf("Protocol : %s\n", proc);
printf("Header lenght : %d; ",tcp_len);
printf("Source  port : %d; ",s );
printf("destination port : %d ",d );
printf("\nPacket lenght captured  : %d\n",pac_len);


//hex convertor


}
