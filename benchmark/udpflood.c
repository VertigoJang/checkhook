// Minimal UDP load generator for benchmarking (lab / isolated networks only).
// usage: ./udpflood <dst_ip> <dst_port>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
int main(int argc,char**argv){
    if(argc<3){fprintf(stderr,"usage: %s IP PORT\n",argv[0]);return 1;}
    int s=socket(AF_INET,SOCK_DGRAM,0);
    struct sockaddr_in d; memset(&d,0,sizeof d);
    d.sin_family=AF_INET; d.sin_port=htons(atoi(argv[2]));
    inet_pton(AF_INET,argv[1],&d.sin_addr);
    char buf[64]; memset(buf,0x41,sizeof buf);
    connect(s,(struct sockaddr*)&d,sizeof d);
    for(;;){ if(send(s,buf,sizeof buf,0)<0){} }
    return 0;
}
