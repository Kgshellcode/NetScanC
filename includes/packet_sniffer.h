#ifndef __PACKET_SNIFFER_H__
#define __PACKET_SNIFFER_H__

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> //Biblioteca libpcap
#include <netinet/in.h> //Estruturas de endereço (sockaddr)
#include <netinet/ip.h> //Para cabeçalhos IP
#include <netinet/tcp.h>
#include <arpa/inet.h> //Para inet_ntoa (converter IP para strings)

//Definição de tamanhos comuns dos cabeçalhos Ethernet, ip, tcp
#define ETHERNET_HEADER_SIZE 14 //Tamanho cabeçalho ethernet

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);


#endif