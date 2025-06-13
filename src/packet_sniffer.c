#include "/home/dev/Projects/C/NetScan/includes/packet_sniffer.h"// Inclui o seu arquivo de cabeçalho

// Função de callback que será chamada para cada pacote capturado
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    printf("----------------------------------------\n");
    printf("Pacote capturado! Tamanho: %d bytes\n", pkthdr->len);

    // 1. Análise do Cabeçalho IP (Camada 3)
    const struct iphdr *ip_header = (const struct iphdr *)(packet + ETHERNET_HEADER_SIZE);

    if (ip_header->version == 4) { // Verifica se é IPv4
        printf("  [IP Header]\n");
        printf("    Versão: %d\n", ip_header->version);
        printf("    Tamanho do Cabeçalho IP: %d bytes\n", ip_header->ihl * 4);
        printf("    Tamanho Total do IP: %d bytes\n", ntohs(ip_header->tot_len));
        printf("    Protocolo: %d (6=TCP, 17=UDP, 1=ICMP)\n", ip_header->protocol);

        struct in_addr src_ip_addr;
        struct in_addr dst_ip_addr;

        src_ip_addr.s_addr = ip_header->saddr;
        dst_ip_addr.s_addr = ip_header->daddr;

        printf("    IP de Origem: %s\n", inet_ntoa(src_ip_addr));
        printf("    IP de Destino: %s\n", inet_ntoa(dst_ip_addr));

        // 2. Análise do Cabeçalho TCP (Camada 4)
        if (ip_header->protocol == IPPROTO_TCP) { // Verifica se é TCP (protocolo 6)
            const struct tcphdr *tcp_header = (const struct tcphdr *)(packet + ETHERNET_HEADER_SIZE + (ip_header->ihl * 4));

            printf("  [TCP Header]\n");
            printf("    Porta de Origem: %d\n", ntohs(tcp_header->source));
            printf("    Porta de Destino: %d\n", ntohs(tcp_header->dest));
            printf("    Número de Sequência: %u\n", ntohl(tcp_header->seq));
            printf("    Número de Acknowledgment: %u\n", ntohl(tcp_header->ack_seq));
            printf("    Tamanho do Cabeçalho TCP: %d bytes\n", tcp_header->doff * 4);

            printf("    Flags: ");
            if (tcp_header->syn) printf("SYN ");
            if (tcp_header->ack) printf("ACK ");
            if (tcp_header->fin) printf("FIN ");
            if (tcp_header->rst) printf("RST ");
            if (tcp_header->psh) printf("PSH ");
            if (tcp_header->urg) printf("URG ");
            printf("\n");

        } else if (ip_header->protocol == IPPROTO_UDP) {
            printf("  [Protocolo UDP - não analisado detalhadamente neste exemplo]\n");
        } else if (ip_header->protocol == IPPROTO_ICMP) {
            printf("  [Protocolo ICMP - não analisado detalhadamente neste exemplo]\n");
        } else {
            printf("  [Protocolo IP Não Tratado: %d]\n", ip_header->protocol);
        }

    } else {
        printf("  [Não é um pacote IPv4 (versão %d)]\n", ip_header->version);
    }
}