#include "/home/dev/Projects/C/NetScan/includes/packet_sniffer.h"

int main(int argc, char *argv[]) {
    pcap_t *handle;                // Handle da sessão de captura
    char *dev;                     // Nome da interface de rede
    char errbuf[PCAP_ERRBUF_SIZE]; // Buffer para mensagens de erro
    struct bpf_program fp;         // Estrutura para o filtro compilado
    char filter_exp[] = "port 80 or port 443"; // Expressão de filtro
    bpf_u_int32 net;               // Máscara de rede da interface
    bpf_u_int32 mask;              // IP da interface
    int num_packets = 10;          // Número de pacotes a capturar

    // Permite especificar a interface de rede como argumento de linha de comando
    if (argc == 2) {
        dev = argv[1];
    } else {
        // 1. Encontrar uma interface de rede (se não for especificada)
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Não foi possível encontrar uma interface de rede: %s\n", errbuf);
            return 1;
        }
    }
    printf("Capturando na interface: %s\n", dev);

    // 2. Obter informações de IP e máscara de rede da interface
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Não foi possível obter a rede/máscara para a interface %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    // 3. Abrir a interface para captura
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Não foi possível abrir a interface %s para captura: %s\n", dev, errbuf);
        return 1;
    }

    // 4. Verificar o tipo de link de dados
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "A interface %s não é Ethernet. Este exemplo assume Ethernet.\n", dev);
        pcap_close(handle);
        return 1;
    }

    // 5. Compilar o filtro de pacotes
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Não foi possível compilar o filtro '%s': %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    // 6. Aplicar o filtro de pacotes
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Não foi possível aplicar o filtro '%s': %s\n", filter_exp, pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        return 1;
    }

    printf("Iniciando a captura de %d pacotes (ou 0 para indefinidamente se você mudar). Pressione Ctrl+C para parar...\n", num_packets);

    // 7. Loop de captura de pacotes
    pcap_loop(handle, num_packets, packet_handler, NULL);

    printf("Captura de pacotes finalizada.\n");

    // 8. Liberar recursos
    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}