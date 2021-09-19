#include <pcap.h>
#include <stdio.h>
#include <string.h>

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main(int argc, char *argv[])
{
    pcap_t *handle;			/* Session handle */
    pcap_dumper_t *dumpfile; /* pcap file writer */
    char dev[] = "wlan0";			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter */
    char filter_exp[] = "port 5500";	/* The filter expression */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    int count;
    // struct pcap_pkthdr *header;	/* The header that pcap gives us */
    // const u_char *packet;		/* The actual packet */

    /* Define the device */
    // dev = pcap_lookupdev(errbuf);
    // if (dev == NULL) {
    //     fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
    //     return(2);
    // }
    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    /* Grab a packet */
    // packet = pcap_next(handle, &header);
    // if (packet == NULL) {
    //     printf("No packet found.\n");
    //     return (2);
    // }
    /* Print its length */
    // printf("Jacked a packet with length of [%d]\n", header.len);

    
    
    if(dumpfile==NULL)
    {
        fprintf(stderr,"\nError opening output file\n");
        return -1;
    }
    while(1){
        if (count == 10){
            count = 0;
        }
        printf("Current:%d",count);
        /* Writing pcap file */
        /* Create the output file. */
        char str1[20] = "/home/pi/rpi_realtime_pc/output";
        char str2[20];
        sprintf(str2, "%d", count);
        strcat(str1,str2);
        char str3[20] = ".pcap";
        strcat(str1,str3);
        dumpfile = pcap_dump_open(handle, str1);
        /* start the capture */
        pcap_loop(handle, 10, packet_handler, (unsigned char *)dumpfile);
        pcap_dump_close(dumpfile);
        count++;
    }
    
    // pcap_dump((unsigned char *)dumpfile, header, packet);
    /* And close the session */
    pcap_close(handle);
    
    return(0);
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    /* save the packet on the dump file */
    printf("\nWriting to file");
    pcap_dump(dumpfile, header, pkt_data);
}

