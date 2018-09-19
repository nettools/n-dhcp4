#pragma once

#include <inttypes.h>
#include <linux/if_packet.h>
#include <linux/netdevice.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * `struct sockaddr_ll` is too small to fit the Infiniband
 * hardware address, introduce `struct sockaddr_ll2` which
 * is the same as the original, except the `sl_addr` field
 * is extended to fit all the supported hardware addresses.
 */
struct sockaddr_ll2 {
        unsigned short  sll_family;
        __be16          sll_protocol;
        int             sll_ifindex;
        unsigned short  sll_hatype;
        unsigned char   sll_pkttype;
        unsigned char   sll_halen;
        unsigned char   sll_addr[MAX_ADDR_LEN];
};

uint16_t packet_internet_checksum(const uint8_t *data, size_t len);
uint16_t packet_internet_checksum_udp(const struct in_addr *src_addr, const struct in_addr *dst_addr,
                                      uint16_t src_port, uint16_t dst_port,
                                      const uint8_t *data, size_t size, uint16_t checksum);

ssize_t packet_sendto_udp(int sockfd, void *buf, size_t len, int flags,
                          const struct sockaddr_in *src_paddr,
                          const struct sockaddr_ll2 *dest_haddr,
                          const struct sockaddr_in *dest_paddr);
ssize_t packet_recvfrom_udp(int sockfd, void *buf, size_t len, int flags,
                            struct sockaddr_in *src);

int packet_shutdown(int sockfd);

/*
 * Convenience Wrappers
 */
static inline ssize_t packet_recv_udp(int sockfd, void *buf, size_t len, int flags) {
        return packet_recvfrom_udp(sockfd, buf, len, flags, NULL);
}
