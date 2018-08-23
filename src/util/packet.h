#pragma once

#include <inttypes.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>

uint16_t packet_internet_checksum(uint8_t *data, size_t len);
uint16_t packet_internet_checksum_udp(const struct in_addr *src_addr, const struct in_addr *dst_addr,
                                      uint16_t src_port, uint16_t dst_port,
                                      uint8_t *data, size_t size, uint16_t checksum);

ssize_t packet_sendto_udp(int sockfd, void *buf, size_t len, int flags,
                          const struct sockaddr_in *src_paddr,
                          const struct sockaddr_ll *dest_haddr,
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
