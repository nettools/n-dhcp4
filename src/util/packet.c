/*
 * Raw packet utility library
 */

#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "packet.h"

/**
 * packet_internet_checksum() - compute the internet checksum
 * @data:               the data to checksum
 * @size:               the length of @data in bytes
 *
 * Computes the internet checksum for a given blob according
 * to RFC1071. @data must be 4-byte aligned.
 *
 * The internet checksum is the one's complement of the one's
 * complement sum of the 16-bit words of the data, padded with
 * zero-bytes if the data does not end on a 16-bit
 * boundary.
 *
 * Return: the checksum.
 */
uint16_t packet_internet_checksum(uint8_t *data, size_t size) {
        uint32_t *data32 = (uint32_t*)data;
        uint32_t *end32 = data32 + (size / sizeof(uint32_t));
        uint64_t acc = 0;

        while (data32 < end32)
                acc += *(data32++);

        if (size % sizeof(uint32_t)) {
                uint32_t data_tail = 0;

                memcpy(&data_tail, data32, size % sizeof(uint32_t));

                acc += data_tail;
        }

        while (acc >> 16)
                acc = (acc & 0xffff) + (acc >> 16);

        return ~acc;
}

/**
 * packet_internet_checskum_udp() - compute the internet checkum for a UDP packet
 * @src_addr:           source IP address
 * @dst_addr:           destinaiton IP address
 * @src_port:           source port
 * @dst_port:           destination port
 * @data:               payload
 * @size:               length of payload in bytes
 * @checksum:           current checksum, or 0
 *
 * Computes the internet checksum for a UDP packet, given the relevant IP and
 * UDP header fields. Note that the resulting checksum should be 0x0000 if verifying
 * a packet, but if computing the checksum for a packet the result must be flipped
 * to 0xffff if it is 0x0000, before inserting it into a packet header.
 *
 * Return: the checksum.
 */
uint16_t packet_internet_checksum_udp(const struct in_addr *src_addr, const struct in_addr *dst_addr,
                                      uint16_t src_port, uint16_t dst_port,
                                      uint8_t *data, size_t size, uint16_t checksum) {
        struct {
                struct in_addr src;
                struct in_addr dst;
                uint8_t _zeros;
                uint8_t protocol;
                uint16_t length;
                struct udphdr udp;
        } __attribute__((__packed__)) udp_phdr = {
                .src.s_addr = src_addr->s_addr,
                .dst.s_addr = dst_addr->s_addr,
                .protocol = IPPROTO_UDP,
                .length = htons(sizeof(struct udphdr) + size),
                .udp = {
                        .source = htons(src_port),
                        .dest = htons(dst_port),
                        .len = htons(sizeof(struct udphdr) + size),
                        .check = checksum,
                },
        };
        uint32_t *data32 = (uint32_t*)data;
        uint32_t *end32 = data32 + (size / sizeof(uint32_t));
        uint64_t acc = 0;

        for (size_t i = 0; i < sizeof(udp_phdr) / sizeof(uint32_t); ++i)
                acc += ((uint32_t*)&udp_phdr)[i];

        while (data32 < end32)
                acc += *(data32++);

        if (size % sizeof(uint32_t)) {
                uint32_t data_tail = 0;

                memcpy(&data_tail, data32, size % sizeof(uint32_t));

                acc += data_tail;
        }

        while (acc >> 16)
                acc = (acc & 0xffff) + (acc >> 16);

        return ~acc;
}

/**
 * packet_sendto_udp() - send UDP packet on AF_PACKET socket
 * @sockfd:             AF_PACKET/SOCK_DGRAM socket
 * @buf:                payload
 * @len:                length of payload in bytes
 * @flags:              flags, see sendto(2)
 * @src_paddr:          source protocol address, see ip(7)
 * @dest_haddr:         destination hardware address, see packet(7)
 * @dest_paddr:         destination protocol address, see ip(7)
 *
 * Sends an UDP packet on a AF_PACKET socket directly to a hardware
 * address. The difference between this and sendto() on an AF_INET
 * socket is that no routing is performed, so the packet is delivered
 * even if the destination IP is not yet configured on the destination
 * host.
 *
 * Return: the number of payload bytes sent on success, or -1 on error.
 */
ssize_t packet_sendto_udp(int sockfd, void *buf, size_t len, int flags,
                          const struct sockaddr_in *src_paddr,
                          const struct sockaddr_ll *dest_haddr,
                          const struct sockaddr_in *dest_paddr) {
        struct udphdr udp_hdr = {
                .source = src_paddr->sin_port,
                .dest = dest_paddr->sin_port,
                .len = htons(sizeof(udp_hdr) + len),
        };
        struct iphdr ip_hdr = {
                .version = IPVERSION,
                .ihl = sizeof(ip_hdr) / 4, /* Length of header in multiples of four bytes */
                .tos = IPTOS_CLASS_CS6, /* Class Selector for network control */
                .tot_len = htons(sizeof(ip_hdr) + sizeof(udp_hdr) + len),
                .frag_off = htons(IP_DF), /* Do not fragment */
                .ttl = IPDEFTTL,
                .protocol = IPPROTO_UDP,
                .saddr = src_paddr->sin_addr.s_addr,
                .daddr = dest_paddr->sin_addr.s_addr,
        };
        struct iovec iov[3] = {
                {
                        .iov_base = &ip_hdr,
                        .iov_len = sizeof(ip_hdr),
                },
                {
                        .iov_base = &udp_hdr,
                        .iov_len = sizeof(udp_hdr),
                },
                {
                        .iov_base = buf,
                        .iov_len = len,
                },
        };
        struct msghdr msg = {
                .msg_name = (void*)dest_haddr,
                .msg_namelen = sizeof(*dest_haddr),
                .msg_iov = iov,
                .msg_iovlen = sizeof(iov) / sizeof(iov[0]),
        };
        ssize_t pktlen;

        ip_hdr.check = packet_internet_checksum((void*)&ip_hdr, sizeof(ip_hdr));
        /*
         * 0x0000 and 0xffff are equivalent for computing the checksum,
         * but 0x0000 is reserved to mean that the checksum is not set
         * and should be ignored by the receiver.
         */
        udp_hdr.check = packet_internet_checksum_udp(&src_paddr->sin_addr, &dest_paddr->sin_addr,
                                                     ntohs(src_paddr->sin_port), ntohs(dest_paddr->sin_port),
                                                     buf, len, 0) ?: 0xffff;

        pktlen = sendmsg(sockfd, &msg, flags);
        if (pktlen < 0)
                return pktlen;

        /* Return the length sent, excluding the headers. */
        assert((size_t)pktlen >= sizeof(ip_hdr) + sizeof(udp_hdr));
        return pktlen - sizeof(ip_hdr) - sizeof(udp_hdr);
}

/**
 * packet_recvfrom_upd() - receive UDP packet from AF_PACKET socket
 * @sockfd:             AF_PACKET/SOCK_DGRAM socket
 * @buf:                buffor for payload
 * @len:                max length of payload in bytes
 * @flags:              flags, see recvfrom(2)
 * @src:                return argumnet for source address, or NULL, see ip(7)
 *
 * Receives an UDP packet on a AF_PACKET socket. The difference between
 * this and recevfrom() on an AF_INET socket is that the packet will be
 * received even if the destination IP address has not been configured
 * on the interface.
 *
 * Return: the number of payload bytes received on success, or -1 on error.
 */
ssize_t packet_recvfrom_udp(int sockfd, void *buf, size_t len, int flags,
                            struct sockaddr_in *src) {
        union {
                struct iphdr hdr;
                uint8_t data[2^4 * 4]; /*
                                        * The ihl field is four bits, representing the
                                        * length of the header as multiples of four
                                        * bytes, determining the max IP header length.
                                        */
        } ip_hdr;
        struct udphdr udp_hdr;
        struct iovec iov[3] = {
                {
                        .iov_base = &ip_hdr,
                },
                {
                        .iov_base = &udp_hdr,
                        .iov_len = sizeof(udp_hdr),
                },
                {
                        .iov_base = buf,
                        .iov_len = len,
                },
        };
        uint8_t cmsgbuf[CMSG_LEN(sizeof(struct tpacket_auxdata))];
        struct msghdr msg = {
                .msg_iov = iov,
                .msg_iovlen = sizeof(iov) / sizeof(iov[0]),
                .msg_control = cmsgbuf,
                .msg_controllen = sizeof(cmsgbuf),
        };
        struct cmsghdr *cmsg;
        bool checksum = true;
        ssize_t pktlen;
        size_t hdrlen;

        /* Peek packet to obtain the real IP header length */
        pktlen = recv(sockfd, &ip_hdr.hdr, sizeof(ip_hdr.hdr), MSG_PEEK | flags);
        if (pktlen < 0)
                return pktlen;

        if ((size_t)pktlen < sizeof(ip_hdr.hdr)) {
                /*
                 * Received packet is smaller than the minimal IP header length,
                 * discard it.
                 */
                recv(sockfd, NULL, 0, 0);
                return 0;
        }

        if (ip_hdr.hdr.version != IPVERSION) {
                /*
                 * This is not an IPv4 packet, discard it.
                 */
                recv(sockfd, NULL, 0, 0);
                return 0;
        }

        hdrlen = ip_hdr.hdr.ihl * 4;

        if (hdrlen < sizeof(ip_hdr.hdr)) {
                /*
                 * The length given in the header is smaller than the minimum
                 * header length, discard the packet.
                 */
                recv(sockfd, NULL, 0, 0);
                return 0;
        }

        /*
         * Set the length of the IP header in the incoming packet.
         */
        iov[0].iov_len = hdrlen;

        /*
         * Read the full packet.
         */
        pktlen = recvmsg(sockfd, &msg, flags);
        if (pktlen < 0)
                return pktlen;

        cmsg = CMSG_FIRSTHDR(&msg);
        if (cmsg) {
                if (cmsg->cmsg_level == SOL_PACKET &&
                    cmsg->cmsg_type == PACKET_AUXDATA &&
                    cmsg->cmsg_len == CMSG_LEN(sizeof(struct tpacket_auxdata))) {
                        struct tpacket_auxdata *aux = (struct tpacket_auxdata*)CMSG_DATA(cmsg);

                        /* The checksum has not yet been fully computed, so the
                         * value is garbage and should be ignored. */
                        checksum = !(aux->tp_status & TP_STATUS_CSUMNOTREADY);
                }
        }

        /* Bounds checks */

        if ((size_t)pktlen < hdrlen + sizeof(udp_hdr))
                /*
                 * The packet is too small to contain an UDP header, discard it.
                 */
                return 0;
        else if ((size_t)pktlen < hdrlen + ntohs(udp_hdr.len))
                /*
                 * The received packet is smaller than the declared size, discard it.
                 */
                return 0;
        else
                /*
                 * Make @pktlen the length of the packet payload, without IP/UDP headers.
                 */
                pktlen = ntohs(udp_hdr.len) - sizeof(struct udphdr);

        /* IP */

        if (ip_hdr.hdr.protocol != IPPROTO_UDP)
                /*
                 * The packet is not UDP, discard it.
                 */
                return 0;

        if (ip_hdr.hdr.frag_off & htons(IP_MF | IP_OFFMASK))
                /*
                 * This is a packet fragment, discard it.
                 */
                return 0;

        if (checksum && packet_internet_checksum(ip_hdr.data, hdrlen))
                /*
                 * The IP checksum is invalid, discard the packet.
                 */
                return 0;

        /* UDP */

        if (checksum && udp_hdr.check) {
               if (packet_internet_checksum_udp(&(struct in_addr){ ip_hdr.hdr.saddr }, &(struct in_addr){ ip_hdr.hdr.daddr },
                                                ntohs(udp_hdr.source), ntohs(udp_hdr.dest),
                                                buf, pktlen, udp_hdr.check)) {
                        /*
                         * The UDP checsum is invalid, discard the packet.
                         */
                        return 0;
               }
        }

        if (src) {
                src->sin_family = AF_INET;
                src->sin_addr.s_addr = ip_hdr.hdr.saddr;
                src->sin_port = udp_hdr.source;
        }

        /*
         * Return the length of the received payload written to @buf, not including the IP and UDP header.
         */
        return pktlen;
}

/**
 * packet_shutdown() - shutdown socket for future receive operations
 * @sockfd:     socket
 *
 * Partially emulates `shutdown(sockfd, SHUT_RD)`, in the sense that no
 * further packets may be queued on the socket. All packets that are
 * already queued will still be delivered, but once -EAGAIN is returned
 * we are guaranteed never to be able to read more packets in the future.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int packet_shutdown(int sockfd) {
        struct sock_filter filter[] = {
                BPF_STMT(BPF_RET + BPF_K, 0), /* discard all packets */
        };
        struct sock_fprog fprog = {
                .filter = filter,
                .len = sizeof(filter) / sizeof(filter[0]),
        };
        int r;

        r = setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));
        if (r < 0)
                return -errno;

        return 0;
}
