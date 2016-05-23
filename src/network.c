/*
 * DHCPv4 Network Helpers
 *
 * XXX
 */

#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/filter.h>
#include <linux/if_infiniband.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "private.h"

typedef struct NDhcp4Packet NDhcp4Packet;

struct NDhcp4Packet {
        struct iphdr ip;
        struct udphdr udp;
        NDhcp4Message dhcp;
} _packed_ ;

static int n_dhcp4_network_raw_attach_filter(int fd,
                                             uint16_t arp_type,
                                             const uint8_t *chaddr,
                                             uint8_t dhcp_hlen,
                                             uint32_t xid) {
        struct sock_filter filter[] = {
                /* check packet length */
                BPF_STMT(BPF_LD + BPF_W + BPF_LEN, 0),                                                  /* A <- packet length */
                BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, sizeof(NDhcp4Packet), 1, 0),                        /* packet >= NDhcp4Packet ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                           /* ignore */

                /* verify IP protocol is UDP */
                BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(NDhcp4Packet, ip.protocol)),                /* A <- IP protocol */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 1, 0),                                 /* IP protocol == UDP ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                           /* ignore */

                /* verify no fragmentation is used */
                BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(NDhcp4Packet, ip.frag_off)),                /* A <- Flags */
                BPF_STMT(BPF_ALU + BPF_AND + BPF_K, 0x20),                                              /* A <- A & 0x20 (More Fragments bit) */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 1, 0),                                           /* A == 0 ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                           /* ignore */
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(NDhcp4Packet, ip.frag_off)),                /* A <- Flags + Fragment offset */
                BPF_STMT(BPF_ALU + BPF_AND + BPF_K, 0x1fff),                                            /* A <- A & 0x1fff (Fragment offset) */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 1, 0),                                           /* A == 0 ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                           /* ignore */

                /* verify UDP destination port */
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(NDhcp4Packet, udp.dest)),                   /* A <- UDP destination port */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, N_DHCP4_NETWORK_CLIENT_PORT, 1, 0),                 /* UDP destination port == DHCP client port ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                           /* ignore */

                /* verify dhcp OP is set to BOOTREPLY */
                BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(NDhcp4Packet, dhcp.header.op)),             /* A <- DHCP op */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, N_DHCP4_OP_BOOTREPLY, 1, 0),                        /* op == BOOTREPLY ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                           /* ignore */

                /* verify DHCP htype is @arp_type */
                BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(NDhcp4Packet, dhcp.header.htype)),          /* A <- DHCP header type */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, arp_type, 1, 0),                                    /* header type == arp_type ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                           /* ignore */

                /* match @hlen on DHCP hlen */
                BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(NDhcp4Packet, dhcp.header.hlen)),           /* A <- MAC address length */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, dhcp_hlen, 1, 0),                                   /* address length == dhcp_hlen ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                           /* ignore */

                /* match @xid on DHCP xid */
                BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(NDhcp4Packet, dhcp.header.xid)),            /* A <- client identifier */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, xid, 1, 0),                                         /* client identifier == xid ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                           /* ignore */

                /* match 6-bytes of @chaddr on DHCP chaddr */
                BPF_STMT(BPF_LD + BPF_IMM, htobe32(*(uint32_t *)chaddr)),                               /* A <- 4 bytes of client's MAC */
                BPF_STMT(BPF_MISC + BPF_TAX, 0),                                                        /* X <- A */
                BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(NDhcp4Packet, dhcp.header.chaddr)),         /* A <- 4 bytes of MAC from dhcp.chaddr */
                BPF_STMT(BPF_ALU + BPF_XOR + BPF_X, 0),                                                 /* A xor X */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 1, 0),                                           /* A == 0 ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                           /* ignore */
                BPF_STMT(BPF_LD + BPF_IMM, htobe16(*(uint16_t *)(chaddr + 4))),                         /* A <- remainder of client's MAC */
                BPF_STMT(BPF_MISC + BPF_TAX, 0),                                                        /* X <- A */
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(NDhcp4Packet, dhcp.header.chaddr) + 4),     /* A <- remainder of MAC from dhcp.chaddr */
                BPF_STMT(BPF_ALU + BPF_XOR + BPF_X, 0),                                                 /* A xor X */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 1, 0),                                           /* A == 0 ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                           /* ignore */

                /* verify DHCP magic is set correctly */
                BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(NDhcp4Packet, dhcp.magic)),                 /* A <- DHCP magic cookie */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, N_DHCP4_MESSAGE_MAGIC, 1, 0),                       /* cookie == DHCP magic cookie ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                           /* ignore */

                /* return entire message */
                BPF_STMT(BPF_RET + BPF_K, 65535),                                                       /* return all */
        };
        struct sock_fprog fprog = {
                .len = sizeof(filter) / sizeof(*filter),
                .filter = filter
        };
        int r;

        r = setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));
        if (r < 0)
                return -errno;

        return 0;
}

int n_dhcp4_network_raw_new(int ifindex,
                            struct sockaddr_ll *addrp,
                            uint16_t arp_type,
                            const uint8_t *mac_addr,
                            size_t n_mac_addr,
                            uint32_t xid) {
        static const int on = 1;
        const uint8_t *bcast;
        uint8_t chaddr[6];
        size_t hlen;
        int r, fd = -1;

        switch (arp_type) {
        case ARPHRD_ETHER: {
                /*
                 * Ethernet has 6-byte addresses and they're carried in the
                 * chaddr DHCP field, so provide them to the BPF filter.
                 */

                static const uint8_t ethernet_bcast[] = {
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
                };

                assert(n_mac_addr == ETH_ALEN);

                bcast = ethernet_bcast;
                memcpy(&chaddr, mac_addr, ETH_ALEN);
                hlen = ETH_ALEN;
                break;
        }
        case ARPHRD_INFINIBAND: {
                /*
                 * Infiniband has 20-byte addresses, so the chaddr field is too
                 * small to carry it. rfc4390 requires it to be cleared and
                 * instead the client-id carries the address.
                 */

                static const uint8_t infiniband_bcast[] = {
                        0x00, 0xff, 0xff, 0xff, 0xff, 0x12, 0x40, 0x1b,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0xff, 0xff, 0xff, 0xff
                };

                assert(n_mac_addr == INFINIBAND_ALEN);

                bcast = infiniband_bcast;
                memset(&chaddr, 0, sizeof(chaddr));
                hlen = 0;
                break;
        }
        default:
                return -EOPNOTSUPP;
        }

        fd = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd < 0) {
                r = -errno;
                goto error;
        }

        r = setsockopt(fd, SOL_PACKET, PACKET_AUXDATA, &on, sizeof(on));
        if (r < 0) {
                r = -errno;
                goto error;
        }

        r = n_dhcp4_network_raw_attach_filter(fd, arp_type, chaddr, hlen, xid);
        if (r < 0)
                goto error;

        addrp->sll_family = AF_PACKET;
        addrp->sll_protocol = htons(ETH_P_IP);
        addrp->sll_ifindex = ifindex;
        addrp->sll_hatype = htons(arp_type);
        addrp->sll_halen = n_mac_addr;
        memcpy(addrp->sll_addr, bcast, n_mac_addr);

        r = bind(fd, (struct sockaddr *)addrp, sizeof(*addrp));
        if (r < 0) {
                r = -errno;
                goto error;
        }

        return fd;

error:
        if (fd >= 0)
                close(fd);
        return r;
}

int n_dhcp4_network_udp_new(uint32_t address, uint16_t port) {
        struct sockaddr_in src = {
                .sin_family = AF_INET,
                .sin_port = htobe16(port),
                .sin_addr.s_addr = address,
        };
        static const int on = 1;
        static const int tos = IPTOS_CLASS_CS6;
        int r, fd = -1;

        fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd < 0) {
                r = -errno;
                goto error;
        }

        r = setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
        if (r < 0) {
                r = -errno;
                goto error;
        }

        r = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        if (r < 0) {
                r = -errno;
                goto error;
        }

        if (address == INADDR_ANY) {
                r = setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
                if (r < 0) {
                        r = -errno;
                        goto error;
                }

                r = setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
                if (r < 0) {
                        r = -errno;
                        goto error;
                }
        } else {
                r = setsockopt(fd, IPPROTO_IP, IP_FREEBIND, &on, sizeof(on));
                if (r < 0) {
                        r = -errno;
                        goto error;
                }
        }

        r = bind(fd, (struct sockaddr *)&src, sizeof(src));
        if (r < 0) {
                r = -errno;
                goto error;
        }

        return fd;

error:
        if (fd >= 0)
                close(fd);
        return r;
}
