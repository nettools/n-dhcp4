/*
 * DHCP specific low-level network helpers
 */

#include <errno.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <linux/udp.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "n-dhcp4-private.h"
#include "util/packet.h"

/**
 * n_dhcp4_network_client_packet_socket_new() - create a new DHCP4 client packet socket
 * @sockfdp:            return argumnet for the new socket
 * @ifindex:            interface index to bind to
 *
 * Create a new AF_PACKET/SOCK_DGRAM socket usable to listen to and send DHCP client
 * packets before an IP address has been configured.
 *
 * Only unfragmented DHCP packets from a server to a client destined for the given
 * ifindex is returned.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int n_dhcp4_network_client_packet_socket_new(int *sockfdp, int ifindex) {
        _cleanup_(n_dhcp4_closep) int sockfd = -1;
        struct sock_filter filter[] = {
                /*
                 * IP
                 *
                 * Check
                 *  - UDP
                 *  - Unfragmented
                 *  - Large enough to fit the DHCP header
                 *
                 *  Leave X the size of the IP header, for future indirect reads.
                 */
                BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(struct iphdr, protocol)),                           /* A <- IP protocol */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 1, 0),                                         /* IP protocol == UDP ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                                   /* ignore */

                BPF_STMT(BPF_LD + BPF_B + BPF_ABS, offsetof(struct iphdr, frag_off)),                           /* A <- Flags */
                BPF_STMT(BPF_ALU + BPF_AND + BPF_K, ntohs(IP_MF | IP_OFFMASK)),                                 /* A <- A & (IP_MF | IP_OFFMASK) */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 1, 0),                                                   /* fragmented packet ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                                   /* ignore */

                BPF_STMT(BPF_LDX + BPF_B + BPF_MSH, 0),                                                         /* X <- IP header length */
                BPF_STMT(BPF_LD + BPF_W + BPF_LEN, 0),                                                          /* A <- packet length */
                BPF_STMT(BPF_ALU + BPF_SUB + BPF_X, 0),                                                         /* A -= X */
                BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, sizeof(struct udphdr) + sizeof(NDhcp4Message), 1, 0),       /* packet >= DHCPPacket ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                                   /* ignore */

                /*
                 * UDP
                 *
                 * Check
                 *  - DHCP client port
                 *
                 * Leave X the size of IP and UDP headers, for future indirect reads.
                 */
                BPF_STMT(BPF_LD + BPF_H + BPF_IND, offsetof(struct udphdr, dest)),                              /* A <- UDP destination port */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, N_DHCP4_NETWORK_CLIENT_PORT, 1, 0),                         /* UDP destination port == DHCP client port ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                                   /* ignore */

                BPF_STMT(BPF_LD + BPF_W + BPF_K, sizeof(struct udphdr)),                                        /* A <- size of UDP header */
                BPF_STMT(BPF_ALU + BPF_ADD + BPF_X, 0),                                                         /* A += X */
                BPF_STMT(BPF_MISC + BPF_TAX, 0),                                                                /* X <- A */

                /*
                 * DHCP
                 *
                 * Check
                 *  - BOOTREPLY (from server to client)
                 *  - DHCP magic cookie
                 */
                BPF_STMT(BPF_LD + BPF_B + BPF_IND, offsetof(NDhcp4Header, op)),                                 /* A <- DHCP op */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, N_DHCP4_OP_BOOTREPLY, 1, 0),                                /* op == BOOTREPLY ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                                   /* ignore */

                BPF_STMT(BPF_LD + BPF_W + BPF_IND, offsetof(NDhcp4Message, magic)),                             /* A <- DHCP magic cookie */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, N_DHCP4_MESSAGE_MAGIC, 1, 0),                               /* cookie == DHCP magic cookie ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                                   /* ignore */

                BPF_STMT(BPF_RET + BPF_K, 65535),                                                               /* return all */
        };
        struct sock_fprog fprog = {
                .filter = filter,
                .len = sizeof(filter) / sizeof(filter[0]),
        };
        struct sockaddr_ll addr = {
                .sll_family = AF_PACKET,
                .sll_protocol = htons(ETH_P_IP),
                .sll_ifindex = ifindex,
        };
        int r, on = 1;

        sockfd = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (sockfd < 0)
                return -errno;

        r = setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));
        if (r < 0)
                return -errno;

        /*
         * We need the flag that tells us if the checksum is correct.
         */
        r = setsockopt(sockfd, SOL_PACKET, PACKET_AUXDATA, &on, sizeof(on));
        if (r < 0)
                return -errno;

        r = bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));
        if (r < 0)
                return -errno;

        *sockfdp = sockfd;
        sockfd = -1;
        return 0;
}

/**
 * n_dhcp4_network_client_udp_socket_new() - create a new DHCP4 client UDP socket
 * @sockfdp:            return argumnet for the new socket
 * @ifindex:            interface index to bind to
 * @addr:               client address to bind to
 *
 * Create a new AF_INET/SOCK_DGRAM socket usable to listen to and send DHCP client
 * packets.
 *
 * The client address given in @addr must be configured on the interface @ifindex
 * before the socket is created.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int n_dhcp4_network_client_udp_socket_new(int *sockfdp, int ifindex, const struct in_addr *addr) {
        _cleanup_(n_dhcp4_closep) int sockfd = -1;
        struct sock_filter filter[] = {
                /*
                 * IP/UDP
                 *
                 * Set X to the size of IP and UDP headers, for future indirect reads.
                 */
                BPF_STMT(BPF_LDX + BPF_B + BPF_MSH, 0),                                                         /* X <- IP header length */
                BPF_STMT(BPF_LD + BPF_W + BPF_K, sizeof(struct udphdr)),                                        /* A <- size of UDP header */
                BPF_STMT(BPF_ALU + BPF_ADD + BPF_X, 0),                                                         /* A += X */
                BPF_STMT(BPF_MISC + BPF_TAX, 0),                                                                /* X <- A */

                /*
                 * DHCP
                 *
                 * Check
                 *  - BOOTREPLY (from server to client)
                 *  - DHCP magic cookie
                 */
                BPF_STMT(BPF_LD + BPF_B + BPF_IND, offsetof(NDhcp4Header, op)),                                 /* A <- DHCP op */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, N_DHCP4_OP_BOOTREPLY, 1, 0),                                /* op == BOOTREPLY ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                                   /* ignore */

                BPF_STMT(BPF_LD + BPF_W + BPF_IND, offsetof(NDhcp4Message, magic)),                             /* A <- DHCP magic cookie */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, N_DHCP4_MESSAGE_MAGIC, 1, 0),                               /* cookie == DHCP magic cookie ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                                   /* ignore */

                BPF_STMT(BPF_RET + BPF_K, 65535),                                                               /* return all */
        };
        struct sock_fprog fprog = {
                .filter = filter,
                .len = sizeof(filter) / sizeof(filter[0]),
        };
        struct sockaddr_in saddr = {
                .sin_family = AF_INET,
                .sin_addr = *addr,
                .sin_port = htons(N_DHCP4_NETWORK_CLIENT_PORT),
        };
        char ifname[IF_NAMESIZE];
        int r, tos = IPTOS_CLASS_CS6;

        if (!if_indextoname(ifindex, ifname))
                return -errno;

        sockfd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (sockfd < 0)
                return -errno;

        r = setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));
        if (r < 0)
                return -errno;

        r = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname));
        if (r < 0)
                return -errno;

        r = setsockopt(sockfd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
        if (r < 0)
                return -errno;

        r = bind(sockfd, (struct sockaddr*)&saddr, sizeof(saddr));
        if (r < 0)
                return -errno;

        *sockfdp = sockfd;
        sockfd = -1;
        return 0;
}

/**
 * n_dhcp4_network_server_packet_socket_new() - create a new DHCP4 server packet socket
 * @sockfdp:            return argumnet for the new socket
 *
 * Create a new AF_PACKET/SOCK_DGRAM socket usable to send DHCP packets to clients
 * before they have an IP address configured, on the given interface.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int n_dhcp4_network_server_packet_socket_new(int *sockfdp) {
        _cleanup_(n_dhcp4_closep) int sockfd = -1;

        sockfd = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (sockfd < 0)
                return -errno;

        *sockfdp = sockfd;
        sockfd = -1;
        return 0;
}

/**
 * n_dhcp4_network_server_udp_socket_new() - create a new DHCP4 server UDP socket
 * @sockfdp:            return argumnet for the new socket
 * @ifindex:            intercafe index to bind to
 *
 * Create a new AF_INET/SOCK_DGRAM socket usable to listen to DHCP server packets,
 * on the given interface.
 *
 * Return: 0 on success, or a negative error code on failure.
 */
int n_dhcp4_network_server_udp_socket_new(int *sockfdp, int ifindex) {
        _cleanup_(n_dhcp4_closep) int sockfd = -1;
        struct sock_filter filter[] = {
                /*
                 * IP/UDP
                 *
                 * Set X to the size of IP and UDP headers, for future indirect reads.
                 */
                BPF_STMT(BPF_LDX + BPF_B + BPF_MSH, 0),                                                         /* X <- IP header length */
                BPF_STMT(BPF_LD + BPF_W + BPF_K, sizeof(struct udphdr)),                                        /* A <- size of UDP header */
                BPF_STMT(BPF_ALU + BPF_ADD + BPF_X, 0),                                                         /* A += X */
                BPF_STMT(BPF_MISC + BPF_TAX, 0),                                                                /* X <- A */

                /*
                 * DHCP
                 *
                 * Check
                 *  - BOOTREQUEST (from client to server)
                 *  - DHCP magic cookie
                 */

                BPF_STMT(BPF_LD + BPF_B + BPF_IND, offsetof(NDhcp4Header, op)),                                 /* A <- DHCP op */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, N_DHCP4_OP_BOOTREQUEST, 1, 0),                              /* op == BOOTREQUEST ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                                   /* ignore */

                BPF_STMT(BPF_LD + BPF_W + BPF_IND, offsetof(NDhcp4Message, magic)),                             /* A <- DHCP magic cookie */
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, N_DHCP4_MESSAGE_MAGIC, 1, 0),                               /* cookie == DHCP magic cookie ? */
                BPF_STMT(BPF_RET + BPF_K, 0),                                                                   /* ignore */

                BPF_STMT(BPF_RET + BPF_K, 65535),                                                               /* return all */
        };
        struct sock_fprog fprog = {
                .filter = filter,
                .len = sizeof(filter) / sizeof(filter[0]),
        };
        struct sockaddr_in addr = {
                .sin_family = AF_INET,
                .sin_addr = { INADDR_ANY },
                .sin_port = htons(N_DHCP4_NETWORK_SERVER_PORT),
        };
        char ifname[IF_NAMESIZE];
        int r, tos = IPTOS_CLASS_CS6;

        if (!if_indextoname(ifindex, ifname))
                return -errno;

        sockfd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (sockfd < 0)
                return -errno;

        r = setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));
        if (r < 0)
                return -errno;

        r = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname));
        if (r < 0)
                return -errno;

        r = setsockopt(sockfd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
        if (r < 0)
                return -errno;

        r = bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));
        if (r < 0)
                return -errno;

        *sockfdp = sockfd;
        sockfd = -1;
        return 0;
}

static int n_dhcp4_network_packet_send(int sockfd, int ifindex,
                                       const struct sockaddr_in *src_paddr,
                                       const unsigned char *dest_haddr, unsigned char halen,
                                       const struct sockaddr_in *dest_paddr,
                                       void *buf, size_t n_buf) {
        struct sockaddr_ll2 haddr = {
                .sll_family = AF_PACKET,
                .sll_protocol = htons(ETH_P_IP),
                .sll_ifindex = ifindex,
                .sll_halen = halen,
        };
        ssize_t len;

        memcpy(haddr.sll_addr, dest_haddr, halen);

        len = packet_sendto_udp(sockfd, buf, n_buf, 0, src_paddr, &haddr, dest_paddr);
        if (len < 0)
                return -errno;
        else if ((size_t)len != n_buf)
                return -EIO;

        return 0;
}

int n_dhcp4_network_client_packet_send(int sockfd, int ifindex,
                                       const unsigned char *dest_haddr, unsigned char halen,
                                       void *buf, size_t n_buf) {
        struct sockaddr_in src_paddr = {
                .sin_family = AF_INET,
                .sin_port = htons(N_DHCP4_NETWORK_CLIENT_PORT),
                .sin_addr = { INADDR_ANY },
        };
        struct sockaddr_in dest_paddr = {
                .sin_family = AF_INET,
                .sin_port = htons(N_DHCP4_NETWORK_SERVER_PORT),
                .sin_addr = { INADDR_ANY }
        };

        return n_dhcp4_network_packet_send(sockfd, ifindex, &src_paddr, dest_haddr, halen, &dest_paddr, buf, n_buf);
}

int n_dhcp4_network_client_udp_send(int sockfd, const struct in_addr *inaddr_dest, void *buf, size_t n_buf) {
        struct sockaddr_in sockaddr_dest = {
                .sin_family = AF_INET,
                .sin_port = htons(N_DHCP4_NETWORK_SERVER_PORT),
                .sin_addr = *inaddr_dest,
        };
        ssize_t len;

        len = sendto(sockfd, buf, n_buf, 0, (struct sockaddr*)&sockaddr_dest, sizeof(sockaddr_dest));
        if (len < 0)
                return -errno;
        else if ((size_t)len != n_buf)
                return -EIO;

        return 0;
}

int n_dhcp4_network_server_packet_send(int sockfd, int ifindex,
                                       const struct in_addr *src_inaddr,
                                       const unsigned char *dest_haddr, unsigned char halen,
                                       const struct in_addr *dest_inaddr,
                                       void *buf, size_t n_buf) {
        struct sockaddr_in src_paddr = {
                .sin_family = AF_INET,
                .sin_port = htons(N_DHCP4_NETWORK_SERVER_PORT),
                .sin_addr = *src_inaddr,
        };
        struct sockaddr_in dest_paddr = {
                .sin_family = AF_INET,
                .sin_port = htons(N_DHCP4_NETWORK_CLIENT_PORT),
                .sin_addr = *dest_inaddr,
        };

        return n_dhcp4_network_packet_send(sockfd, ifindex, &src_paddr, dest_haddr, halen, &dest_paddr, buf, n_buf);
}

int n_dhcp4_network_server_udp_send(int sockfd, const struct in_addr *inaddr_dest, void *buf, size_t n_buf) {
        struct sockaddr_in sockaddr_dest = {
                .sin_family = AF_INET,
                .sin_port = htons(N_DHCP4_NETWORK_CLIENT_PORT),
                .sin_addr = *inaddr_dest,
        };
        ssize_t len;

        len = sendto(sockfd, buf, n_buf, 0, (struct sockaddr*)&sockaddr_dest, sizeof(sockaddr_dest));
        if (len < 0)
                return -errno;
        else if ((size_t)len != n_buf)
                return -EIO;

        return 0;
}
