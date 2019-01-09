/*
 * Test for raw packet utility library
 */

#include <assert.h>
#include <errno.h>
#include <net/if_arp.h>
#include <stdlib.h>
#include <string.h>
#include "n-dhcp4-private.h"
#include "util/link.h"
#include "util/netns.h"
#include "util/packet.h"
#include "test.h"

typedef struct Blob {
        uint16_t checksum;
        uint8_t data[128];
} Blob;

static void test_checksum_one(Blob *blob, size_t size) {
        uint16_t checksum;

        blob->checksum = 0;
        blob->checksum = packet_internet_checksum((uint8_t*)blob, size);

        checksum = packet_internet_checksum((uint8_t*)blob, size);
        assert(!checksum);
}

static void test_checksum_generic(void) {
        Blob blob = {};

        for (size_t i = 0; i < sizeof(blob.data); ++i)
                blob.data[i] = (i & 0xffff) ^ (i << 16);

        for (size_t j = 0; j < sizeof(uint64_t); ++j) {
                for (uint32_t i = 0; i <= 0xffff; ++i) {
                        blob.data[0] = i & 0xff;
                        blob.data[1] = i >> 8;
                        test_checksum_one(&blob, sizeof(blob) - j);
                }
        }
}

static void test_checksum_udp_one(Blob *blob, size_t size) {
        uint16_t checksum;

        checksum = packet_internet_checksum_udp(&(struct in_addr){htonl(10<<24 | 2)}, &(struct in_addr){htonl(10<<24 | 1)},
                                                67, 68, blob->data, sizeof(blob->data), 0) ?: 0xffff;
        checksum = packet_internet_checksum_udp(&(struct in_addr){htonl(10<<24 | 2)}, &(struct in_addr){htonl(10<<24 | 1)},
                                                67, 68, blob->data, sizeof(blob->data), checksum);
        assert(!checksum);
}

static void test_checksum_udp(void) {
        Blob blob = {};

        for (size_t i = 0; i < sizeof(blob.data); ++i)
                blob.data[i] = (i & 0xffff) ^ (i << 16);

        for (size_t j = 0; j < sizeof(uint64_t); ++j) {
                for (uint32_t i = 0; i <= 0xffff; ++i) {
                        blob.data[0] = i & 0xff;
                        blob.data[1] = i >> 8;
                        test_checksum_udp_one(&blob, sizeof(blob) - j);
                }
        }
}

static void test_new_packet_socket(Link *link, int *skp) {
        struct sockaddr_ll addr = {
                .sll_family = AF_PACKET,
                .sll_protocol = htons(ETH_P_IP),
                .sll_ifindex = link->ifindex,
        };
        int r, on = 1;

        link_socket(link, skp, AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC);

        r = setsockopt(*skp, SOL_PACKET, PACKET_AUXDATA, &on, sizeof(on));
        assert(r >= 0);

        r = bind(*skp, (struct sockaddr*)&addr, sizeof(addr));
        assert(r >= 0);
}

static void test_packet_unicast(int ifindex, int sk, void *buf, size_t n_buf,
                                const struct sockaddr_in *paddr_src,
                                const struct sockaddr_in *paddr_dst,
                                const struct ether_addr *haddr_dst) {
        struct packet_sockaddr_ll2 addr = {
                .sll_family = AF_PACKET,
                .sll_protocol = htons(ETH_P_IP),
                .sll_ifindex = ifindex,
                .sll_halen = ETH_ALEN,
        };
        ssize_t len;

        memcpy(addr.sll_addr, haddr_dst, ETH_ALEN);

        len = packet_sendto_udp(sk, buf, n_buf, 0, paddr_src, &addr, paddr_dst);
        assert(len == (ssize_t)n_buf);
}

static void test_packet_broadcast(int ifindex, int sk, void *buf, size_t n_buf,
                                  const struct sockaddr_in *paddr_src,
                                  const struct sockaddr_in *paddr_dst) {
        struct packet_sockaddr_ll2 addr = {
                .sll_family = AF_PACKET,
                .sll_protocol = htons(ETH_P_IP),
                .sll_ifindex = ifindex,
                .sll_halen = ETH_ALEN,
        };
        ssize_t len;

        memcpy(addr.sll_addr, (unsigned char[]){ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, }, ETH_ALEN);

        len = packet_sendto_udp(sk, buf, n_buf, 0, paddr_src, &addr, paddr_dst);
        assert(len == (ssize_t)n_buf);
}

static void test_packet_packet(Link *link_src,
                               Link *link_dst,
                               const struct sockaddr_in *paddr_src,
                               const struct sockaddr_in *paddr_dst) {
        _cleanup_(n_dhcp4_closep) int sk_src = -1, sk_dst = -1;
        uint8_t buf[1024];
        ssize_t len;

        link_socket(link_src, &sk_src, AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC);
        test_new_packet_socket(link_dst, &sk_dst);

        test_packet_unicast(link_src->ifindex, sk_src, buf, sizeof(buf) - 1, paddr_src, paddr_dst, &link_dst->mac);
        test_packet_broadcast(link_src->ifindex, sk_src, buf, sizeof(buf) - 1, paddr_src, paddr_dst);

        len = packet_recvfrom_udp(sk_dst, buf, sizeof(buf), 0, NULL);
        assert(len == (ssize_t)sizeof(buf) - 1);

        len = packet_recvfrom_udp(sk_dst, buf, sizeof(buf), 0, NULL);
        assert(len == (ssize_t)sizeof(buf) - 1);
}

static void test_packet_udp(Link *link_src,
                            Link *link_dst,
                            const struct sockaddr_in *paddr_src,
                            const struct sockaddr_in *paddr_dst) {
        _cleanup_(n_dhcp4_closep) int sk_src = -1, sk_dst = -1;
        uint8_t buf[1024];
        ssize_t len;
        int r;

        link_socket(link_src, &sk_src, AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC);
        link_socket(link_dst, &sk_dst, AF_INET, SOCK_DGRAM | SOCK_CLOEXEC);
        link_add_ip4(link_dst, &paddr_dst->sin_addr, 8);

        r = bind(sk_dst, (struct sockaddr*)paddr_dst, sizeof(*paddr_dst));
        assert(r >= 0);

        test_packet_unicast(link_src->ifindex, sk_src, buf, sizeof(buf) - 1, paddr_src, paddr_dst, &link_dst->mac);
        test_packet_broadcast(link_src->ifindex, sk_src, buf, sizeof(buf) - 1, paddr_src, paddr_dst);

        len = recv(sk_dst, buf, sizeof(buf), 0);
        assert(len == (ssize_t)sizeof(buf) - 1);

        len = recv(sk_dst, buf, sizeof(buf), 0);
        assert(len == (ssize_t)sizeof(buf) - 1);

        link_del_ip4(link_dst, &paddr_dst->sin_addr, 8);
}

static void test_udp_packet(Link *link_src,
                            Link *link_dst,
                            const struct sockaddr_in *paddr_src,
                            const struct sockaddr_in *paddr_dst) {
        _cleanup_(n_dhcp4_closep) int sk_src = -1, sk_dst = -1;
        uint8_t buf[1024];
        ssize_t len;

        link_socket(link_src, &sk_src, AF_INET, SOCK_DGRAM | SOCK_CLOEXEC);
        test_new_packet_socket(link_dst, &sk_dst);
        link_add_ip4(link_src, &paddr_src->sin_addr, 8);
        link_add_ip4(link_dst, &paddr_dst->sin_addr, 8);

        len = sendto(sk_src, buf, sizeof(buf) - 1, 0,
                     (struct sockaddr*)paddr_dst, sizeof(*paddr_dst));
        assert(len == (ssize_t)sizeof(buf) - 1);

        len = packet_recvfrom_udp(sk_dst, buf, sizeof(buf), 0, NULL);
        assert(len == (ssize_t)sizeof(buf) - 1);

        link_del_ip4(link_dst, &paddr_dst->sin_addr, 8);
        link_del_ip4(link_src, &paddr_src->sin_addr, 8);
}

static void test_udp_udp(Link *link_src,
                         Link *link_dst,
                         const struct sockaddr_in *paddr_src,
                         const struct sockaddr_in *paddr_dst) {
        _cleanup_(n_dhcp4_closep) int sk_src = -1, sk_dst = -1;
        uint8_t buf[1024];
        ssize_t len;
        int r;

        link_socket(link_src, &sk_src, AF_INET, SOCK_DGRAM | SOCK_CLOEXEC);
        link_socket(link_dst, &sk_dst, AF_INET, SOCK_DGRAM | SOCK_CLOEXEC);
        link_add_ip4(link_src, &paddr_src->sin_addr, 8);
        link_add_ip4(link_dst, &paddr_dst->sin_addr, 8);

        r = bind(sk_dst, (struct sockaddr*)paddr_dst, sizeof(*paddr_dst));
        assert(r >= 0);

        len = sendto(sk_src, buf, sizeof(buf) - 1, 0,
                     (struct sockaddr*)paddr_dst, sizeof(*paddr_dst));
        assert(len == (ssize_t)sizeof(buf) - 1);

        len = recv(sk_dst, buf, sizeof(buf), 0);
        assert(len == (ssize_t)sizeof(buf) - 1);

        link_del_ip4(link_dst, &paddr_dst->sin_addr, 8);
        link_del_ip4(link_src, &paddr_src->sin_addr, 8);
}

static void test_shutdown(Link *link_src,
                          Link *link_dst,
                          const struct sockaddr_in *paddr_src,
                          const struct sockaddr_in *paddr_dst) {
        _cleanup_(n_dhcp4_closep) int sk_src = -1, sk_dst1 = -1, sk_dst2 = -1;
        uint8_t buf[1024];
        ssize_t len;
        int r;

        link_socket(link_src, &sk_src, AF_INET, SOCK_DGRAM | SOCK_CLOEXEC);
        test_new_packet_socket(link_dst, &sk_dst1);
        link_add_ip4(link_src, &paddr_src->sin_addr, 8);
        link_add_ip4(link_dst, &paddr_dst->sin_addr, 8);

        /* 1 - send only to the packet socket */
        len = sendto(sk_src, buf, sizeof(buf), 0,
                     (struct sockaddr*)paddr_dst, sizeof(*paddr_dst));
        assert(len == (ssize_t)sizeof(buf));

        /* create a UDP socket */
        link_socket(link_dst, &sk_dst2, AF_INET, SOCK_DGRAM | SOCK_CLOEXEC);

        r = bind(sk_dst2, (struct sockaddr*)paddr_dst, sizeof(*paddr_dst));
        assert(r >= 0);

        /* 2 - send to both sockets */
        len = sendto(sk_src, buf, sizeof(buf), 0,
                     (struct sockaddr*)paddr_dst, sizeof(*paddr_dst));
        assert(len == (ssize_t)sizeof(buf));

        /* shut down the packet socket */
        r = packet_shutdown(sk_dst1);
        assert(r >= 0);

        /* 3 - send only to the UDP socket */
        len = sendto(sk_src, buf, sizeof(buf), 0,
                     (struct sockaddr*)paddr_dst, sizeof(*paddr_dst));
        assert(len == (ssize_t)sizeof(buf));

        /* receive 1 and 2 on the packet socket */
        len = packet_recvfrom_udp(sk_dst1, buf, sizeof(buf), 0, NULL);
        assert(len == (ssize_t)sizeof(buf));
        len = packet_recvfrom_udp(sk_dst1, buf, sizeof(buf), 0, NULL);
        assert(len == (ssize_t)sizeof(buf));

        /* make sure there is nothing more pending on the packet socket */
        len = recv(sk_dst1, buf, sizeof(buf), MSG_DONTWAIT);
        assert(len < 0);
        assert(errno == EAGAIN);

        /* receive 2 and 3 on the UDP socket */
        len = recv(sk_dst2, buf, sizeof(buf), 0);
        assert(len == (ssize_t)sizeof(buf));
        len = recv(sk_dst2, buf, sizeof(buf), 0);
        assert(len == (ssize_t)sizeof(buf));

        /* make sure there is nothing more pending on the UDP socket */
        len = recv(sk_dst1, buf, sizeof(buf), MSG_DONTWAIT);
        assert(len < 0);
        assert(errno == EAGAIN);

        link_del_ip4(link_dst, &paddr_dst->sin_addr, 8);
        link_del_ip4(link_src, &paddr_src->sin_addr, 8);
}

static void test_packet(void) {
        _cleanup_(netns_closep) int ns_src = -1, ns_dst = -1;
        _cleanup_(link_deinit) Link link_src = LINK_NULL(link_src);
        _cleanup_(link_deinit) Link link_dst = LINK_NULL(link_dst);
        struct sockaddr_in paddr_src = {
                .sin_family = AF_INET,
                .sin_addr = (struct in_addr){ htonl(10<<24 | 1) },
                .sin_port = htons(10),
        };
        struct sockaddr_in paddr_dst = {
                .sin_family = AF_INET,
                .sin_addr = (struct in_addr){ htonl(10<<24 | 2) },
                .sin_port = htons(11),
        };

        /* setup */

        netns_new(&ns_src);
        netns_new(&ns_dst);
        link_new_veth(&link_src, &link_dst, ns_src, ns_dst);

        /* communication tests */

        test_packet_packet(&link_src, &link_dst, &paddr_src, &paddr_dst);
        test_packet_udp(&link_src, &link_dst, &paddr_src, &paddr_dst);
        test_udp_packet(&link_src, &link_dst, &paddr_src, &paddr_dst);
        test_udp_udp(&link_src, &link_dst, &paddr_src, &paddr_dst);

        /* management tests */

        test_shutdown(&link_src, &link_dst, &paddr_src, &paddr_dst);
}

int main(int argc, char **argv) {
        test_setup();

        test_checksum_generic();
        test_checksum_udp();
        test_packet();

        return 0;
}
