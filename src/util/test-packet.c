/*
 * Test for raw packet utility library
 */

#include <assert.h>
#include <errno.h>
#include <net/if_arp.h>
#include <stdlib.h>
#include <string.h>
#include "packet.h"
#include "../test.h"

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

static void test_checksum(void) {
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

static void test_packet_socket_new(int ns, int *skp, int ifindex) {
        struct sockaddr_ll addr = {
                .sll_family = AF_PACKET,
                .sll_protocol = htons(ETH_P_IP),
                .sll_ifindex = ifindex,
        };
        int r, on = 1;

        test_socket_new(ns, skp, AF_PACKET, ifindex);

        r = setsockopt(*skp, SOL_PACKET, PACKET_AUXDATA, &on, sizeof(on));
        assert(r >= 0);

        r = bind(*skp, (struct sockaddr*)&addr, sizeof(addr));
        assert(r >= 0);
}

static void test_packet_unicast(int ifindex, int sk, void *buf, size_t n_buf,
                                const struct sockaddr_in *paddr_src,
                                const struct sockaddr_in *paddr_dst,
                                const struct ether_addr *haddr_dst) {
        struct sockaddr_ll addr = {
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
        struct sockaddr_ll addr = {
                .sll_family = AF_PACKET,
                .sll_protocol = htons(ETH_P_IP),
                .sll_ifindex = ifindex,
                .sll_halen = ETH_ALEN,
        };
        ssize_t len;

        memcpy(addr.sll_addr, (char[]){ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, }, ETH_ALEN);

        len = packet_sendto_udp(sk, buf, n_buf, 0, paddr_src, &addr, paddr_dst);
        assert(len == (ssize_t)n_buf);
}

static void test_packet_packet(int ns_src, int ifindex_src,
                               int ns_dst, int ifindex_dst,
                               const struct sockaddr_in *paddr_src,
                               const struct sockaddr_in *paddr_dst,
                               const struct ether_addr *haddr_dst) {
        uint8_t buf[1024];
        int sk_src, sk_dst;
        ssize_t len;

        test_socket_new(ns_src, &sk_src, AF_PACKET, ifindex_src);
        test_packet_socket_new(ns_dst, &sk_dst, ifindex_dst);

        test_packet_unicast(ifindex_src, sk_src, buf, sizeof(buf) - 1, paddr_src, paddr_dst, haddr_dst);
        test_packet_broadcast(ifindex_src, sk_src, buf, sizeof(buf) - 1, paddr_src, paddr_dst);

        len = packet_recvfrom_udp(sk_dst, buf, sizeof(buf), 0, NULL);
        assert(len == sizeof(buf) - 1);

        len = packet_recvfrom_udp(sk_dst, buf, sizeof(buf), 0, NULL);
        assert(len == sizeof(buf) - 1);

        close(sk_dst);
        close(sk_src);
}

static void test_packet_udp(int ns_src, int ifindex_src,
                            int ns_dst, int ifindex_dst,
                            const struct sockaddr_in *paddr_src,
                            const struct sockaddr_in *paddr_dst,
                            const struct ether_addr *haddr_dst) {
        uint8_t buf[1024];
        int sk_src, sk_dst;
        ssize_t len;
        int r;

        test_socket_new(ns_src, &sk_src, AF_PACKET, ifindex_src);
        test_socket_new(ns_dst, &sk_dst, AF_INET, ifindex_dst);
        test_add_ip(ns_dst, ifindex_dst, &paddr_dst->sin_addr, 8);

        r = bind(sk_dst, (struct sockaddr*)paddr_dst, sizeof(*paddr_dst));
        assert(r >= 0);

        test_packet_unicast(ifindex_src, sk_src, buf, sizeof(buf) - 1, paddr_src, paddr_dst, haddr_dst);
        test_packet_broadcast(ifindex_src, sk_src, buf, sizeof(buf) - 1, paddr_src, paddr_dst);

        len = recv(sk_dst, buf, sizeof(buf), 0);
        assert(len == sizeof(buf) - 1);

        len = recv(sk_dst, buf, sizeof(buf), 0);
        assert(len == sizeof(buf) - 1);

        test_del_ip(ns_dst, ifindex_dst, &paddr_dst->sin_addr, 8);
        close(sk_dst);
        close(sk_src);
}

static void test_udp_packet(int ns_src, int ifindex_src,
                            int ns_dst, int ifindex_dst,
                            const struct sockaddr_in *paddr_src,
                            const struct sockaddr_in *paddr_dst) {
        uint8_t buf[1024];
        int sk_src, sk_dst;
        ssize_t len;

        test_socket_new(ns_src, &sk_src, AF_INET, ifindex_src);
        test_packet_socket_new(ns_dst, &sk_dst, ifindex_dst);
        test_add_ip(ns_src, ifindex_src, &paddr_src->sin_addr, 8);
        test_add_ip(ns_dst, ifindex_dst, &paddr_dst->sin_addr, 8);

        len = sendto(sk_src, buf, sizeof(buf) - 1, 0,
                     (struct sockaddr*)paddr_dst, sizeof(*paddr_dst));
        assert(len == sizeof(buf) - 1);

        len = packet_recvfrom_udp(sk_dst, buf, sizeof(buf), 0, NULL);
        assert(len == sizeof(buf) - 1);

        test_del_ip(ns_dst, ifindex_dst, &paddr_dst->sin_addr, 8);
        test_del_ip(ns_src, ifindex_src, &paddr_src->sin_addr, 8);
        close(sk_dst);
        close(sk_src);
}

static void test_udp_udp(int ns_src, int ifindex_src,
                         int ns_dst, int ifindex_dst,
                         const struct sockaddr_in *paddr_src,
                         const struct sockaddr_in *paddr_dst) {
        uint8_t buf[1024];
        int sk_src, sk_dst;
        ssize_t len;
        int r;

        test_socket_new(ns_src, &sk_src, AF_INET, ifindex_src);
        test_socket_new(ns_dst, &sk_dst, AF_INET, ifindex_dst);
        test_add_ip(ns_src, ifindex_src, &paddr_src->sin_addr, 8);
        test_add_ip(ns_dst, ifindex_dst, &paddr_dst->sin_addr, 8);

        r = bind(sk_dst, (struct sockaddr*)paddr_dst, sizeof(*paddr_dst));
        assert(r >= 0);

        len = sendto(sk_src, buf, sizeof(buf) - 1, 0,
                     (struct sockaddr*)paddr_dst, sizeof(*paddr_dst));
        assert(len == sizeof(buf) - 1);

        len = recv(sk_dst, buf, sizeof(buf), 0);
        assert(len == sizeof(buf) - 1);

        test_del_ip(ns_dst, ifindex_dst, &paddr_dst->sin_addr, 8);
        test_del_ip(ns_src, ifindex_src, &paddr_src->sin_addr, 8);
        close(sk_dst);
        close(sk_src);
}

int main(int argc, char **argv) {
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
        struct ether_addr haddr_dst;
        int r, ifindex_src, ifindex_dst, ns_src, ns_dst;

        test_checksum();
        test_checksum_udp();

        r = test_setup();
        if (r)
                return r;

        test_veth_new(&ns_src, &ifindex_src, NULL, &ns_dst, &ifindex_dst, &haddr_dst);

        test_packet_packet(ns_src, ifindex_src, ns_dst, ifindex_dst, &paddr_src, &paddr_dst, &haddr_dst);
        test_packet_udp(ns_src, ifindex_src, ns_dst, ifindex_dst, &paddr_src, &paddr_dst, &haddr_dst);
        test_udp_packet(ns_src, ifindex_src, ns_dst, ifindex_dst, &paddr_src, &paddr_dst);
        test_udp_udp(ns_src, ifindex_src, ns_dst, ifindex_dst, &paddr_src, &paddr_dst);

        return 0;
}
