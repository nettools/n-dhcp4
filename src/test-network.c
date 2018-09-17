/*
 * Tests for DHCP4 Network Helpers
 */

#undef NDEBUG
#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <poll.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "n-dhcp4-private.h"
#include "test.h"
#include "util/packet.h"

static void test_poll(int sk) {
        int r;

        r = poll(&(struct pollfd){.fd = sk, .events = POLLIN}, 1, -1);
        assert(r == 1);
}

static void test_client_packet_socket_new(int netns, int *skp, int ifindex) {
        int r, oldns;

        test_netns_get(&oldns);
        test_netns_set(netns);

        r = n_dhcp4_network_client_packet_socket_new(skp, ifindex);
        assert(r >= 0);

        test_netns_set(oldns);
}

static void test_client_udp_socket_new(int netns, int *skp, int ifindex, const struct in_addr *addr) {
        int r, oldns;

        test_netns_get(&oldns);
        test_netns_set(netns);

        r = n_dhcp4_network_client_udp_socket_new(skp, ifindex, addr);
        assert(r >= 0);

        test_netns_set(oldns);
}

static void test_server_packet_socket_new(int netns, int *skp, int ifindex) {
        int r, oldns;

        test_netns_get(&oldns);
        test_netns_set(netns);

        r = n_dhcp4_network_server_packet_socket_new(skp, ifindex);
        assert(r >= 0);

        test_netns_set(oldns);
}

static void test_server_udp_socket_new(int netns, int *skp, int ifindex) {
        int r, oldns;

        test_netns_get(&oldns);
        test_netns_set(netns);

        r = n_dhcp4_network_server_udp_socket_new(skp, ifindex);
        assert(r >= 0);

        test_netns_set(oldns);
}

static void test_client_packet_send(int sk, void *buf, size_t n_buf, int ifindex) {
        struct sockaddr_in paddr_src = {
                .sin_family = AF_INET,
                .sin_addr = { INADDR_ANY },
                .sin_port =  htons(N_DHCP4_NETWORK_CLIENT_PORT),
        };
        struct sockaddr_in paddr_dst = {
                .sin_family = AF_INET,
                .sin_addr = { INADDR_ANY },
                .sin_port =  htons(N_DHCP4_NETWORK_SERVER_PORT),
        };
        struct sockaddr_ll haddr_dst = {
                .sll_family = AF_PACKET,
                .sll_protocol = htons(ETH_P_IP),
                .sll_ifindex = ifindex,
                .sll_halen = ETH_ALEN,
        };
        ssize_t len;

        memcpy(haddr_dst.sll_addr, (char[]){ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, }, ETH_ALEN);

        len = packet_sendto_udp(sk, buf, n_buf, 0, &paddr_src, &haddr_dst, &paddr_dst);
        assert(len == n_buf);
}

static void test_client_udp_send(int sk, void *buf, size_t n_buf, const struct in_addr *addr) {
        struct sockaddr_in sockaddr_dst = {
                .sin_family = AF_INET,
                .sin_addr = *addr,
                .sin_port = htons(N_DHCP4_NETWORK_SERVER_PORT),
        };
        ssize_t len;

        len = sendto(sk, buf, n_buf, 0, (struct sockaddr*)&sockaddr_dst, sizeof(sockaddr_dst));
        assert(len == n_buf);
}

static void test_server_packet_send(int sk, void *buf, size_t n_buf, int ifindex, const struct in_addr *src, const struct in_addr *dst, const struct ether_addr *dst_mac) {
        struct sockaddr_in paddr_src = {
                .sin_family = AF_INET,
                .sin_addr = *src,
                .sin_port =  htons(N_DHCP4_NETWORK_SERVER_PORT),
        };
        struct sockaddr_in paddr_dst = {
                .sin_family = AF_INET,
                .sin_addr = *dst,
                .sin_port =  htons(N_DHCP4_NETWORK_CLIENT_PORT),
        };
        struct sockaddr_ll haddr_dst = {
                .sll_family = AF_PACKET,
                .sll_protocol = htons(ETH_P_IP),
                .sll_ifindex = ifindex,
                .sll_halen = ETH_ALEN,
        };
        ssize_t len;

        memcpy(haddr_dst.sll_addr, dst_mac, ETH_ALEN);

        len = packet_sendto_udp(sk, buf, n_buf, 0, &paddr_src, &haddr_dst, &paddr_dst);
        assert(len == n_buf);
}

static void test_server_packet_send_broadcast(int sk, void *buf, size_t n_buf, int ifindex, const struct in_addr *src, const struct in_addr *dst) {
        test_server_packet_send(sk, buf, n_buf, ifindex, src, dst, &(struct ether_addr){ { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, } });
}

static void test_server_udp_send(int sk, void *buf, size_t n_buf, const struct in_addr *addr) {
        struct sockaddr_in sockaddr_dst = {
                .sin_family = AF_INET,
                .sin_addr = *addr,
                .sin_port = htons(N_DHCP4_NETWORK_CLIENT_PORT),
        };
        ssize_t len;

        len = sendto(sk, buf, n_buf, 0, (struct sockaddr*)&sockaddr_dst, sizeof(sockaddr_dst));
        assert(len == n_buf);
}

static void test_client_server_packet(int ns_server, int ns_client, int ifindex_server, int ifindex_client) {
        NDhcp4Message message_out = N_DHCP4_MESSAGE_NULL, message_in = {};
        int sk_server, sk_client;
        ssize_t len;

        test_client_packet_socket_new(ns_client, &sk_client, ifindex_client);
        test_server_udp_socket_new(ns_server, &sk_server, ifindex_server);

        message_out.header.op = N_DHCP4_OP_BOOTREQUEST;

        test_client_packet_send(sk_client, &message_out, sizeof(message_out), ifindex_client);

        test_poll(sk_server);

        len = recv(sk_server, &message_in, sizeof(message_in), 0);
        assert(len == sizeof(message_in));
        assert(memcmp(&message_out, &message_in, sizeof(message_out)) == 0);

        close(sk_server);
        close(sk_client);
}

static void test_client_server_udp(int ns_server, int ns_client, int ifindex_server, int ifindex_client) {
        NDhcp4Message message_out = N_DHCP4_MESSAGE_NULL, message_in = {};
        struct in_addr addr_client = (struct in_addr){ htonl(10 << 24 | 2) };
        struct in_addr addr_server = (struct in_addr){ htonl(10 << 24 | 1) };
        int sk_server, sk_client;
        ssize_t len;

        test_add_ip(ns_client, ifindex_client, &addr_client, 8);
        test_add_ip(ns_server, ifindex_server, &addr_server, 8);

        test_client_udp_socket_new(ns_client, &sk_client, ifindex_client, &addr_client);
        test_server_udp_socket_new(ns_server, &sk_server, ifindex_server);

        message_out.header.op = N_DHCP4_OP_BOOTREQUEST;

        test_client_udp_send(sk_client, &message_out, sizeof(message_out), &addr_server);

        test_poll(sk_server);

        len = recv(sk_server, &message_in, sizeof(message_in), 0);
        assert(len == sizeof(message_in));
        assert(memcmp(&message_out, &message_in, sizeof(message_out)) == 0);

        close(sk_server);
        close(sk_client);

        test_del_ip(ns_server, ifindex_server, &addr_server, 8);
        test_del_ip(ns_client, ifindex_client, &addr_client, 8);
}

static void test_server_client_packet(int ns_server, int ns_client, int ifindex_server, int ifindex_client, const struct ether_addr *mac_client) {
        NDhcp4Message message_out = N_DHCP4_MESSAGE_NULL, message_in = {};
        struct in_addr addr_client = (struct in_addr){ htonl(10 << 24 | 2) };
        struct in_addr addr_server = (struct in_addr){ htonl(10 << 24 | 1) };
        int sk_server, sk_client;
        ssize_t len;

        test_add_ip(ns_server, ifindex_server, &addr_server, 8);

        test_client_packet_socket_new(ns_client, &sk_client, ifindex_client);
        test_server_packet_socket_new(ns_server, &sk_server, ifindex_server);

        message_out.header.op = N_DHCP4_OP_BOOTREPLY;

        test_server_packet_send(sk_server, &message_out, sizeof(message_out), ifindex_server, &addr_server, &addr_client, mac_client);
        test_server_packet_send_broadcast(sk_server, &message_out, sizeof(message_out), ifindex_server, &addr_server, &addr_client);

        test_poll(sk_client);

        len = packet_recv_udp(sk_client, &message_in, sizeof(message_in), 0);
        assert(len == sizeof(message_in));
        assert(memcmp(&message_out, &message_in, sizeof(message_out)) == 0);

        test_poll(sk_client);

        len = packet_recv_udp(sk_client, &message_in, sizeof(message_in), 0);
        assert(len == sizeof(message_in));
        assert(memcmp(&message_out, &message_in, sizeof(message_out)) == 0);

        close(sk_server);
        close(sk_client);

        test_del_ip(ns_server, ifindex_server, &addr_server, 8);
}

static void test_server_client_udp(int ns_server, int ns_client, int ifindex_server, int ifindex_client) {
        NDhcp4Message message_out = N_DHCP4_MESSAGE_NULL, message_in = {};
        struct in_addr addr_client = (struct in_addr){ htonl(10 << 24 | 2) };
        struct in_addr addr_server = (struct in_addr){ htonl(10 << 24 | 1) };
        int sk_server, sk_client;
        ssize_t len;

        test_add_ip(ns_client, ifindex_client, &addr_client, 8);
        test_add_ip(ns_server, ifindex_server, &addr_server, 8);

        test_client_udp_socket_new(ns_client, &sk_client, ifindex_client, &addr_client);
        test_server_udp_socket_new(ns_server, &sk_server, ifindex_server);

        message_out.header.op = N_DHCP4_OP_BOOTREPLY;

        test_server_udp_send(sk_server, &message_out, sizeof(message_out), &addr_client);

        test_poll(sk_client);

        len = recv(sk_client, &message_in, sizeof(message_in), 0);
        assert(len == sizeof(message_in));
        assert(memcmp(&message_out, &message_in, sizeof(message_out)) == 0);

        close(sk_server);
        close(sk_client);

        test_del_ip(ns_server, ifindex_server, &addr_server, 8);
        test_del_ip(ns_client, ifindex_client, &addr_client, 8);
}

int main(int argc, char **argv) {
        int r, ns_server, ns_client, ifindex_server, ifindex_client;
        struct ether_addr mac_client;

        r = test_setup();
        if (r)
                return r;

        test_netns_new(&ns_server);
        test_netns_new(&ns_client);

        test_veth_new(ns_server, &ifindex_server, NULL, ns_client, &ifindex_client, &mac_client);

        test_client_server_packet(ns_server, ns_client, ifindex_server, ifindex_client);
        test_client_server_udp(ns_server, ns_client, ifindex_server, ifindex_client);
        test_server_client_packet(ns_server, ns_client, ifindex_server, ifindex_client, &mac_client);
        test_server_client_udp(ns_server, ns_client, ifindex_server, ifindex_client);

        close(ns_client);
        close(ns_server);

        return 0;
}
