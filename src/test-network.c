/*
 * Tests for DHCP4 Network Helpers
 */

#undef NDEBUG
#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <poll.h>
#include <linux/if_arp.h>
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

static void test_server_packet_socket_new(int netns, int *skp) {
        int r, oldns;

        test_netns_get(&oldns);
        test_netns_set(netns);

        r = n_dhcp4_network_server_packet_socket_new(skp);
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

static void test_client_server_packet(int ns_server, int ns_client, int ifindex_server, int ifindex_client) {
        NDhcp4Message message_out = N_DHCP4_MESSAGE_NULL, message_in = {};
        int sk_server, sk_client;
        ssize_t len;
        int r;

        test_client_packet_socket_new(ns_client, &sk_client, ifindex_client);
        test_server_udp_socket_new(ns_server, &sk_server, ifindex_server);

        message_out.header.op = N_DHCP4_OP_BOOTREQUEST;

        r = n_dhcp4_network_client_packet_broadcast(sk_client, ifindex_client, ARPHRD_ETHER, &message_out, sizeof(message_out));
        assert(r >= 0);

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
        int r, sk_server, sk_client;
        ssize_t len;

        test_add_ip(ns_client, ifindex_client, &addr_client, 8);
        test_add_ip(ns_server, ifindex_server, &addr_server, 8);

        test_client_udp_socket_new(ns_client, &sk_client, ifindex_client, &addr_client);
        test_server_udp_socket_new(ns_server, &sk_server, ifindex_server);

        message_out.header.op = N_DHCP4_OP_BOOTREQUEST;

        r = n_dhcp4_network_client_udp_send(sk_client, &addr_server, &message_out, sizeof(message_out));
        assert(r >= 0);

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
        int r;

        test_add_ip(ns_server, ifindex_server, &addr_server, 8);

        test_client_packet_socket_new(ns_client, &sk_client, ifindex_client);
        test_server_packet_socket_new(ns_server, &sk_server);

        message_out.header.op = N_DHCP4_OP_BOOTREPLY;

        r = n_dhcp4_network_server_packet_send(sk_server, ifindex_server, &addr_server,
                                               mac_client->ether_addr_octet, ETH_ALEN,
                                               &addr_client,
                                               &message_out, sizeof(message_out));
        assert(r >= 0);
        r = n_dhcp4_network_server_packet_broadcast(sk_server, ifindex_server, ARPHRD_ETHER, &addr_server, &addr_client, &message_out, sizeof(message_out));
        assert(r >= 0);

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
        int r;

        test_add_ip(ns_client, ifindex_client, &addr_client, 8);
        test_add_ip(ns_server, ifindex_server, &addr_server, 8);

        test_client_udp_socket_new(ns_client, &sk_client, ifindex_client, &addr_client);
        test_server_udp_socket_new(ns_server, &sk_server, ifindex_server);

        message_out.header.op = N_DHCP4_OP_BOOTREPLY;

        r = n_dhcp4_network_server_udp_send(sk_server, &addr_client, &message_out, sizeof(message_out));
        assert(r >= 0);

        test_poll(sk_client);

        len = recv(sk_client, &message_in, sizeof(message_in), 0);
        assert(len == sizeof(message_in));
        assert(memcmp(&message_out, &message_in, sizeof(message_out)) == 0);

        close(sk_server);
        close(sk_client);

        test_del_ip(ns_server, ifindex_server, &addr_server, 8);
        test_del_ip(ns_client, ifindex_client, &addr_client, 8);
}

static void test_multiple_servers(void) {
        int netns, ifindex1, ifindex2, sk1, sk2;

        test_netns_new(&netns);

        test_veth_new(netns, &ifindex1, NULL, netns, &ifindex2, NULL);

        test_server_udp_socket_new(netns, &sk1, ifindex1);
        test_server_udp_socket_new(netns, &sk2, ifindex2);

        close(sk2);
        close(sk1);
        close(netns);
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

        test_multiple_servers();

        return 0;
}
