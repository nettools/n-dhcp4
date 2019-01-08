/*
 * Tests for DHCP4 Socket Helpers
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
#include "util/netns.h"
#include "util/packet.h"

static void test_poll(int sk) {
        int r;

        r = poll(&(struct pollfd){.fd = sk, .events = POLLIN}, 1, -1);
        assert(r == 1);
}

static void test_client_packet_socket_new(int netns, int *skp, int ifindex) {
        int r, oldns;

        netns_get(&oldns);
        netns_set(netns);

        r = n_dhcp4_c_socket_packet_new(skp, ifindex);
        assert(r >= 0);

        netns_set(oldns);
}

static void test_client_udp_socket_new(int netns,
                                       int *skp,
                                       int ifindex,
                                       const struct in_addr *addr_client,
                                       const struct in_addr *addr_server) {
        int r, oldns;

        netns_get(&oldns);
        netns_set(netns);

        r = n_dhcp4_c_socket_udp_new(skp, ifindex, addr_client, addr_server);
        assert(r >= 0);

        netns_set(oldns);
}

static void test_server_packet_socket_new(int netns, int *skp) {
        int r, oldns;

        netns_get(&oldns);
        netns_set(netns);

        r = n_dhcp4_s_socket_packet_new(skp);
        assert(r >= 0);

        netns_set(oldns);
}

static void test_server_udp_socket_new(int netns, int *skp, int ifindex) {
        int r, oldns;

        netns_get(&oldns);
        netns_set(netns);

        r = n_dhcp4_s_socket_udp_new(skp, ifindex);
        assert(r >= 0);

        netns_set(oldns);
}

static void test_client_server_packet(int ns_server,
                                      int ns_client,
                                      int ifindex_server,
                                      int ifindex_client) {
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *outgoing = NULL;
        _cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *incoming = NULL;
        int sk_server, sk_client;
        int r;

        test_client_packet_socket_new(ns_client, &sk_client, ifindex_client);
        test_server_udp_socket_new(ns_server, &sk_server, ifindex_server);

        r = n_dhcp4_outgoing_new(&outgoing, 0, 0);
        assert(!r);
        n_dhcp4_outgoing_get_header(outgoing)->op = N_DHCP4_OP_BOOTREQUEST;

        r = n_dhcp4_c_socket_packet_send(sk_client,
                                         ifindex_client,
                                         (const unsigned char[]){0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
                                         ETH_ALEN,
                                         outgoing);
        assert(!r);

        test_poll(sk_server);

        r = n_dhcp4_s_socket_udp_recv(sk_server, &incoming);
        assert(!r);
        assert(incoming);

        close(sk_server);
        close(sk_client);
}

static void test_client_server_udp(int ns_server,
                                   int ns_client,
                                   int ifindex_server,
                                   int ifindex_client) {
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *outgoing = NULL;
        _cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *incoming = NULL;
        struct in_addr addr_client = (struct in_addr){ htonl(10 << 24 | 2) };
        struct in_addr addr_server = (struct in_addr){ htonl(10 << 24 | 1) };
        int r, sk_server, sk_client;

        test_add_ip(ns_client, ifindex_client, &addr_client, 8);
        test_client_udp_socket_new(ns_client, &sk_client, ifindex_client, &addr_client, &addr_server);
        test_server_udp_socket_new(ns_server, &sk_server, ifindex_server);
        test_add_ip(ns_server, ifindex_server, &addr_server, 8);

        r = n_dhcp4_outgoing_new(&outgoing, 0, 0);
        assert(!r);
        n_dhcp4_outgoing_get_header(outgoing)->op = N_DHCP4_OP_BOOTREQUEST;

        r = n_dhcp4_c_socket_udp_send(sk_client, outgoing);
        assert(!r);

        test_poll(sk_server);

        r = n_dhcp4_s_socket_udp_recv(sk_server, &incoming);
        assert(!r);
        assert(incoming);

        close(sk_server);
        close(sk_client);

        test_del_ip(ns_server, ifindex_server, &addr_server, 8);
        test_del_ip(ns_client, ifindex_client, &addr_client, 8);
}

static void test_server_client_packet(int ns_server,
                                      int ns_client,
                                      int ifindex_server,
                                      int ifindex_client,
                                      const struct ether_addr *mac_client) {
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *outgoing = NULL;
        _cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *incoming1 = NULL, *incoming2 = NULL;
        struct in_addr addr_client = (struct in_addr){ htonl(10 << 24 | 2) };
        struct in_addr addr_server = (struct in_addr){ htonl(10 << 24 | 1) };
        int sk_server, sk_client;
        int r;

        test_client_packet_socket_new(ns_client, &sk_client, ifindex_client);
        test_server_packet_socket_new(ns_server, &sk_server);
        test_add_ip(ns_server, ifindex_server, &addr_server, 8);

        r = n_dhcp4_outgoing_new(&outgoing, 0, 0);
        assert(!r);
        n_dhcp4_outgoing_get_header(outgoing)->op = N_DHCP4_OP_BOOTREPLY;

        r = n_dhcp4_s_socket_packet_send(sk_server,
                                         ifindex_server,
                                         &addr_server,
                                         mac_client->ether_addr_octet,
                                         ETH_ALEN,
                                         &addr_client,
                                         outgoing);
        assert(!r);
        r = n_dhcp4_s_socket_packet_send(sk_server,
                                         ifindex_server,
                                         &addr_server,
                                         (const unsigned char[]){0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
                                         ETH_ALEN,
                                         &addr_client,
                                         outgoing);
        assert(!r);

        test_poll(sk_client);

        r = n_dhcp4_c_socket_packet_recv(sk_client, &incoming1);
        assert(!r);
        assert(incoming1);

        test_poll(sk_client);

        r = n_dhcp4_c_socket_packet_recv(sk_client, &incoming2);
        assert(!r);
        assert(incoming2);

        close(sk_server);
        close(sk_client);

        test_del_ip(ns_server, ifindex_server, &addr_server, 8);
}

static void test_server_client_udp(int ns_server,
                                   int ns_client,
                                   int ifindex_server,
                                   int ifindex_client) {
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *outgoing = NULL;
        _cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *incoming = NULL;
        struct in_addr addr_client = (struct in_addr){ htonl(10 << 24 | 2) };
        struct in_addr addr_server = (struct in_addr){ htonl(10 << 24 | 1) };
        int sk_server, sk_client;
        int r;

        test_add_ip(ns_client, ifindex_client, &addr_client, 8);
        test_client_udp_socket_new(ns_client, &sk_client, ifindex_client, &addr_client, &addr_server);
        test_server_udp_socket_new(ns_server, &sk_server, ifindex_server);
        test_add_ip(ns_server, ifindex_server, &addr_server, 8);

        r = n_dhcp4_outgoing_new(&outgoing, 0, 0);
        assert(!r);
        n_dhcp4_outgoing_get_header(outgoing)->op = N_DHCP4_OP_BOOTREPLY;

        r = n_dhcp4_s_socket_udp_send(sk_server,
                                      &addr_server,
                                      &addr_client,
                                      outgoing);
        assert(!r);

        test_poll(sk_client);

        r = n_dhcp4_c_socket_udp_recv(sk_client, &incoming);
        assert(!r);
        assert(incoming);

        close(sk_server);
        close(sk_client);

        test_del_ip(ns_server, ifindex_server, &addr_server, 8);
        test_del_ip(ns_client, ifindex_client, &addr_client, 8);
}

static void test_multiple_servers(void) {
        int netns, ifindex1, ifindex2, sk1, sk2;

        netns_new(&netns);

        test_veth_new(netns, &ifindex1, NULL, netns, &ifindex2, NULL);

        test_server_udp_socket_new(netns, &sk1, ifindex1);
        test_server_udp_socket_new(netns, &sk2, ifindex2);

        close(sk2);
        close(sk1);
        close(netns);
}

int main(int argc, char **argv) {
        int ns_server, ns_client, ifindex_server, ifindex_client;
        struct ether_addr mac_client;

        test_setup();

        netns_new(&ns_server);
        netns_new(&ns_client);

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
