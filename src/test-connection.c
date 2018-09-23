/*
 * Tests for DHCP4 Client Connections
 */

#undef NDEBUG
#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <poll.h>
#include <linux/if_packet.h>
#include <net/if_arp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include "n-dhcp4-private.h"
#include "test.h"
#include "util/packet.h"

static void test_poll(int sk) {
        int r;

        r = poll(&(struct pollfd){.fd = sk, .events = POLLIN}, 1, -1);
        assert(r == 1);
}

static void test_server_packet_socket_new(int netns, int *skp) {
        int r, oldns;

        test_netns_get(&oldns);
        test_netns_set(netns);

        r = n_dhcp4_s_socket_packet_new(skp);
        assert(r >= 0);

        test_netns_set(oldns);
}

static void test_server_udp_socket_new(int netns, int *skp, int ifindex) {
        int r, oldns;

        test_netns_get(&oldns);
        test_netns_set(netns);

        r = n_dhcp4_s_socket_udp_new(skp, ifindex);
        assert(r >= 0);

        test_netns_set(oldns);
}

static void test_server_receive(int sk, uint8_t type) {
        _cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *message = NULL;
        uint8_t buf[1 << 15];
        const void *value;
        ssize_t len;
        size_t size;
        int r;

        test_poll(sk);

        len = recv(sk, buf, sizeof(buf), 0);
        assert(len > 0);

        r = n_dhcp4_incoming_new(&message, buf, len);
        assert(r >= 0);

        r = n_dhcp4_incoming_query(message, N_DHCP4_OPTION_MESSAGE_TYPE, &value, &size);
        assert(r >= 0);
        assert(size == 1);
        assert(*(const uint8_t *)value == type);
}

static void test_acquisition(int ns_client, NDhcp4CConnection *connection, int sk_server, const struct in_addr *addr_server) {
        struct in_addr addr_client = (struct in_addr){ htonl(10 << 24 | 2) };
        int r, oldns;

        test_netns_get(&oldns);
        test_netns_set(ns_client);
        r = n_dhcp4_c_connection_listen(connection);
        test_netns_set(oldns);
        assert(r >= 0);

        r = n_dhcp4_c_connection_discover(connection, 1, 1);
        assert(r >= 0);

        test_server_receive(sk_server, N_DHCP4_MESSAGE_DISCOVER);

        r = n_dhcp4_c_connection_select(connection, &addr_client, addr_server, 1, 1);
        assert(r >= 0);

        test_server_receive(sk_server, N_DHCP4_MESSAGE_REQUEST);

        r = n_dhcp4_c_connection_decline(connection, "No thanks.", &addr_client, addr_server);
        assert(r >= 0);

        test_server_receive(sk_server, N_DHCP4_MESSAGE_DECLINE);

        test_add_ip(ns_client, connection->ifindex, &addr_client, 8);

        test_netns_set(ns_client);
        r = n_dhcp4_c_connection_connect(connection, &addr_client, addr_server);
        test_netns_set(oldns);
        assert(r >= 0);

        r = n_dhcp4_c_connection_renew(connection, 1, 1);
        assert(r >= 0);

        test_server_receive(sk_server, N_DHCP4_MESSAGE_REQUEST);

        r = n_dhcp4_c_connection_rebind(connection, 1, 1);
        assert(r >= 0);

        test_server_receive(sk_server, N_DHCP4_MESSAGE_REQUEST);

        r = n_dhcp4_c_connection_release(connection, "Shutting down!");
        assert(r >= 0);

        test_server_receive(sk_server, N_DHCP4_MESSAGE_RELEASE);
}

int main(int argc, char **argv) {
        int efd;
        NDhcp4CConnection connection = N_DHCP4_C_CONNECTION_NULL;
        struct in_addr addr_server = (struct in_addr){ htonl(10 << 24 | 1) };
        int r, ns_server, ns_client, ifindex_server, ifindex_client, sk_server_packet, sk_server_udp;
        struct ether_addr mac_client;

        efd = epoll_create1(EPOLL_CLOEXEC);
        assert(efd >= 0);

        r = test_setup();
        if (r)
                return r;

        test_netns_new(&ns_server);
        test_netns_new(&ns_client);

        test_veth_new(ns_server, &ifindex_server, NULL, ns_client, &ifindex_client, &mac_client);

        test_server_packet_socket_new(ns_server, &sk_server_packet);
        test_server_udp_socket_new(ns_server, &sk_server_udp, ifindex_server);
        test_add_ip(ns_server, ifindex_server, &addr_server, 8);

        r = n_dhcp4_c_connection_init(&connection,
                                      &efd,
                                      ifindex_client,
                                      ARPHRD_ETHER,
                                      ETH_ALEN,
                                      mac_client.ether_addr_octet,
                                      (const uint8_t[]){0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
                                      0,
                                      NULL,
                                      false);
        assert(r >= 0);
        test_acquisition(ns_client, &connection, sk_server_udp, &addr_server);
        n_dhcp4_c_connection_deinit(&connection);

        test_del_ip(ns_server, ifindex_server, &addr_server, 8);
        close(sk_server_udp);
        close(sk_server_packet);
        close(ns_client);
        close(ns_server);
        close(efd);

        return 0;
}
