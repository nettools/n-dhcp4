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

static void test_poll(int efd, unsigned int u32) {
        struct epoll_event event = {};
        int r;

        r = epoll_wait(efd, &event, 1, -1);
        assert(r == 1);
        assert(event.events == EPOLLIN);
        assert(event.data.u32 == u32);
}

static void test_s_connection_listen(int netns, NDhcp4SConnection *connection) {
        int r, oldns;

        test_netns_get(&oldns);
        test_netns_set(netns);

        r = n_dhcp4_s_connection_listen(connection);
        assert(!r);

        test_netns_set(oldns);
}

static void test_c_connection_listen(int netns, NDhcp4CConnection *connection) {
        int r, oldns;

        test_netns_get(&oldns);
        test_netns_set(netns);

        r = n_dhcp4_c_connection_listen(connection);
        assert(!r);

        test_netns_set(oldns);
}

static void test_c_connection_connect(int netns,
                                      NDhcp4CConnection *connection,
                                      const struct in_addr *client,
                                      const struct in_addr *server) {
        int r, oldns;

        test_netns_get(&oldns);
        test_netns_set(netns);

        r = n_dhcp4_c_connection_connect(connection, client, server);
        assert(!r);

        test_netns_set(oldns);
}

static void test_server_receive(NDhcp4SConnection *connection, uint8_t type, NDhcp4Incoming **messagep) {
        _cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *message = NULL;
        uint8_t *value;
        size_t size;
        int r;

        test_poll(*connection->fd_epollp, N_DHCP4_SERVER_EPOLL_IO);

        r = n_dhcp4_s_connection_dispatch_io(connection, &message);
        assert(!r);
        assert(message);

        r = n_dhcp4_incoming_query(message, N_DHCP4_OPTION_MESSAGE_TYPE, &value, &size);
        assert(!r);
        assert(size == 1);
        assert(*value == type);

        if (messagep) {
                *messagep = message;
                message = NULL;
        }
}

static void test_client_receive(NDhcp4CConnection *connection, uint8_t type, NDhcp4Incoming **messagep) {
        _cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *message = NULL;
        uint8_t *value;
        size_t size;
        int r;

        test_poll(*connection->fd_epollp, N_DHCP4_CLIENT_EPOLL_IO);

        r = n_dhcp4_c_connection_dispatch_io(connection, &message);
        assert(!r);
        assert(message);

        r = n_dhcp4_incoming_query(message, N_DHCP4_OPTION_MESSAGE_TYPE, &value, &size);
        assert(!r);
        assert(size == 1);
        assert(*value == type);

        if (messagep) {
                *messagep = message;
                message = NULL;
        }
}

static void test_discover(NDhcp4SConnection *connection_server,
                          NDhcp4CConnection *connection_client,
                          const struct in_addr *addr_server,
                          const struct in_addr *addr_client,
                          NDhcp4Incoming **offerp) {
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *request_out = NULL;
        _cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *request_in = NULL;
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *reply_out = NULL;
        int r;

        r = n_dhcp4_c_connection_discover_new(connection_client, &request_out, 1);
        assert(!r);

        r = n_dhcp4_c_connection_send_request(connection_client, request_out, 0);
        assert(!r);

        test_server_receive(connection_server, N_DHCP4_MESSAGE_DISCOVER, &request_in);

        r = n_dhcp4_s_connection_offer_new(connection_server, &reply_out, request_in, addr_server, addr_client, 60);
        assert(!r);

        r = n_dhcp4_s_connection_send_reply(connection_server, addr_server, reply_out);
        assert(!r);

        test_client_receive(connection_client, N_DHCP4_MESSAGE_OFFER, offerp);
}

static void test_select(NDhcp4SConnection *connection_server,
                        NDhcp4CConnection *connection_client,
                        NDhcp4Incoming *offer,
                        const struct in_addr *addr_server,
                        const struct in_addr *addr_client) {
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *request_out = NULL;
        _cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *request_in = NULL;
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *reply = NULL;
        int r;

        r = n_dhcp4_c_connection_select_new(connection_client, &request_out, offer, 1);
        assert(!r);

        r = n_dhcp4_c_connection_send_request(connection_client, request_out, 0);
        assert(!r);

        test_server_receive(connection_server, N_DHCP4_MESSAGE_REQUEST, &request_in);

        r = n_dhcp4_s_connection_ack_new(connection_server, &reply, request_in, addr_server, addr_client, 60);
        assert(!r);

        r = n_dhcp4_s_connection_send_reply(connection_server, addr_server, reply);
        assert(!r);

        test_client_receive(connection_client, N_DHCP4_MESSAGE_ACK, NULL);
}

static void test_reboot(NDhcp4SConnection *connection_server,
                        NDhcp4CConnection *connection_client,
                        const struct in_addr *addr_server,
                        const struct in_addr *addr_client,
                        NDhcp4Incoming **ackp) {
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *request_out = NULL;
        _cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *request_in = NULL;
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *reply = NULL;
        int r;

        r = n_dhcp4_c_connection_reboot_new(connection_client, &request_out, addr_server, 1);
        assert(!r);

        r = n_dhcp4_c_connection_send_request(connection_client, request_out, 0);
        assert(!r);

        test_server_receive(connection_server, N_DHCP4_MESSAGE_REQUEST, &request_in);

        r = n_dhcp4_s_connection_ack_new(connection_server, &reply, request_in, addr_server, addr_client, 60);
        assert(!r);

        r = n_dhcp4_s_connection_send_reply(connection_server, addr_server, reply);
        assert(!r);

        test_client_receive(connection_client, N_DHCP4_MESSAGE_ACK, ackp);
}

static void test_decline(NDhcp4SConnection *connection_server,
                         NDhcp4CConnection *connection_client,
                         NDhcp4Incoming *ack) {
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *request_out = NULL;
        int r;

        r = n_dhcp4_c_connection_decline_new(connection_client, &request_out, ack, "No thanks.");
        assert(!r);

        r = n_dhcp4_c_connection_send_request(connection_client, request_out, 0);
        assert(!r);

        test_server_receive(connection_server, N_DHCP4_MESSAGE_DECLINE, NULL);
}


static void test_renew(NDhcp4SConnection *connection_server,
                       NDhcp4CConnection *connection_client,
                       const struct in_addr *addr_server,
                       const struct in_addr *addr_client) {
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *request_out = NULL;
        _cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *request_in = NULL;
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *reply = NULL;
        int r;

        r = n_dhcp4_c_connection_renew_new(connection_client, &request_out, 1);
        assert(!r);

        r = n_dhcp4_c_connection_send_request(connection_client, request_out, 0);
        assert(!r);

        test_server_receive(connection_server, N_DHCP4_MESSAGE_REQUEST, &request_in);

        r = n_dhcp4_s_connection_ack_new(connection_server, &reply, request_in, addr_server, addr_client, 60);
        assert(!r);

        r = n_dhcp4_s_connection_send_reply(connection_server, addr_server, reply);
        assert(!r);

        test_client_receive(connection_client, N_DHCP4_MESSAGE_ACK, NULL);
}

static void test_rebind(NDhcp4SConnection *connection_server,
                        NDhcp4CConnection *connection_client,
                        const struct in_addr *addr_server,
                        const struct in_addr *addr_client) {
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *request_out = NULL;
        _cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *request_in = NULL;
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *reply = NULL;
        int r;

        r = n_dhcp4_c_connection_rebind_new(connection_client, &request_out, 1);
        assert(!r);

        r = n_dhcp4_c_connection_send_request(connection_client, request_out, 0);
        assert(!r);

        test_server_receive(connection_server, N_DHCP4_MESSAGE_REQUEST, &request_in);

        r = n_dhcp4_s_connection_ack_new(connection_server, &reply, request_in, addr_server, addr_client, 60);
        assert(!r);

        r = n_dhcp4_s_connection_send_reply(connection_server, addr_server, reply);
        assert(!r);

        test_client_receive(connection_client, N_DHCP4_MESSAGE_ACK, NULL);
}

static void test_release(NDhcp4SConnection *connection_server,
                         NDhcp4CConnection *connection_client,
                         const struct in_addr *addr_server,
                         const struct in_addr *addr_client) {
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *request_out = NULL;
        int r;

        r = n_dhcp4_c_connection_release_new(connection_client, &request_out, "Shutting down!");
        assert(!r);

        r = n_dhcp4_c_connection_send_request(connection_client, request_out, 0);
        assert(!r);

        test_server_receive(connection_server, N_DHCP4_MESSAGE_RELEASE, NULL);
}

int main(int argc, char **argv) {
        NDhcp4SConnection connection_server = N_DHCP4_S_CONNECTION_NULL(connection_server);
        NDhcp4CConnection connection_client = N_DHCP4_C_CONNECTION_NULL(connection_client);
        _cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *offer = NULL;
        _cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *ack = NULL;
        struct in_addr addr_server = (struct in_addr){ htonl(10 << 24 | 1) };
        struct in_addr addr_client = (struct in_addr){ htonl(10 << 24 | 2) };
        int r, efd_server, efd_client, ns_server, ns_client, ifindex_server, ifindex_client;
        struct ether_addr mac_client;

        efd_server = epoll_create1(EPOLL_CLOEXEC);
        assert(efd_server >= 0);

        efd_client = epoll_create1(EPOLL_CLOEXEC);
        assert(efd_client >= 0);

        test_setup();

        test_netns_new(&ns_server);
        test_netns_new(&ns_client);

        test_veth_new(ns_server, &ifindex_server, NULL, ns_client, &ifindex_client, &mac_client);
        test_add_ip(ns_server, ifindex_server, &addr_server, 8);

        n_dhcp4_s_connection_init(&connection_server, &efd_server, ifindex_server);

        r = n_dhcp4_s_connection_add_server_address(&connection_server, &addr_server);
        assert(!r);

        r = n_dhcp4_c_connection_init(&connection_client,
                                      &efd_client,
                                      0,
                                      ifindex_client,
                                      ARPHRD_ETHER,
                                      ETH_ALEN,
                                      mac_client.ether_addr_octet,
                                      (const uint8_t[]){0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
                                      0,
                                      NULL,
                                      false);
        assert(!r);

        test_s_connection_listen(ns_server, &connection_server);
        test_c_connection_listen(ns_client, &connection_client);

        test_discover(&connection_server, &connection_client, &addr_server, &addr_client, &offer);
        test_select(&connection_server, &connection_client, offer, &addr_server, &addr_client);
        test_reboot(&connection_server, &connection_client, &addr_server, &addr_client, &ack);
        test_decline(&connection_server, &connection_client, ack);

        test_add_ip(ns_client, connection_client.ifindex, &addr_client, 8);
        test_c_connection_connect(ns_client, &connection_client, &addr_client, &addr_server);

        test_renew(&connection_server, &connection_client, &addr_server, &addr_client);
        test_rebind(&connection_server, &connection_client, &addr_server, &addr_client);
        test_release(&connection_server, &connection_client, &addr_server, &addr_client);

        n_dhcp4_c_connection_deinit(&connection_client);
        n_dhcp4_s_connection_deinit(&connection_server);

        test_del_ip(ns_client, ifindex_client, &addr_client, 8);
        test_del_ip(ns_server, ifindex_server, &addr_server, 8);
        close(ns_client);
        close(ns_server);
        close(efd_client);
        close(efd_server);

        return 0;
}
