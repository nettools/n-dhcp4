/*
 * DHCPv4 Client Connection
 *
 * XXX
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <net/if_arp.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include "n-dhcp4-private.h"
#include "util/packet.h"

enum {
        _N_DHCP4_C_MESSAGE_INVALID = 0,
        N_DHCP4_C_MESSAGE_DISCOVER,
        N_DHCP4_C_MESSAGE_INFORM,
        N_DHCP4_C_MESSAGE_SELECT,
        N_DHCP4_C_MESSAGE_RENEW,
        N_DHCP4_C_MESSAGE_REBIND,
        N_DHCP4_C_MESSAGE_REBOOT,
        N_DHCP4_C_MESSAGE_RELEASE,
        N_DHCP4_C_MESSAGE_DECLINE,
};

int n_dhcp4_c_connection_init(NDhcp4CConnection *connection,
                              int *fd_epollp,
                              uint64_t seed,
                              int ifindex,
                              uint8_t htype,
                              uint8_t hlen,
                              const uint8_t *chaddr,
                              const uint8_t *bhaddr,
                              size_t idlen,
                              const uint8_t *id,
                              bool request_broadcast) {
        unsigned short int seed16v[3];
        int r;

        assert(hlen > 0);
        assert(hlen <= sizeof(connection->chaddr));
        assert(chaddr);
        assert(bhaddr);

        *connection = (NDhcp4CConnection)N_DHCP4_C_CONNECTION_NULL(*connection);
        connection->fd_epollp = fd_epollp;
        connection->ifindex = ifindex;
        connection->request_broadcast = request_broadcast;
        connection->htype = htype;
        connection->hlen = hlen;
        memcpy(connection->chaddr, chaddr, hlen);
        memcpy(connection->bhaddr, bhaddr, hlen);

        seed16v[0] = seed;
        seed16v[1] = seed >> 16;
        seed16v[2] = (seed >> 32) ^ (seed >> 48);

        r = seed48_r(seed16v, &connection->entropy);
        assert(!r);

        if (idlen) {
                connection->id = malloc(idlen);
                if (!connection->id)
                        return -ENOMEM;

                memcpy(connection->id, id, idlen);
        }

        /*
         * Force specific options depending on the configured transport. In
         * particular, Infiniband mandates broadcasts. It also has hw-addresses
         * bigger than the chaddr field, so it requires its suppression.
         */
        if (htype == ARPHRD_INFINIBAND)
                connection->request_broadcast = true;
        else
                connection->send_chaddr = true;

        return 0;
}

void n_dhcp4_c_connection_deinit(NDhcp4CConnection *connection) {
        if (connection->fd_epollp) {
                if (connection->fd_udp >= 0) {
                        epoll_ctl(*connection->fd_epollp, EPOLL_CTL_DEL, connection->fd_udp, NULL);
                        close(connection->fd_udp);
                }

                if (connection->fd_packet >= 0) {
                        epoll_ctl(*connection->fd_epollp, EPOLL_CTL_DEL, connection->fd_packet, NULL);
                        close(connection->fd_packet);
                }
        }

        free(connection->id);
        *connection = (NDhcp4CConnection)N_DHCP4_C_CONNECTION_NULL(*connection);
}

int n_dhcp4_c_connection_listen(NDhcp4CConnection *connection) {
        struct epoll_event ev = {
                .events = EPOLLIN,
        };
        int r;

        assert(connection->state == N_DHCP4_C_CONNECTION_STATE_INIT);

        r = n_dhcp4_c_socket_packet_new(&connection->fd_packet, connection->ifindex);
        if (r)
                return r;

        ev.data.u32 = N_DHCP4_CLIENT_EPOLL_IO;
        r = epoll_ctl(*connection->fd_epollp, EPOLL_CTL_ADD, connection->fd_packet, &ev);
        if (r < 0)
                return -errno;

        connection->state = N_DHCP4_C_CONNECTION_STATE_PACKET;

        return 0;
}

int n_dhcp4_c_connection_connect(NDhcp4CConnection *connection,
                                 const struct in_addr *client,
                                 const struct in_addr *server) {
        struct epoll_event ev = {
                .events = EPOLLIN,
        };
        int r;

        assert(connection->state == N_DHCP4_C_CONNECTION_STATE_PACKET);

        r = n_dhcp4_c_socket_udp_new(&connection->fd_udp, connection->ifindex, client, server);
        if (r)
                return r;

        ev.data.u32 = N_DHCP4_CLIENT_EPOLL_IO;
        r = epoll_ctl(*connection->fd_epollp, EPOLL_CTL_ADD, connection->fd_udp, &ev);
        if (r < 0)
                return -errno;

        r = packet_shutdown(connection->fd_packet);
        if (r < 0)
                return r;

        connection->client_ip = client->s_addr;
        connection->server_ip = server->s_addr;
        connection->state = N_DHCP4_C_CONNECTION_STATE_DRAINING;

        return 0;
}

static int n_dhcp4_c_connection_verify_incoming(NDhcp4CConnection *connection,
                                                NDhcp4Incoming *message) {
        NDhcp4Header *header = n_dhcp4_incoming_get_header(message);
        uint8_t *type;
        size_t n_type;
        uint8_t *id = NULL;
        size_t idlen = 0;
        int r;

        r = n_dhcp4_incoming_query(message, N_DHCP4_OPTION_MESSAGE_TYPE, &type, &n_type);
        if (r) {
                if (r == N_DHCP4_E_UNSET)
                        return N_DHCP4_E_MALFORMED;
                else
                        return r;
        } else if (n_type != sizeof(*type)) {
                return N_DHCP4_E_MALFORMED;
        }

        switch (*type) {
        case N_DHCP4_MESSAGE_OFFER:
        case N_DHCP4_MESSAGE_ACK:
        case N_DHCP4_MESSAGE_NAK:
                if (header->xid != connection->xid)
                        return N_DHCP4_E_UNEXPECTED;
                message->userdata.timestamp = connection->xts;
                connection->xid = 0;
                connection->xts = 0;
                break;
        case N_DHCP4_MESSAGE_FORCERENEW:
                break;
        default:
                return N_DHCP4_E_UNEXPECTED;
        }

        if (memcmp(connection->chaddr, header->chaddr, connection->hlen) != 0)
                return N_DHCP4_E_UNEXPECTED;

        r = n_dhcp4_incoming_query(message, N_DHCP4_OPTION_CLIENT_IDENTIFIER, &id, &idlen);
        if (r) {
                if (r == N_DHCP4_E_UNSET) {
                        if (connection->idlen)
                                return N_DHCP4_E_UNEXPECTED;
                } else {
                        return r;
                }
        }

        if (idlen != connection->idlen)
                return N_DHCP4_E_UNEXPECTED;

        if (memcmp(connection->id, id, idlen) != 0)
                return N_DHCP4_E_UNEXPECTED;

        return 0;
}

int n_dhcp4_c_connection_dispatch_io(NDhcp4CConnection *connection,
                                     NDhcp4Incoming **messagep) {
        _cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *message = NULL;
        int r;

        switch (connection->state) {
        case N_DHCP4_C_CONNECTION_STATE_PACKET:
                r = n_dhcp4_c_socket_packet_recv(connection->fd_packet, &message);
                if (r)
                        return r;

                break;
        case N_DHCP4_C_CONNECTION_STATE_DRAINING:
                r = n_dhcp4_c_socket_packet_recv(connection->fd_packet, &message);
                if (!r)
                        break;
                else if (r != N_DHCP4_E_AGAIN)
                        return r;

                /*
                 * The UDP socket is open and the packet socket has been shut down
                 * and drained, clean up the packet socket and fall through to
                 * dispatching the UDP socket.
                 */
                epoll_ctl(*connection->fd_epollp, EPOLL_CTL_DEL, connection->fd_packet, NULL);
                close(connection->fd_packet);
                connection->state = N_DHCP4_C_CONNECTION_STATE_UDP;

                /* fall-through */
        case N_DHCP4_C_CONNECTION_STATE_UDP:
                r = n_dhcp4_c_socket_udp_recv(connection->fd_udp, &message);
                if (r)
                        return r;
        }

        r = n_dhcp4_c_connection_verify_incoming(connection, message);
        if (r) {
                if (r == N_DHCP4_E_MALFORMED) {
                        *messagep = NULL;
                        return 0;
                }

                return -ENOTRECOVERABLE;
        }

        *messagep = message;
        message = NULL;
        return 0;
}

static int n_dhcp4_c_connection_packet_broadcast(NDhcp4CConnection *connection,
                                                 NDhcp4Outgoing *message) {
        int r;

        assert(connection->state == N_DHCP4_C_CONNECTION_STATE_PACKET);

        r = n_dhcp4_c_socket_packet_send(connection->fd_packet,
                                         connection->ifindex,
                                         connection->bhaddr,
                                         connection->hlen,
                                         message);
        if (r)
                return r;

        return 0;
}

static int n_dhcp4_c_connection_udp_broadcast(NDhcp4CConnection *connection,
                                              NDhcp4Outgoing *message) {
        int r;

        assert(connection->state > N_DHCP4_C_CONNECTION_STATE_PACKET);

        r = n_dhcp4_c_socket_udp_broadcast(connection->fd_udp, message);
        if (r)
                return r;

        return 0;
}

static int n_dhcp4_c_connection_udp_send(NDhcp4CConnection *connection,
                                         NDhcp4Outgoing *message) {
        int r;

        assert(connection->state > N_DHCP4_C_CONNECTION_STATE_PACKET);

        r = n_dhcp4_c_socket_udp_send(connection->fd_udp, message);
        if (r)
                return r;

        return 0;
}

static void n_dhcp4_c_connection_init_header(NDhcp4CConnection *connection,
                                             NDhcp4Header *header) {
        header->op = N_DHCP4_OP_BOOTREQUEST;
        header->htype = connection->htype;
        header->ciaddr = connection->client_ip;

        if (connection->request_broadcast)
                header->flags |= N_DHCP4_MESSAGE_FLAG_BROADCAST;

        if (connection->send_chaddr) {
                assert(connection->hlen <= sizeof(header->chaddr));

                header->hlen = connection->hlen;
                memcpy(header->chaddr, connection->chaddr, connection->hlen);
        }
}

static int n_dhcp4_c_connection_new_message(NDhcp4CConnection *connection,
                                            NDhcp4Outgoing **messagep, uint8_t type) {
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *message = NULL;
        NDhcp4Header *header;
        uint8_t message_type;
        int r;

        switch (type) {
        case N_DHCP4_C_MESSAGE_DISCOVER:
                message_type = N_DHCP4_MESSAGE_DISCOVER;
                break;
        case N_DHCP4_C_MESSAGE_INFORM:
                message_type = N_DHCP4_MESSAGE_INFORM;
                break;
        case N_DHCP4_C_MESSAGE_SELECT:
        case N_DHCP4_C_MESSAGE_RENEW:
        case N_DHCP4_C_MESSAGE_REBIND:
        case N_DHCP4_C_MESSAGE_REBOOT:
                message_type = N_DHCP4_MESSAGE_REQUEST;
                break;
        case N_DHCP4_C_MESSAGE_RELEASE:
                message_type = N_DHCP4_MESSAGE_RELEASE;
                break;
        case N_DHCP4_C_MESSAGE_DECLINE:
                message_type = N_DHCP4_MESSAGE_DECLINE;
                break;
        default:
                assert(0);
        }

        /*
         * We explicitly pass 0 as maximum message size, which makes
         * NDhcp4Outgoing use the mandated default value from the spec (see its
         * implementation). We could theoretically increase this, in case we
         * know more properties about the server, but this is first of all not
         * necessary (so far clients have no reason to send big packets, there
         * is simply no data to send), but also might break theoretical
         * use-cases like anycast-DHCP-servers, or whatever crazy setups
         * network-vendors come up with.
         */
        r = n_dhcp4_outgoing_new(&message, 0, N_DHCP4_OVERLOAD_FILE | N_DHCP4_OVERLOAD_SNAME);
        if (r)
                return r;

        header = n_dhcp4_outgoing_get_header(message);
        n_dhcp4_c_connection_init_header(connection, header);

        message->userdata.type = type;

        /*
         * Note that some implementations expect the MESSAGE_TYPE option to be
         * the first option, and possibly even hard-code access to it. Hence,
         * we really should make sure to pass it first as well.
         */
        r = n_dhcp4_outgoing_append(message, N_DHCP4_OPTION_MESSAGE_TYPE, &message_type, sizeof(message_type));
        if (r)
                return r;

        if (connection->idlen) {
                r = n_dhcp4_outgoing_append(message, N_DHCP4_OPTION_CLIENT_IDENTIFIER, connection->id, connection->idlen);
                if (r)
                        return r;
        }

        switch (message_type) {
        case N_DHCP4_MESSAGE_DISCOVER:
        case N_DHCP4_MESSAGE_REQUEST:
        case N_DHCP4_MESSAGE_INFORM: {
                uint16_t mtu;

                if (connection->state <= N_DHCP4_C_CONNECTION_STATE_PACKET) {
                        /*
                         * In case of packet sockets, we do not support
                         * fragmentation. Hence, our maximum message size
                         * equals the transport MTU. In case no mtu is given,
                         * we use the minimum size mandated by the IP spec. If
                         * we omit the field, some implementations will
                         * interpret this to mean any packet size is supported,
                         * which we rather not want as default behavior (we can
                         * always support suppressing this field, if that is
                         * what the caller wants).
                         */
                        mtu = htons(connection->mtu ?: N_DHCP4_NETWORK_IP_MINIMUM_MAX_SIZE);
                        r = n_dhcp4_outgoing_append(message, N_DHCP4_OPTION_MAXIMUM_MESSAGE_SIZE, &mtu, sizeof(mtu));
                        if (r)
                                return r;
                } else {
                        /*
                         * Once we use UDP sockets, we support fragmentation
                         * through the kernel IP stack. This means, the biggest
                         * message we can receive is the maximum UDP size plus
                         * the possible IP header. This would sum up to
                         * 2^16-1 + 20 (or even 2^16-1 + 60 if pedantic) and
                         * thus exceed the option field. Hence, we simply set
                         * the option to the maximum possible value.
                         */
                        mtu = htons(UINT16_MAX);
                        r = n_dhcp4_outgoing_append(message, N_DHCP4_OPTION_MAXIMUM_MESSAGE_SIZE, &mtu, sizeof(mtu));
                        if (r)
                                return r;
                }

                break;
        }
        default:
                break;
        }

        *messagep = message;
        message = NULL;
        return 0;
}

static uint32_t n_dhcp4_c_connection_get_random(NDhcp4CConnection *connection) {
        long int result;
        int r;

        r = mrand48_r(&connection->entropy, &result);
        assert(!r);

        return result;
};

static void n_dhcp4_c_connection_outgoing_set_secs(NDhcp4Outgoing *message, uint32_t secs) {
        NDhcp4Header *header = n_dhcp4_outgoing_get_header(message);

        /*
         * Some DHCP servers will reject DISCOVER or REQUEST messages if 'secs'
         * is not set (i.e., set to 0), even though the spec allows it.
         */
        assert(secs != 0);

        header->secs = htonl(secs);
}

static void n_dhcp4_c_connection_outgoing_set_xid(NDhcp4Outgoing *message, uint32_t xid) {
        NDhcp4Header *header = n_dhcp4_outgoing_get_header(message);

        header->xid = xid;
}

static int n_dhcp4_c_connection_incoming_get_xid(NDhcp4Incoming *message, uint32_t *xidp) {
        NDhcp4Header *header = n_dhcp4_incoming_get_header(message);

        *xidp = header->xid;

        return 0;
}

static int n_dhcp4_c_connection_incoming_get_yiaddr(NDhcp4Incoming *message, struct in_addr *yiaddr) {
        NDhcp4Header *header = n_dhcp4_incoming_get_header(message);

        yiaddr->s_addr = header->yiaddr;

        return 0;
}

static int n_dhcp4_c_connection_incoming_get_server_identifier(NDhcp4Incoming *message, struct in_addr *server_identifier) {
        uint8_t *data;
        size_t n_data;
        int r;

        r = n_dhcp4_incoming_query(message, N_DHCP4_OPTION_SERVER_IDENTIFIER, &data, &n_data);
        if (r)
                return r;
        else if (n_data != sizeof(*server_identifier))
                return N_DHCP4_E_MALFORMED;

        memcpy(server_identifier, data, n_data);

        return 0;
}

/*
 *      RFC2131 3.1
 *
 *      The client broadcasts a DHCPDISCOVER message on its local physical
 *      subnet.  The DHCPDISCOVER message MAY include options that suggest
 *      values for the network address and lease duration.  BOOTP relay
 *      agents may pass the message on to DHCP servers not on the same
 *      physical subnet.
 *
 *      RFC2131 3.5
 *
 *      [...] in its initial DHCPDISCOVER or DHCPREQUEST message, a client
 *      may provide the server with a list of specific parameters the
 *      client is interested in.  If the client includes a list of
 *      parameters in a DHCPDISCOVER message, it MUST include that list in
 *      any subsequent DHCPREQUEST messages.
 *
 *      [...]
 *
 *      In addition, the client may suggest values for the network address
 *      and lease time in the DHCPDISCOVER message.  The client may include
 *      the 'requested IP address' option to suggest that a particular IP
 *      address be assigned, and may include the 'IP address lease time'
 *      option to suggest the lease time it would like.  Other options
 *      representing "hints" at configuration parameters are allowed in a
 *      DHCPDISCOVER or DHCPREQUEST message.
 *
 *      RFC2131 4.4.1
 *
 *      The client generates and records a random transaction identifier and
 *      inserts that identifier into the 'xid' field.  The client records its
 *      own local time for later use in computing the lease expiration.  The
 *      client then broadcasts the DHCPDISCOVER on the local hardware
 *      broadcast address to the 0xffffffff IP broadcast address and 'DHCP
 *      server' UDP port.
 *
 *      If the 'xid' of an arriving DHCPOFFER message does not match the
 *      'xid' of the most recent DHCPDISCOVER message, the DHCPOFFER message
 *      must be silently discarded.  Any arriving DHCPACK messages must be
 *      silently discarded.
 */
int n_dhcp4_c_connection_discover_new(NDhcp4CConnection *connection,
                                      NDhcp4Outgoing **requestp,
                                      uint32_t secs) {
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *message = NULL;
        int r;

        r = n_dhcp4_c_connection_new_message(connection, &message, N_DHCP4_C_MESSAGE_DISCOVER);
        if (r)
                return r;

        n_dhcp4_c_connection_outgoing_set_xid(message, n_dhcp4_c_connection_get_random(connection));
        n_dhcp4_c_connection_outgoing_set_secs(message, secs);

        *requestp = message;
        message = NULL;
        return 0;
}

/*
 *
 *      RFC2131 4.1.1
 *
 *      The DHCPREQUEST message contains the same 'xid' as the DHCPOFFER
 *      message.
 *
 *      RFC2131 4.3.2
 *
 *      Client inserts the address of the selected server in 'server
 *      identifier', 'ciaddr' MUST be zero, 'requested IP address' MUST be
 *      filled in with the yiaddr value from the chosen DHCPOFFER.
 */
int n_dhcp4_c_connection_select_new(NDhcp4CConnection *connection,
                                    NDhcp4Outgoing **requestp,
                                    NDhcp4Incoming *offer,
                                    uint32_t secs) {
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *message = NULL;
        struct in_addr client;
        struct in_addr server;
        uint32_t xid;
        int r;

        r = n_dhcp4_c_connection_incoming_get_xid(offer, &xid);
        if (r)
                return r;

        r = n_dhcp4_c_connection_incoming_get_yiaddr(offer, &client);
        if (r)
                return r;

        r = n_dhcp4_c_connection_incoming_get_server_identifier(offer, &server);
        if (r)
                return r;

        r = n_dhcp4_c_connection_new_message(connection, &message, N_DHCP4_C_MESSAGE_SELECT);
        if (r)
                return r;

        n_dhcp4_c_connection_outgoing_set_xid(message, xid);
        n_dhcp4_c_connection_outgoing_set_secs(message, secs);

        r = n_dhcp4_outgoing_append(message, N_DHCP4_OPTION_REQUESTED_IP_ADDRESS, &client, sizeof(client));
        if (r)
                return r;

        r = n_dhcp4_outgoing_append(message, N_DHCP4_OPTION_SERVER_IDENTIFIER, &server, sizeof(server));
        if (r)
                return r;

        *requestp = message;
        message = NULL;
        return 0;
}

/*
 *      RFC2131 4.3.2
 *
 *      'server identifier' MUST NOT be filled in, 'requested IP address'
 *      option MUST be filled in with client's notion of its previously
 *      assigned address. 'ciaddr' MUST be zero. The client is seeking to
 *      verify a previously allocated, cached configuration. Server SHOULD
 *      send a DHCPNAK message to the client if the 'requested IP address'
 *      is incorrect, or is on the wrong network.
 */
int n_dhcp4_c_connection_reboot_new(NDhcp4CConnection *connection,
                                    NDhcp4Outgoing **requestp,
                                    const struct in_addr *client,
                                    uint32_t secs) {
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *message = NULL;
        int r;

        r = n_dhcp4_c_connection_new_message(connection, &message, N_DHCP4_C_MESSAGE_REBOOT);
        if (r)
                return r;

        n_dhcp4_c_connection_outgoing_set_xid(message, n_dhcp4_c_connection_get_random(connection));
        n_dhcp4_c_connection_outgoing_set_secs(message, secs);

        r = n_dhcp4_outgoing_append(message, N_DHCP4_OPTION_REQUESTED_IP_ADDRESS, client, sizeof(*client));
        if (r)
                return r;

        *requestp = message;
        message = NULL;
        return 0;
}

/*
 *      RFC2131 4.3.2
 *
 *      'server identifier' MUST NOT be filled in, 'requested IP address'
 *      option MUST NOT be filled in, 'ciaddr' MUST be filled in with
 *      client's IP address. In this situation, the client is completely
 *      configured, and is trying to extend its lease. This message will
 *      be unicast, so no relay agents will be involved in its
 *      transmission.  Because 'giaddr' is therefore not filled in, the
 *      DHCP server will trust the value in 'ciaddr', and use it when
 *      replying to the client.
 *
 *      A client MAY choose to renew or extend its lease prior to T1.  The
 *      server may choose not to extend the lease (as a policy decision by
 *      the network administrator), but should return a DHCPACK message
 *      regardless.
 *
 *      RFC2131 4.4.5
 *
 *      At time T1 the client moves to RENEWING state and sends (via unicast)
 *      a DHCPREQUEST message to the server to extend its lease.  The client
 *      sets the 'ciaddr' field in the DHCPREQUEST to its current network
 *      address. The client records the local time at which the DHCPREQUEST
 *      message is sent for computation of the lease expiration time.  The
 *      client MUST NOT include a 'server identifier' in the DHCPREQUEST
 *      message.
 */
int n_dhcp4_c_connection_renew_new(NDhcp4CConnection *connection,
                                   NDhcp4Outgoing **requestp,
                                   uint32_t secs) {
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *message = NULL;
        int r;

        r = n_dhcp4_c_connection_new_message(connection, &message, N_DHCP4_C_MESSAGE_RENEW);
        if (r)
                return r;

        n_dhcp4_c_connection_outgoing_set_xid(message, n_dhcp4_c_connection_get_random(connection));
        n_dhcp4_c_connection_outgoing_set_secs(message, secs);

        *requestp = message;
        message = NULL;
        return 0;
}

/*
 *      RFC2131 4.3.2
 *
 *      'server identifier' MUST NOT be filled in, 'requested IP address'
 *      option MUST NOT be filled in, 'ciaddr' MUST be filled in with
 *      client's IP address. In this situation, the client is completely
 *      configured, and is trying to extend its lease. This message MUST
 *      be broadcast to the 0xffffffff IP broadcast address.  The DHCP
 *      server SHOULD check 'ciaddr' for correctness before replying to
 *      the DHCPREQUEST.
 *
 *      RFC2131 4.4.5
 *
 *      If no DHCPACK arrives before time T2, the client moves to REBINDING
 *      state and sends (via broadcast) a DHCPREQUEST message to extend its
 *      lease.  The client sets the 'ciaddr' field in the DHCPREQUEST to its
 *      current network address.  The client MUST NOT include a 'server
 *      identifier' in the DHCPREQUEST message.
 */
int n_dhcp4_c_connection_rebind_new(NDhcp4CConnection *connection,
                                    NDhcp4Outgoing **requestp,
                                    uint32_t secs) {
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *message = NULL;
        int r;

        r = n_dhcp4_c_connection_new_message(connection, &message, N_DHCP4_C_MESSAGE_REBIND);
        if (r)
                return r;

        n_dhcp4_c_connection_outgoing_set_xid(message, n_dhcp4_c_connection_get_random(connection));
        n_dhcp4_c_connection_outgoing_set_secs(message, secs);

        *requestp = message;
        message = NULL;
        return 0;
}

/*
 *      RFC2131 3.2
 *
 *      If the client detects that the IP address in the DHCPACK message
 *      is already in use, the client MUST send a DHCPDECLINE message to the
 *      server and restarts the configuration process by requesting a
 *      new network address.
 *
 *      RFC2131 4.4.4
 *
 *      Because the client is declining the use of the IP address supplied by
 *      the server, the client broadcasts DHCPDECLINE messages.
 */
int n_dhcp4_c_connection_decline_new(NDhcp4CConnection *connection,
                                     NDhcp4Outgoing **requestp,
                                     NDhcp4Incoming *ack,
                                     const char *error) {
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *message = NULL;
        struct in_addr client;
        struct in_addr server;
        int r;

        r = n_dhcp4_c_connection_incoming_get_yiaddr(ack, &client);
        if (r)
                return r;

        r = n_dhcp4_c_connection_incoming_get_server_identifier(ack, &server);
        if (r)
                return r;

        r = n_dhcp4_c_connection_new_message(connection, &message, N_DHCP4_C_MESSAGE_DECLINE);
        if (r)
                return r;

        r = n_dhcp4_outgoing_append(message, N_DHCP4_OPTION_REQUESTED_IP_ADDRESS, &client, sizeof(client));
        if (r)
                return r;

        r = n_dhcp4_outgoing_append(message, N_DHCP4_OPTION_SERVER_IDENTIFIER, &server, sizeof(server));
        if (r)
                return r;

        if (error) {
                r = n_dhcp4_outgoing_append(message, N_DHCP4_OPTION_ERROR_MESSAGE, error, strlen(error) + 1);
                if (r)
                        return r;
        }

        *requestp = message;
        message = NULL;
        return 0;
}

/*
 *      RFC2131 3.4
 *
 *      If a client has obtained a network address through some other means
 *      (e.g., manual configuration), it may use a DHCPINFORM request message
 *      to obtain other local configuration parameters.
 *
 *      RFC2131 4.4
 *
 *      The DHCPINFORM message is not shown in figure 5.  A client simply
 *      sends the DHCPINFORM and waits for DHCPACK messages.  Once the client
 *      has selected its parameters, it has completed the configuration
 *      process.
 *
 *      RFC2131 4.4.3
 *
 *      The client sends a DHCPINFORM message. The client may request
 *      specific configuration parameters by including the 'parameter request
 *      list' option. The client generates and records a random transaction
 *      identifier and inserts that identifier into the 'xid' field. The
 *      client places its own network address in the 'ciaddr' field. The
 *      client SHOULD NOT request lease time parameters.
 *
 *      The client then unicasts the DHCPINFORM to the DHCP server if it
 *      knows the server's address, otherwise it broadcasts the message to
 *      the limited (all 1s) broadcast address.  DHCPINFORM messages MUST be
 *      directed to the 'DHCP server' UDP port.
 */
int n_dhcp4_c_connection_inform_new(NDhcp4CConnection *connection,
                                    NDhcp4Outgoing **requestp,
                                    uint32_t secs) {
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *message = NULL;
        int r;

        r = n_dhcp4_c_connection_new_message(connection, &message, N_DHCP4_C_MESSAGE_INFORM);
        if (r)
                return r;

        n_dhcp4_c_connection_outgoing_set_xid(message, n_dhcp4_c_connection_get_random(connection));
        n_dhcp4_c_connection_outgoing_set_secs(message, secs);

        *requestp = message;
        message = NULL;
        return 0;
}

/*
 *      RFC2131 3.1
 *
 *      The client may choose to relinquish its lease on a network address
 *      by sending a DHCPRELEASE message to the server.  The client
 *      identifies the lease to be released with its 'client identifier',
 *      or 'chaddr' and network address in the DHCPRELEASE message. If the
 *      client used a 'client identifier' when it obtained the lease, it
 *      MUST use the same 'client identifier' in the DHCPRELEASE message.
 *
 *      RFC2131 3.2
 *
 *      The client may choose to relinquish its lease on a network
 *      address by sending a DHCPRELEASE message to the server.  The
 *      client identifies the lease to be released with its
 *      'client identifier', or 'chaddr' and network address in the
 *      DHCPRELEASE message.
 *
 *      Note that in this case, where the client retains its network
 *      address locally, the client will not normally relinquish its
 *      lease during a graceful shutdown.  Only in the case where the
 *      client explicitly needs to relinquish its lease, e.g., the client
 *      is about to be moved to a different subnet, will the client send
 *      a DHCPRELEASE message.
 *
 *      RFC2131 4.4.4
 *
 *      The client unicasts DHCPRELEASE messages to the server.
 *
 *      RFC2131 4.4.6
 *
 *      If the client no longer requires use of its assigned network address
 *      (e.g., the client is gracefully shut down), the client sends a
 *      DHCPRELEASE message to the server.  Note that the correct operation
 *      of DHCP does not depend on the transmission of DHCPRELEASE messages.
 */
int n_dhcp4_c_connection_release_new(NDhcp4CConnection *connection,
                                     NDhcp4Outgoing **requestp,
                                     const char *error) {
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *message = NULL;
        int r;

        r = n_dhcp4_c_connection_new_message(connection, &message, N_DHCP4_C_MESSAGE_RELEASE);
        if (r)
                return r;

        r = n_dhcp4_outgoing_append(message, N_DHCP4_OPTION_SERVER_IDENTIFIER, &connection->server_ip, sizeof(connection->server_ip));
        if (r)
                return r;

        if (error) {
                r = n_dhcp4_outgoing_append(message, N_DHCP4_OPTION_ERROR_MESSAGE, error, strlen(error) + 1);
                if (r)
                        return r;
        }

        *requestp = message;
        message = NULL;
        return 0;
}

int n_dhcp4_c_connection_send_request(NDhcp4CConnection *connection,
                                      NDhcp4Outgoing *request,
                                      uint64_t timestamp) {
        NDhcp4Header *header = n_dhcp4_outgoing_get_header(request);
        int r;

        switch (request->userdata.type) {
        case N_DHCP4_C_MESSAGE_DISCOVER:
        case N_DHCP4_C_MESSAGE_SELECT:
        case N_DHCP4_C_MESSAGE_REBOOT:
        case N_DHCP4_C_MESSAGE_DECLINE:
                r = n_dhcp4_c_connection_packet_broadcast(connection, request);
                if (r)
                        return r;
                break;
        case N_DHCP4_C_MESSAGE_INFORM:
        case N_DHCP4_C_MESSAGE_REBIND:
                r = n_dhcp4_c_connection_udp_broadcast(connection, request);
                if (r)
                        return r;

                break;
        case N_DHCP4_C_MESSAGE_RENEW:
        case N_DHCP4_C_MESSAGE_RELEASE:
                r = n_dhcp4_c_connection_udp_send(connection, request);
                if (r)
                        return r;

                break;
        default:
                assert(0);
        }

        connection->xid = header->xid;
        connection->xts = timestamp;

        return 0;
}
