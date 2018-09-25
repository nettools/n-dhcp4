/*
 * DHCPv4 Server Connection
 *
 * XXX
 */

#include <assert.h>
#include <errno.h>
#include <net/if_arp.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include "n-dhcp4-private.h"
#include "util/packet.h"

void n_dhcp4_s_connection_init(NDhcp4SConnection *connection, int *efd, int ifindex) {
        *connection = (NDhcp4SConnection)N_DHCP4_S_CONNECTION_NULL(*connection);

        connection->efd = efd;
        connection->ifindex = ifindex;
}

void n_dhcp4_s_connection_deinit(NDhcp4SConnection *connection) {
        if (*connection->efd >= 0) {
                if (connection->ufd >= 0) {
                        epoll_ctl(*connection->efd, EPOLL_CTL_DEL, connection->ufd, NULL);
                        close(connection->ufd);
                }

                if (connection->pfd >= 0) {
                        close(connection->pfd);
                }
        }

        *connection = (NDhcp4SConnection)N_DHCP4_S_CONNECTION_NULL(*connection);
}

int n_dhcp4_s_connection_add_server_address(NDhcp4SConnection *connection,
                                            const struct in_addr *server_address) {

        /* XXX: add support for a set of server addresses */
        if (connection->server_address != INADDR_ANY)
                return -EBUSY;

        connection->server_address = server_address->s_addr;

        return 0;
}

int n_dhcp4_s_connection_remove_server_address(NDhcp4SConnection *connection,
                                               const struct in_addr *server_address) {

        if (connection->server_address != server_address->s_addr)
                return -ENOENT;

        connection->server_address = INADDR_ANY;

        return 0;
}

int n_dhcp4_s_connection_listen(NDhcp4SConnection *connection) {
        struct epoll_event ev = {
                .events = EPOLLIN,
        };
        int r;

        r = n_dhcp4_s_socket_packet_new(&connection->pfd);
        if (r < 0)
                return r;

        r = n_dhcp4_s_socket_udp_new(&connection->ufd, connection->ifindex);
        if (r < 0)
                return r;

        ev.data.u32 = N_DHCP4_SERVER_EPOLL_CONNECTION;
        r = epoll_ctl(*connection->efd, EPOLL_CTL_ADD, connection->ufd, &ev);
        if (r < 0)
                return -errno;

        return 0;
}

int n_dhcp4_s_connection_dispatch(NDhcp4SConnection *connection, NDhcp4Incoming **messagep) {
        return n_dhcp4_s_socket_udp_recv(connection->ufd, messagep);
}

/*
 * If the 'giaddr' field in a DHCP message from a client is non-zero,
 * the server sends any return messages to the 'DHCP server' port on the
 * BOOTP relay agent whose address appears in 'giaddr'. If the 'giaddr'
 * field is zero and the 'ciaddr' field is nonzero, then the server
 * unicasts DHCPOFFER and DHCPACK messages to the address in 'ciaddr'.
 * If 'giaddr' is zero and 'ciaddr' is zero, and the broadcast bit is
 * set, then the server broadcasts DHCPOFFER and DHCPACK messages to
 * 0xffffffff. If the broadcast bit is not set and 'giaddr' is zero and
 * 'ciaddr' is zero, then the server unicasts DHCPOFFER and DHCPACK
 * messages to the client's hardware address and 'yiaddr' address.  In
 * all cases, when 'giaddr' is zero, the server broadcasts any DHCPNAK
 * messages to 0xffffffff.
 */
int n_dhcp4_s_connection_send_reply(NDhcp4SConnection *connection,
                                    const struct in_addr *server_addr,
                                    NDhcp4Outgoing *message) {
        NDhcp4Header *header = n_dhcp4_outgoing_get_header(message);
        int r;

        if (header->giaddr) {
                const struct in_addr giaddr = { header->giaddr };

                r = n_dhcp4_s_socket_udp_send(connection->ufd,
                                              server_addr,
                                              &giaddr,
                                              message);
                if (r < 0)
                        return r;
        } else if (header->ciaddr) {
                const struct in_addr ciaddr = { header->ciaddr };

                r = n_dhcp4_s_socket_udp_send(connection->ufd,
                                              server_addr,
                                              &ciaddr,
                                              message);
                if (r < 0)
                        return r;
        } else if (header->flags & htons(N_DHCP4_MESSAGE_FLAG_BROADCAST)) {
                r = n_dhcp4_s_socket_udp_broadcast(connection->ufd,
                                                   server_addr,
                                                   message);
                if (r < 0)
                        return r;
        } else {
                r = n_dhcp4_s_socket_packet_send(connection->pfd,
                                                 connection->ifindex,
                                                 server_addr,
                                                 header->chaddr,
                                                 header->hlen,
                                                 &(struct in_addr){header->yiaddr},
                                                 message);
                if (r < 0)
                        return r;
        }

        return 0;
}

static void n_dhcp4_s_connection_init_reply_header(NDhcp4SConnection *connection,
                                                   NDhcp4Header *request,
                                                   NDhcp4Header *reply) {
        reply->op = N_DHCP4_OP_BOOTREPLY;

        reply->htype = request->htype;
        reply->hlen = request->hlen;
        reply->flags = request->flags;
        reply->xid = request->xid;
        reply->ciaddr = request->ciaddr;
        reply->giaddr = request->giaddr;
        memcpy(reply->chaddr, request->chaddr, request->hlen);
}

static int n_dhcp4_s_connection_outgoing_set_yiaddr(NDhcp4Outgoing *message,
                                                     uint32_t yiaddr,
                                                     uint32_t lifetime) {
        NDhcp4Header *header = n_dhcp4_outgoing_get_header(message);
        uint32_t t1 = lifetime / 2;
        uint32_t t2 = ((uint64_t)lifetime * 7) / 8;
        int r;

        r = n_dhcp4_outgoing_append(message,
                                    N_DHCP4_OPTION_IP_ADDRESS_LEASE_TIME,
                                    &lifetime, sizeof(lifetime));
        if (r < 0)
                return r;

        r = n_dhcp4_outgoing_append(message,
                                    N_DHCP4_OPTION_RENEWAL_T1_TIME,
                                    &t1, sizeof(t1));
        if (r < 0)
                return r;

        r = n_dhcp4_outgoing_append(message,
                                    N_DHCP4_OPTION_REBINDING_T2_TIME,
                                    &t2, sizeof(t2));
        if (r < 0)
                return r;

        header->yiaddr = yiaddr;

        return 0;
}

static int n_dhcp4_s_connection_incoming_get_max_message_size(NDhcp4Incoming *request,
                                                              uint16_t *max_message_size) {
        uint8_t *data;
        size_t n_data;
        int r;

        r = n_dhcp4_incoming_query(request,
                                   N_DHCP4_OPTION_MAXIMUM_MESSAGE_SIZE,
                                   &data,
                                   &n_data);
        if (r == -ENODATA) {
                *max_message_size = 0;
                return 0;
        } else if (r < 0)
                return r;
        else if (n_data != sizeof(*max_message_size))
                return -EIO;

        memcpy(max_message_size, data, sizeof(*max_message_size));

        return 0;
}

static int n_dhcp4_s_connection_new_reply(NDhcp4SConnection *connection,
                                          NDhcp4Outgoing **messagep,
                                          NDhcp4Incoming *request,
                                          uint8_t type,
                                          const struct in_addr *server_address) {
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *message = NULL;
        uint16_t max_message_size;
        uint8_t *client_identifier;
        size_t n_client_identifier;
        int r;

        r = n_dhcp4_s_connection_incoming_get_max_message_size(request, &max_message_size);
        if (r < 0)
                return r;

        r = n_dhcp4_outgoing_new(&message,
                                 max_message_size,
                                 N_DHCP4_OVERLOAD_FILE | N_DHCP4_OVERLOAD_SNAME);
        if (r < 0)
                return r;

        n_dhcp4_s_connection_init_reply_header(connection,
                                               n_dhcp4_incoming_get_header(request),
                                               n_dhcp4_outgoing_get_header(message));

        r = n_dhcp4_outgoing_append(message, N_DHCP4_OPTION_MESSAGE_TYPE, &type, sizeof(type));
        if (r < 0)
                return r;

        r = n_dhcp4_outgoing_append(message,
                                    N_DHCP4_OPTION_SERVER_IDENTIFIER,
                                    &server_address->s_addr,
                                    sizeof(server_address->s_addr));
        if (r < 0)
                return r;

        r = n_dhcp4_incoming_query(request,
                                   N_DHCP4_OPTION_CLIENT_IDENTIFIER,
                                   &client_identifier,
                                   &n_client_identifier);
        if (r >= 0) {
                r = n_dhcp4_outgoing_append(message,
                                            N_DHCP4_OPTION_CLIENT_IDENTIFIER,
                                            client_identifier,
                                            n_client_identifier);
                if (r < 0)
                        return r;
        } else if (r != -ENODATA) {
                return r;
        }

        *messagep = message;
        message = NULL;
        return 0;
}

int n_dhcp4_s_connection_offer_new(NDhcp4SConnection *connection,
                                   NDhcp4Outgoing **replyp,
                                   NDhcp4Incoming *request,
                                   const struct in_addr *server_address,
                                   const struct in_addr *client_address,
                                   uint32_t lifetime) {
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *reply = NULL;
        int r;

        r = n_dhcp4_s_connection_new_reply(connection,
                                           &reply,
                                           request,
                                           N_DHCP4_MESSAGE_OFFER,
                                           server_address);
        if (r < 0)
                return r;

        r = n_dhcp4_s_connection_outgoing_set_yiaddr(reply,
                                                     client_address->s_addr,
                                                     lifetime);
        if (r < 0)
                return r;

        *replyp = reply;
        reply = NULL;
        return 0;
}

int n_dhcp4_s_connection_ack_new(NDhcp4SConnection *connection,
                                 NDhcp4Outgoing **replyp,
                                 NDhcp4Incoming *request,
                                 const struct in_addr *server_address,
                                 const struct in_addr *client_address,
                                 uint32_t lifetime) {
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *reply = NULL;
        int r;

        r = n_dhcp4_s_connection_new_reply(connection,
                                           &reply,
                                           request,
                                           N_DHCP4_MESSAGE_ACK,
                                           server_address);
        if (r < 0)
                return r;

        r = n_dhcp4_s_connection_outgoing_set_yiaddr(reply,
                                                     client_address->s_addr,
                                                     lifetime);
        if (r < 0)
                return r;

        *replyp = reply;
        reply = NULL;
        return 0;
}

int n_dhcp4_s_connection_nak_new(NDhcp4SConnection *connection,
                                 NDhcp4Outgoing **replyp,
                                 NDhcp4Incoming *request,
                                 const struct in_addr *server_address) {
        _cleanup_(n_dhcp4_outgoing_freep) NDhcp4Outgoing *reply = NULL;
        int r;

        r = n_dhcp4_s_connection_new_reply(connection,
                                           &reply,
                                           request,
                                           N_DHCP4_MESSAGE_NAK,
                                           server_address);
        if (r < 0)
                return r;

        /*
         * The RFC is a bit unclear on how NAK should be sent, on the
         * one hand it says that they should be unconditinoally broadcast
         * (unless going through a relay agent), on the other, when they
         * do go through a relay agent, they will not be. We treat them
         * as any other reply and only broadcast when the broadcast bit
         * is set.
         */

        *replyp = reply;
        reply = NULL;
        return 0;
}
