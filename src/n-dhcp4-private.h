#pragma once

#include <arpa/inet.h>
#include <c-list.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/netdevice.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include "n-dhcp4.h"

typedef struct NDhcp4CConnection NDhcp4CConnection;
typedef struct NDhcp4CEventNode NDhcp4CEventNode;
typedef struct NDhcp4Header NDhcp4Header;
typedef struct NDhcp4Incoming NDhcp4Incoming;
typedef struct NDhcp4Message NDhcp4Message;
typedef struct NDhcp4Outgoing NDhcp4Outgoing;

/* macros */

#define _cleanup_(_x) __attribute__((__cleanup__(_x)))
#define _packed_ __attribute__((__packed__))
#define _public_ __attribute__((__visibility__("default")))

#define MIN(_x, _y) ((_x) < (_y) ? (_x) : (_y))

/* specs */

#define N_DHCP4_NETWORK_IP_MAXIMUM_HEADER_SIZE (60) /* See RFC791 */
#define N_DHCP4_NETWORK_IP_MINIMUM_MAX_SIZE (576) /* See RFC791 */
#define N_DHCP4_NETWORK_SERVER_PORT (67)
#define N_DHCP4_NETWORK_CLIENT_PORT (68)
#define N_DHCP4_MESSAGE_MAGIC ((uint32_t)(0x63825363))
#define N_DHCP4_MESSAGE_FLAG_BROADCAST (htons(0x8000))

enum {
        N_DHCP4_OP_BOOTREQUEST                          = 1,
        N_DHCP4_OP_BOOTREPLY                            = 2,
};

enum {
        N_DHCP4_OPTION_PAD                              = 0,
        N_DHCP4_OPTION_SUBNET_MASK                      = 1,
        N_DHCP4_OPTION_TIME_OFFSET                      = 2,
        N_DHCP4_OPTION_ROUTER                           = 3,
        N_DHCP4_OPTION_DOMAIN_NAME_SERVER               = 6,
        N_DHCP4_OPTION_HOST_NAME                        = 12,
        N_DHCP4_OPTION_BOOT_FILE_SIZE                   = 13,
        N_DHCP4_OPTION_DOMAIN_NAME                      = 15,
        N_DHCP4_OPTION_ROOT_PATH                        = 17,
        N_DHCP4_OPTION_ENABLE_IP_FORWARDING             = 19,
        N_DHCP4_OPTION_ENABLE_IP_FORWARDING_NL          = 20,
        N_DHCP4_OPTION_POLICY_FILTER                    = 21,
        N_DHCP4_OPTION_INTERFACE_MDR                    = 22,
        N_DHCP4_OPTION_INTERFACE_TTL                    = 23,
        N_DHCP4_OPTION_INTERFACE_MTU_AGING_TIMEOUT      = 24,
        N_DHCP4_OPTION_INTERFACE_MTU                    = 26,
        N_DHCP4_OPTION_BROADCAST                        = 28,
        N_DHCP4_OPTION_STATIC_ROUTE                     = 33,
        N_DHCP4_OPTION_NTP_SERVER                       = 42,
        N_DHCP4_OPTION_VENDOR_SPECIFIC                  = 43,
        N_DHCP4_OPTION_REQUESTED_IP_ADDRESS             = 50,
        N_DHCP4_OPTION_IP_ADDRESS_LEASE_TIME            = 51,
        N_DHCP4_OPTION_OVERLOAD                         = 52,
        N_DHCP4_OPTION_MESSAGE_TYPE                     = 53,
        N_DHCP4_OPTION_SERVER_IDENTIFIER                = 54,
        N_DHCP4_OPTION_PARAMETER_REQUEST_LIST           = 55,
        N_DHCP4_OPTION_ERROR_MESSAGE                    = 56,
        N_DHCP4_OPTION_MAXIMUM_MESSAGE_SIZE             = 57,
        N_DHCP4_OPTION_RENEWAL_T1_TIME                  = 58,
        N_DHCP4_OPTION_REBINDING_T2_TIME                = 59,
        N_DHCP4_OPTION_VENDOR_CLASS_IDENTIFIER          = 60,
        N_DHCP4_OPTION_CLIENT_IDENTIFIER                = 61,
        N_DHCP4_OPTION_FQDN                             = 81,
        N_DHCP4_OPTION_NEW_POSIX_TIMEZONE               = 100,
        N_DHCP4_OPTION_NEW_TZDB_TIMEZONE                = 101,
        N_DHCP4_OPTION_CLASSLESS_STATIC_ROUTE           = 121,
        N_DHCP4_OPTION_PRIVATE_BASE                     = 224,
        N_DHCP4_OPTION_PRIVATE_LAST                     = 254,
        N_DHCP4_OPTION_END                              = 255,
        _N_DHCP4_OPTION_N                               = 256,
};

enum {
        N_DHCP4_OVERLOAD_FILE                           = 1,
        N_DHCP4_OVERLOAD_SNAME                          = 2,
};

enum {
        N_DHCP4_MESSAGE_DISCOVER                        = 1,
        N_DHCP4_MESSAGE_OFFER                           = 2,
        N_DHCP4_MESSAGE_REQUEST                         = 3,
        N_DHCP4_MESSAGE_DECLINE                         = 4,
        N_DHCP4_MESSAGE_ACK                             = 5,
        N_DHCP4_MESSAGE_NAK                             = 6,
        N_DHCP4_MESSAGE_RELEASE                         = 7,
        N_DHCP4_MESSAGE_INFORM                          = 8,
        N_DHCP4_MESSAGE_FORCERENEW                      = 9,
};

struct NDhcp4Header {
        uint8_t op;
        uint8_t htype;
        uint8_t hlen;
        uint8_t hops;
        uint32_t xid;
        uint16_t secs;
        uint16_t flags;
        uint32_t ciaddr;
        uint32_t yiaddr;
        uint32_t siaddr;
        uint32_t giaddr;
        uint8_t chaddr[16];
} _packed_;

struct NDhcp4Message {
        NDhcp4Header header;
        uint8_t sname[64];
        uint8_t file[128];
        uint32_t magic;
        uint8_t options[];
} _packed_;

/* objects */

enum {
        _N_DHCP4_E_INTERNAL = _N_DHCP4_E_N,

        N_DHCP4_E_NO_SPACE,
        N_DHCP4_E_MALFORMED,
        N_DHCP4_E_UNSET,
};

enum {
        N_DHCP4_C_CONNECTION_STATE_INIT,
        N_DHCP4_C_CONNECTION_STATE_PACKET,
        N_DHCP4_C_CONNECTION_STATE_DRAINING,
        N_DHCP4_C_CONNECTION_STATE_UDP,
};

enum {
        N_DHCP4_CLIENT_EPOLL_TIMER,
        N_DHCP4_CLIENT_EPOLL_CONNECTION,
};

enum {
        N_DHCP4_C_PROBE_STATE_INIT,
        N_DHCP4_C_PROBE_STATE_INIT_REBOOT,
        N_DHCP4_C_PROBE_STATE_SELECTING,
        N_DHCP4_C_PROBE_STATE_REBOOTING,
        N_DHCP4_C_PROBE_STATE_REQUESTING,
        N_DHCP4_C_PROBE_STATE_BOUND,
        N_DHCP4_C_PROBE_STATE_RENEWING,
        N_DHCP4_C_PROBE_STATE_REBINDING,
};

struct NDhcp4Outgoing {
        NDhcp4Message *message;
        size_t n_message;
        size_t i_message;
        size_t max_size;

        uint8_t overload : 2;
};

#define N_DHCP4_OUTGOING_NULL(_x) {                                             \
        }

struct NDhcp4Incoming {
        struct {
                uint8_t *value;
                size_t size;
        } options[_N_DHCP4_OPTION_N];

        size_t n_message;
        NDhcp4Message message;
        /* @message must be the last member */
};

#define N_DHCP4_INCOMING_NULL(_x) {                                             \
        }

struct NDhcp4ClientConfig {
        int ifindex;
        unsigned int transport;
        uint8_t mac[MAX_ADDR_LEN];
        size_t n_mac;
        uint8_t broadcast_mac[MAX_ADDR_LEN];
        size_t n_broadcast_mac;
        uint8_t *client_id;
        size_t n_client_id;
};

#define N_DHCP4_CLIENT_CONFIG_NULL(_x) {                                        \
                .transport = _N_DHCP4_TRANSPORT_N,                              \
        }

struct NDhcp4ClientProbeConfig {
        bool inform_only;
        bool init_reboot;
        struct in_addr requested_ip;
};

#define N_DHCP4_CLIENT_PROBE_CONFIG_NULL(_x) {                                  \
        }

struct NDhcp4CEventNode {
        CList client_link;
        CList probe_link;
        NDhcp4ClientEvent event;
        bool is_public : 1;
};

#define N_DHCP4_C_EVENT_NODE_NULL(_x) {                                         \
                .client_link = C_LIST_INIT((_x).client_link),                   \
                .probe_link = C_LIST_INIT((_x).probe_link),                     \
        }

struct NDhcp4CConnection {
        unsigned int state;             /* current connection state */
        int *efd;                       /* epoll fd */
        int ifindex;                    /* interface index */
        int pfd;                        /* packet socket */
        int ufd;                        /* udp socket */

        bool request_broadcast : 1;     /* request broadcast from server */
        bool send_chaddr : 1;           /* send chaddr to server */

        uint8_t htype;                  /* APR hardware type */
        uint8_t hlen;                   /* hardware address length */
        uint8_t chaddr[MAX_ADDR_LEN];   /* client hardware address */
        uint8_t bhaddr[MAX_ADDR_LEN];   /* broadcast hardware address */

        uint32_t client_ip;             /* client IP address, or 0 */
        uint32_t server_ip;             /* server IP address, or 0 */
        uint16_t mtu;                   /* client mtu, or 0 */

        size_t idlen;                   /* client identifier length */
        uint8_t *id;                    /* client identifier */
};

#define N_DHCP4_C_CONNECTION_NULL(_x) {                                         \
                .pfd = -1,                                                      \
                .ufd = -1,                                                      \
        }

struct NDhcp4Client {
        unsigned long n_refs;
        CList event_list;

        unsigned int state;             /* current client state */
        int efd;                        /* epoll fd */
        int tfd;                        /* timer fd */
        uint64_t u_t1;                  /* next T1 timeout, or 0 */
        uint64_t u_t2;                  /* next T2 timeout, or 0 */
        uint64_t u_lifetime;            /* next lifetime timeout, or 0 */

        uint32_t xid;                   /* transaction id, or 0 */
        uint64_t u_starttime;           /* transaction start time, or 0 */
        uint32_t secs;                  /* seconds since start of transaction, or 0 */

        NDhcp4CConnection connection;   /* client connection wrapper */
};

#define N_DHCP4_CLIENT_NULL(_x) {                                               \
                .n_refs = 1,                                                    \
                .event_list = C_LIST_INIT((_x).event_list),                     \
                .efd = -1,                                                      \
                .tfd = -1,                                                      \
                .connection = N_DHCP4_C_CONNECTION_NULL((_x).connection),       \
        }

struct NDhcp4ClientProbe {
        NDhcp4Client *client;
        CList event_list;
        void *userdata;
};

#define N_DHCP4_CLIENT_PROBE_NULL(_x) {                                         \
                .event_list = C_LIST_INIT((_x).event_list),                     \
        }

/* outgoing messages */

int n_dhcp4_outgoing_new(NDhcp4Outgoing **outgoingp, size_t max_size, uint8_t overload);
NDhcp4Outgoing *n_dhcp4_outgoing_free(NDhcp4Outgoing *outgoing);

NDhcp4Header *n_dhcp4_outgoing_get_header(NDhcp4Outgoing *outgoing);
size_t n_dhcp4_outgoing_get_raw(NDhcp4Outgoing *outgoing, const void **rawp);
int n_dhcp4_outgoing_append(NDhcp4Outgoing *outgoing, uint8_t option, const void *data, uint8_t n_data);

/* incoming messages */

int n_dhcp4_incoming_new(NDhcp4Incoming **incomingp, const void *raw, size_t n_raw);
NDhcp4Incoming *n_dhcp4_incoming_free(NDhcp4Incoming *incoming);

NDhcp4Header *n_dhcp4_incoming_get_header(NDhcp4Incoming *incoming);
size_t n_dhcp4_incoming_get_raw(NDhcp4Incoming *incoming, const void **rawp);
int n_dhcp4_incoming_query(NDhcp4Incoming *incoming, uint8_t option, uint8_t **datap, size_t *n_datap);

/* sockets */

int n_dhcp4_c_socket_packet_new(int *sockfdp, int ifindex);
int n_dhcp4_c_socket_udp_new(int *sockfdp,
                             int ifindex,
                             const struct in_addr *client_addr,
                             const struct in_addr *server_addr);
int n_dhcp4_s_socket_packet_new(int *sockfdp);
int n_dhcp4_s_socket_udp_new(int *sockfdp, int ifindex);

int n_dhcp4_c_socket_packet_send(int sockfd,
                                 int ifindex,
                                 const unsigned char *dest_haddr,
                                 unsigned char halen,
                                 NDhcp4Outgoing *message);
int n_dhcp4_c_socket_udp_send(int sockfd, NDhcp4Outgoing *message);
int n_dhcp4_c_socket_udp_broadcast(int sockfd, NDhcp4Outgoing *message);
int n_dhcp4_s_socket_packet_send(int sockfd,
                                 int ifindex,
                                 const struct in_addr *src_inaddr,
                                 const unsigned char *dest_haddr,
                                 unsigned char halen,
                                 const struct in_addr *dest_inaddr,
                                 NDhcp4Outgoing *message);
int n_dhcp4_s_socket_udp_send(int sockfd,
                              const struct in_addr *inaddr_src,
                              const struct in_addr *inaddr_dest,
                              NDhcp4Outgoing *message);
int n_dhcp4_s_socket_udp_broadcast(int sockfd,
                                   const struct in_addr *inaddr_src,
                                   NDhcp4Outgoing *message);

int n_dhcp4_c_socket_packet_recv(int sockfd,
                                 NDhcp4Incoming **messagep);
int n_dhcp4_c_socket_udp_recv(int sockfd,
                              NDhcp4Incoming **messagep);
int n_dhcp4_s_socket_udp_recv(int sockfd,
                              NDhcp4Incoming **messagep);

/* client events */

int n_dhcp4_c_event_node_new(NDhcp4CEventNode **nodep);
NDhcp4CEventNode *n_dhcp4_c_event_node_free(NDhcp4CEventNode *node);

/* client connections */

int n_dhcp4_c_connection_init(NDhcp4CConnection *connection,
                              int *efd,
                              int ifindex,
                              uint8_t htype,
                              uint8_t hlen,
                              const uint8_t *chaddr,
                              const uint8_t *bhaddr,
                              size_t idlen,
                              const uint8_t *id,
                              bool request_broadcast);
void n_dhcp4_c_connection_deinit(NDhcp4CConnection *connection);

int n_dhcp4_c_connection_listen(NDhcp4CConnection *connection);
int n_dhcp4_c_connection_connect(NDhcp4CConnection *connection, const struct in_addr *client, const struct in_addr *server);

int n_dhcp4_c_connection_dispatch(NDhcp4CConnection *connection, NDhcp4Incoming **messagep);

int n_dhcp4_c_connection_discover(NDhcp4CConnection *connection,
                                  uint32_t xid,
                                  uint32_t secs);
int n_dhcp4_c_connection_select(NDhcp4CConnection *connection,
                                const struct in_addr *client,
                                const struct in_addr *server,
                                uint32_t xid,
                                uint32_t secs);
int n_dhcp4_c_connection_reboot(NDhcp4CConnection *connection,
                                const struct in_addr *client,
                                uint32_t xid,
                                uint32_t secs);
int n_dhcp4_c_connection_renew(NDhcp4CConnection *connection,
                               uint32_t xid,
                               uint32_t secs);
int n_dhcp4_c_connection_rebind(NDhcp4CConnection *connection,
                                uint32_t xid,
                                uint32_t secs);
int n_dhcp4_c_connection_decline(NDhcp4CConnection *connection,
                                 const char *error,
                                 const struct in_addr *client,
                                 const struct in_addr *server);
int n_dhcp4_c_connection_inform(NDhcp4CConnection *connection,
                                uint32_t xid,
                                uint32_t secs);
int n_dhcp4_c_connection_release(NDhcp4CConnection *connection,
                                 const char *error);

/* clients */

int n_dhcp4_client_raise(NDhcp4Client *client, NDhcp4CEventNode **nodep, unsigned int event);

/* client probes */

int n_dhcp4_client_probe_new(NDhcp4ClientProbe **probep, NDhcp4Client *client);

/* inline helpers */

static inline void n_dhcp4_outgoing_freep(NDhcp4Outgoing **outgoing) {
        if (*outgoing)
                n_dhcp4_outgoing_free(*outgoing);
}

static inline void n_dhcp4_incoming_freep(NDhcp4Incoming **incoming) {
        if (*incoming)
                n_dhcp4_incoming_free(*incoming);
}

static inline void n_dhcp4_closep(int *fdp) {
        if (*fdp >= 0)
                close(*fdp);
}
