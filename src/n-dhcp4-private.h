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
typedef struct NDhcp4SConnection NDhcp4SConnection;

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

        N_DHCP4_E_UNEXPECTED,

        N_DHCP4_E_NO_SPACE,
        N_DHCP4_E_MALFORMED,
        N_DHCP4_E_UNSET,

        N_DHCP4_E_DROPPED,
        N_DHCP4_E_DOWN,
        N_DHCP4_E_AGAIN,
};

enum {
        N_DHCP4_C_CONNECTION_STATE_INIT,
        N_DHCP4_C_CONNECTION_STATE_PACKET,
        N_DHCP4_C_CONNECTION_STATE_DRAINING,
        N_DHCP4_C_CONNECTION_STATE_UDP,
};

enum {
        N_DHCP4_CLIENT_EPOLL_TIMER,
        N_DHCP4_CLIENT_EPOLL_IO,
};

enum {
        N_DHCP4_CLIENT_PROBE_STATE_INIT,
        N_DHCP4_CLIENT_PROBE_STATE_INIT_REBOOT,
        N_DHCP4_CLIENT_PROBE_STATE_SELECTING,
        N_DHCP4_CLIENT_PROBE_STATE_REBOOTING,
        N_DHCP4_CLIENT_PROBE_STATE_REQUESTING,
        N_DHCP4_CLIENT_PROBE_STATE_BOUND,
        N_DHCP4_CLIENT_PROBE_STATE_RENEWING,
        N_DHCP4_CLIENT_PROBE_STATE_REBINDING,
};

enum {
        N_DHCP4_CLIENT_LEASE_STATE_INIT,
        N_DHCP4_CLIENT_LEASE_STATE_OFFERED,
        N_DHCP4_CLIENT_LEASE_STATE_SELECTED,
        N_DHCP4_CLIENT_LEASE_STATE_DECLINED,
        N_DHCP4_CLIENT_LEASE_STATE_ACKED,
};

enum {
        N_DHCP4_SERVER_EPOLL_IO,
};

struct NDhcp4Outgoing {
        NDhcp4Message *message;
        size_t n_message;
        size_t i_message;
        size_t max_size;

        uint8_t overload : 2;

        struct {
                uint8_t type;
                uint64_t start_time;
                uint64_t send_time;
                size_t n_send;
        } userdata;
};

#define N_DHCP4_OUTGOING_NULL(_x) {                                             \
        }

struct NDhcp4Incoming {
        struct {
                uint8_t *value;
                size_t size;
        } options[_N_DHCP4_OPTION_N];

        struct {
                uint64_t start_time;
                uint64_t send_time;
        } userdata;

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
        int *fd_epollp;                 /* pointer to epoll fd */
        int ifindex;                    /* interface index */
        int fd_packet;                  /* packet socket */
        int fd_udp;                     /* udp socket */
        uint8_t buf[UINT16_MAX];        /* scratch receive buffer */

        bool request_broadcast : 1;     /* request broadcast from server */
        bool send_chaddr : 1;           /* send chaddr to server */

        uint8_t htype;                  /* APR hardware type */
        uint8_t hlen;                   /* hardware address length */
        uint8_t chaddr[MAX_ADDR_LEN];   /* client hardware address */
        uint8_t bhaddr[MAX_ADDR_LEN];   /* broadcast hardware address */

        struct drand48_data entropy;    /* entropy pool */
        NDhcp4Outgoing *request;        /* current request */

        uint32_t client_ip;             /* client IP address, or 0 */
        uint32_t server_ip;             /* server IP address, or 0 */
        uint16_t mtu;                   /* client mtu, or 0 */

        size_t idlen;                   /* client identifier length */
        uint8_t *id;                    /* client identifier */
};

#define N_DHCP4_C_CONNECTION_NULL(_x) {                                         \
                .fd_packet = -1,                                                \
                .fd_udp = -1,                                                   \
        }

struct NDhcp4Client {
        unsigned long n_refs;
        CList event_list;
        int fd_epoll;
        int fd_timer;

        uint16_t mtu;
        NDhcp4ClientProbe *current_probe;

        bool preempted : 1;
};

#define N_DHCP4_CLIENT_NULL(_x) {                                               \
                .n_refs = 1,                                                    \
                .event_list = C_LIST_INIT((_x).event_list),                     \
                .fd_epoll = -1,                                                 \
                .fd_timer = -1,                                                 \
        }

struct NDhcp4ClientProbe {
        NDhcp4Client *client;
        CList event_list;
        CList lease_list;
        void *userdata;

        unsigned int state;                     /* current probe state */
        NDhcp4ClientLease *current_lease;       /* current lease */

        NDhcp4CConnection connection;           /* client connection wrapper */
};

#define N_DHCP4_CLIENT_PROBE_NULL(_x) {                                         \
                .event_list = C_LIST_INIT((_x).event_list),                     \
                .lease_list = C_LIST_INIT((_x).lease_list),                     \
                .connection = N_DHCP4_C_CONNECTION_NULL((_x).connection),       \
        }

struct NDhcp4ClientLease {
        unsigned long n_refs;

        NDhcp4ClientProbe *probe;
        CList probe_link;

        NDhcp4Incoming *message;

        unsigned int state;

        uint64_t t1;
        uint64_t t2;
        uint64_t lifetime;
};

#define N_DHCP4_CLIENT_LEASE_NULL(_x) {                                         \
                .n_refs = 1,                                                    \
                .probe_link = C_LIST_INIT((_x).probe_link),                     \
        }

struct NDhcp4SConnection {
        int *fd_epollp;                 /* epoll fd */
        int ifindex;                    /* interface index */
        int fd_packet;                  /* packet socket */
        int fd_udp;                     /* udp socket */
        uint8_t buf[UINT16_MAX];        /* scratch recevie buffer */

        /* XXX: support a set of server addresses */
        uint32_t server_address;        /* server IP address, or 0 */
};

#define N_DHCP4_S_CONNECTION_NULL(_x) {                                         \
                .fd_packet = -1,                                                \
                .fd_udp = -1,                                                   \
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
                                 uint8_t *buf,
                                 size_t n_buf,
                                 NDhcp4Incoming **messagep);
int n_dhcp4_c_socket_udp_recv(int sockfd,
                              uint8_t *buf,
                              size_t n_buf,
                              NDhcp4Incoming **messagep);
int n_dhcp4_s_socket_udp_recv(int sockfd,
                              uint8_t *buf,
                              size_t n_buf,
                              NDhcp4Incoming **messagep);

/* client events */

int n_dhcp4_c_event_node_new(NDhcp4CEventNode **nodep);
NDhcp4CEventNode *n_dhcp4_c_event_node_free(NDhcp4CEventNode *node);

/* client connections */

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
                              bool request_broadcast);
void n_dhcp4_c_connection_deinit(NDhcp4CConnection *connection);

int n_dhcp4_c_connection_listen(NDhcp4CConnection *connection);
int n_dhcp4_c_connection_connect(NDhcp4CConnection *connection, const struct in_addr *client, const struct in_addr *server);

void n_dhcp4_c_connection_get_timeout(NDhcp4CConnection *connection, uint64_t *timeoutp);
int n_dhcp4_c_connection_dispatch_timer(NDhcp4CConnection *connection, uint64_t timestamp);
int n_dhcp4_c_connection_dispatch_io(NDhcp4CConnection *connection, NDhcp4Incoming **messagep);

int n_dhcp4_c_connection_discover_new(NDhcp4CConnection *connection,
                                      NDhcp4Outgoing **request);
int n_dhcp4_c_connection_select_new(NDhcp4CConnection *connection,
                                    NDhcp4Outgoing **request,
                                    NDhcp4Incoming *offer);
int n_dhcp4_c_connection_reboot_new(NDhcp4CConnection *connection,
                                    NDhcp4Outgoing **request,
                                    const struct in_addr *client);
int n_dhcp4_c_connection_renew_new(NDhcp4CConnection *connection,
                                   NDhcp4Outgoing **request);
int n_dhcp4_c_connection_rebind_new(NDhcp4CConnection *connection,
                                    NDhcp4Outgoing **request);
int n_dhcp4_c_connection_decline_new(NDhcp4CConnection *connection,
                                     NDhcp4Outgoing **request,
                                     NDhcp4Incoming *ack,
                                     const char *error);
int n_dhcp4_c_connection_inform_new(NDhcp4CConnection *connection,
                                    NDhcp4Outgoing **request);
int n_dhcp4_c_connection_release_new(NDhcp4CConnection *connection,
                                     NDhcp4Outgoing **request,
                                     const char *error);

int n_dhcp4_c_connection_start_request(NDhcp4CConnection *connection,
                                       NDhcp4Outgoing *request,
                                       uint64_t timestamp);

/* client leases */
int n_dhcp4_client_lease_new(NDhcp4ClientLease **leasep, NDhcp4Incoming *message, uint64_t base_time);

/* clients */

int n_dhcp4_client_raise(NDhcp4Client *client, NDhcp4CEventNode **nodep, unsigned int event);

/* client probes */

int n_dhcp4_client_probe_new(NDhcp4ClientProbe **probep, NDhcp4Client *client);

int n_dhcp4_client_probe_raise(NDhcp4ClientProbe *probe, NDhcp4CEventNode **nodep, unsigned int event);
int n_dhcp4_client_probe_install(NDhcp4ClientProbe *probe);
void n_dhcp4_client_probe_uninstall(NDhcp4ClientProbe *probe);
void n_dhcp4_client_probe_get_timeout(NDhcp4ClientProbe *probe, uint64_t *timeoutp);
int n_dhcp4_client_probe_dispatch_timer(NDhcp4ClientProbe *probe);
int n_dhcp4_client_probe_dispatch_io(NDhcp4ClientProbe *probe, uint32_t events);
int n_dhcp4_client_probe_update_mtu(NDhcp4ClientProbe *probe, uint16_t mtu);

/* server connections */

void n_dhcp4_s_connection_init(NDhcp4SConnection *connection, int *fd_epollp, int ifindex);
void n_dhcp4_s_connection_deinit(NDhcp4SConnection *connection);

int n_dhcp4_s_connection_add_server_address(NDhcp4SConnection *connection,
                                            const struct in_addr *server_address);
int n_dhcp4_s_connection_remove_server_address(NDhcp4SConnection *connection,
                                               const struct in_addr *server_address);

int n_dhcp4_s_connection_listen(NDhcp4SConnection *connection);

int n_dhcp4_s_connection_dispatch_io(NDhcp4SConnection *connection, NDhcp4Incoming **messagep);

int n_dhcp4_s_connection_offer_new(NDhcp4SConnection *connection,
                                   NDhcp4Outgoing **replyp,
                                   NDhcp4Incoming *request,
                                   const struct in_addr *server_address,
                                   const struct in_addr *client_address,
                                   uint32_t lifetime);
int n_dhcp4_s_connection_ack_new(NDhcp4SConnection *connection,
                                   NDhcp4Outgoing **replyp,
                                   NDhcp4Incoming *request,
                                   const struct in_addr *server_address,
                                   const struct in_addr *client_address,
                                   uint32_t lifetime);
int n_dhcp4_s_connection_nak_new(NDhcp4SConnection *connection,
                                 NDhcp4Outgoing **replyp,
                                 NDhcp4Incoming *request,
                                 const struct in_addr *server_address);

int n_dhcp4_s_connection_send_reply(NDhcp4SConnection *connection,
                                    const struct in_addr *server_addr,
                                    NDhcp4Outgoing *reply);

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
