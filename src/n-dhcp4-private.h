#pragma once

#include <arpa/inet.h>
#include <inttypes.h>
#include <stdlib.h>
#include "n-dhcp4.h"

typedef struct NDhcp4Header NDhcp4Header;
typedef struct NDhcp4Incoming NDhcp4Incoming;
typedef struct NDhcp4Message NDhcp4Message;
typedef struct NDhcp4Outgoing NDhcp4Outgoing;

/*
 * Macros
 */

#define _cleanup_(_x) __attribute__((__cleanup__(_x)))
#define _packed_ __attribute__((__packed__))
#define _public_ __attribute__((__visibility__("default")))

#define MIN(_x, _y) ((_x) < (_y) ? (_x) : (_y))

/*
 * Network Layers
 */

#define N_DHCP4_NETWORK_IP_DEFAULT_MAX_SIZE (576) /* See RFC791 */
#define N_DHCP4_NETWORK_SERVER_PORT (67)
#define N_DHCP4_NETWORK_CLIENT_PORT (68)

int n_dhcp4_network_client_packet_socket_new(int *sockfdp, int ifindex, uint32_t xid);

/*
 * DHCP4 Messages
 */

#define N_DHCP4_MESSAGE_MAGIC ((uint32_t)(0x63825363))

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

#define N_DHCP4_MESSAGE_NULL {                          \
                .magic = htonl(N_DHCP4_MESSAGE_MAGIC),  \
        }

int n_dhcp4_outgoing_new(NDhcp4Outgoing **outgoingp, size_t max_size, uint8_t overload);
NDhcp4Outgoing *n_dhcp4_outgoing_free(NDhcp4Outgoing *outgoing);
NDhcp4Header *n_dhcp4_outgoing_get_header(NDhcp4Outgoing *outgoing);
size_t n_dhcp4_outgoing_get_raw(NDhcp4Outgoing *outgoing, const void **rawp);
int n_dhcp4_outgoing_append(NDhcp4Outgoing *outgoing, uint8_t option, const void *data, uint8_t n_data);

int n_dhcp4_incoming_new(NDhcp4Incoming **incomingp, const void *raw, size_t n_raw);
NDhcp4Incoming *n_dhcp4_incoming_free(NDhcp4Incoming *incoming);
NDhcp4Header *n_dhcp4_incoming_get_header(NDhcp4Incoming *incoming);
size_t n_dhcp4_incoming_get_raw(NDhcp4Incoming *incoming, const void **rawp);
int n_dhcp4_incoming_query(NDhcp4Incoming *incoming, uint8_t option, const void **datap, size_t *n_datap);

/*
 * Convenience Wrappers
 */

static inline void n_dhcp4_outgoing_freep(NDhcp4Outgoing **outgoing) {
        if (*outgoing)
                n_dhcp4_outgoing_free(*outgoing);
}

static inline void n_dhcp4_incoming_freep(NDhcp4Incoming **incoming) {
        if (*incoming)
                n_dhcp4_incoming_free(*incoming);
}
