#pragma once

/*
 * XXX
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <stdlib.h>

/* error codes */

enum {
        _N_DHCP4_E_SUCCESS,

        N_DHCP4_E_AGAIN,

        N_DHCP4_E_INVALID_AGRUMENT,
        N_DHCP4_E_STARTED,
        N_DHCP4_E_STOPPED,
};

/* lease structs */

typedef struct NDhcp4LeaseRequest {
        struct {
                uint8_t type;
                size_t n_data;
                uint8_t *data;
        } client_identifier;
        size_t n_options;
        struct {
                uint8_t option;
                union {
                        struct in_addr address;
                        uint32_t lifetime;
                        struct {
                                size_t n_data;
                                uint8_t *data;
                        } options, vendor_identifier;
                };
        } options[];
} NDhcp4LeaseRequest;

typedef struct NDhcp4Lease {
        struct in_addr address;
        size_t n_options;
        struct {
                uint8_t option;
                struct {
                        uint8_t *data;
                        size_t n_data;
                } raw;
                union {
                        struct {
                                struct in_addr address;
                        } subnet_mask,
                          swap_server,
                          broadcast_address,
                          router_solicitation_address;
                        struct {
                                struct in_addr *addresses;
                                size_t n_addresses;
                        } router,
                          time_server,
                          name_server,
                          domain_name_server,
                          log_server,
                          cookie_server,
                          lpr_server,
                          impress_server,
                          resource_location_server,
                          nis_servers,
                          ntp_servers,
                          netbios_name_server,
                          netbios_datagram_distribution_server,
                          x_window_system_font_server,
                          x_window_system_display_manager,
                          nis_plus_server,
                          mobile_ip_home_agent,
                          smtp_server,
                          pop3_server,
                          nntp_server,
                          www_server,
                          default_finger_server,
                          default_irc_server,
                          street_talk_server,
                          stda_server;
                };
                struct {
                        char *string;
                        size_t n_string;
                } host_name,
                  merit_dump_file,
                  domain_name,
                  root_path,
                  extensions_path,
                  nis_domain_name,
                  net_bios_scope,
                  nis_plus_domain_name,
                  tft_server_name,
                  bootfile_name;
        } options[];
} NDhcp4Lease;

/* client structs */

typedef struct NDhcp4Client NDhcp4Client;

typedef struct NDhcp4ClientConfig {
        unsigned int ifindex;
        struct ether_addr mac;
} NDhcp4ClientConfig;

typedef struct NDhcp4ClientEvent {
        unsigned int event;
        union {
                struct {
                        uint64_t expiration;
                        NDhcp4Lease lease;
                } offer;
        };
} NDhcp4ClientEvent;

enum {
        N_DHCP4_CLIENT_EVENT_OFFER,
        N_DHCP4_CLIENT_EVENT_DOWN,
        _N_DHCP4_CLIENT_EVENT_N,
        _N_DHCP4_CLIENT_EVENT_INVALID,
};

/* server structs */

typedef struct NDhcp4Server NDhcp4Server;

typedef struct NDhcp4ServerConfig {
        unsigned int ifindex;
        struct in_addr address;
        uint32_t min_lease_sec;
        uint32_t max_lease_sec;
        uint32_t default_lease_sec;
} NDhcp4ServerConfig;

typedef struct NDhcp4ServerEvent {
        unsigned int event;
        union {
                struct {
                        uint64_t client_id;
                        NDhcp4LeaseRequest request;
                } request;
                struct {
                        uint64_t client_id;
                        uint64_t expiration;
                } commit;
        };
} NDhcp4ServerEvent;

enum {
        N_DHCP4_SERVER_EVENT_REQUEST,
        N_DHCP4_SERVER_EVENT_COMMIT,
        N_DHCP4_SERVER_EVENT_DOWN,
        _N_DHCP4_SERVER_EVENT_N,
        _N_DHCP4_SERVER_EVENT_INVALID,
};

/* client */

int n_dhcp4_client_new(NDhcp4Client **clientp);
NDhcp4Client *n_dhcp4_client_free(NDhcp4Client *client);

int n_dhcp4_client_get_fd(NDhcp4Client *client);
int n_dhcp4_client_dispatch(NDhcp4Client *client);
int n_dhcp4_client_pop_event(NDhcp4Client *client, NDhcp4ClientEvent *eventp);

int n_dhcp4_client_accept(NDhcp4Client *client);
int n_dhcp4_client_decline(NDhcp4Client *client);

int n_dhcp4_client_start(NDhcp4Client *client, NDhcp4ClientConfig *config);
void n_dhcp4_client_stop(NDhcp4Client *client);

/* server */

int n_dhcp4_server_new(NDhcp4Server **serverp);
NDhcp4Server *n_dhcp4_server_free(NDhcp4Server *server);

int n_dhcp4_server_get_fd(NDhcp4Server *server);
int n_dhcp4_server_dispatch(NDhcp4Server *server);
int n_dhcp4_server_pop_event(NDhcp4Server *server, NDhcp4ServerEvent *eventp);

int n_dhcp4_server_set_lease(NDhcp4Server *server, uint64_t client_id, NDhcp4Lease *lease);

int n_dhcp4_server_start(NDhcp4Server *server, NDhcp4ServerConfig *config);
void n_dhcp4_server_stop(NDhcp4Server *server);

/* inline helpers */

static inline void n_dhcp4_client_freep(NDhcp4Client **client) {
        if (*client)
                n_dhcp4_client_free(*client);
}

static inline void n_dhcp4_server_freep(NDhcp4Server **server) {
        if (*server)
                n_dhcp4_server_free(*server);
}

#ifdef __cplusplus
}
#endif
