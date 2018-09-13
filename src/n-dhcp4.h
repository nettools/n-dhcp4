#pragma once

/*
 * Dynamic Host Configuration Protocol for IPv4
 *
 * This is the public header of the n-dhcp4 library, implementing IPv4 Dynamic
 * Host Configuration Protocol as described in RFC-2132. This header defines
 * the public API and all entry points of n-dhcp4.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>

typedef struct NDhcp4Client NDhcp4Client;
typedef struct NDhcp4ClientConfig NDhcp4ClientConfig;
typedef struct NDhcp4ClientEvent NDhcp4ClientEvent;
typedef struct NDhcp4ClientLease NDhcp4ClientLease;
typedef struct NDhcp4ClientRequest NDhcp4ClientRequest;

enum {
        _N_DHCP4_E_SUCCESS,

        N_DHCP4_E_PREEMPTED,

        _N_DHCP4_E_N,
};

enum {
        N_DHCP4_CLIENT_EVENT_DOWN,
        N_DHCP4_CLIENT_EVENT_OFFER,
        N_DHCP4_CLIENT_EVENT_READY,
        N_DHCP4_CLIENT_EVENT_EXPIRED,
        N_DHCP4_CLIENT_EVENT_REVOKED,

        _N_DHCP4_CLIENT_EVENT_N,
};

struct NDhcp4ClientEvent {
        unsigned int event;
        union {
                struct {
                } down;
                struct {
                        NDhcp4ClientLease *lease;
                } offer, ready, expired, revoked;
        };
};

/* configs */

int n_dhcp4_client_config_new(NDhcp4ClientConfig **configp);
NDhcp4ClientConfig *n_dhcp4_client_config_free(NDhcp4ClientConfig *config);

void n_dhcp4_client_config_set_ifindex(NDhcp4ClientConfig *config, int ifindex);

/* requests */

int n_dhcp4_client_request_new(NDhcp4ClientRequest *request);
NDhcp4ClientRequest *n_dhcp4_client_request_free(NDhcp4ClientRequest *request);

/* clients */

int n_dhcp4_client_new(NDhcp4Client **clientp);
NDhcp4Client *n_dhcp4_client_free(NDhcp4Client *client);

void n_dhcp4_client_get_fd(NDhcp4Client *client, int *fdp);
int n_dhcp4_client_dispatch(NDhcp4Client *client);
int n_dhcp4_client_pop_event(NDhcp4Client *client, NDhcp4ClientEvent **eventp);

int n_dhcp4_client_lease(NDhcp4Client *client,
                         NDhcp4ClientLease **leasep,
                         NDhcp4ClientRequest *request);

/* client lease */

NDhcp4ClientLease *n_dhcp4_client_lease_free(NDhcp4ClientLease *lease);

int n_dhcp4_client_lease_reject(NDhcp4ClientLease *lease);
int n_dhcp4_client_lease_accept(NDhcp4ClientLease *lease);

/* inline helpers */

static inline void n_dhcp4_client_config_freep(NDhcp4ClientConfig **config) {
        if (*config)
                n_dhcp4_client_config_free(*config);
}

static inline void n_dhcp4_client_config_freev(NDhcp4ClientConfig *config) {
        n_dhcp4_client_config_free(config);
}

static inline void n_dhcp4_client_request_freep(NDhcp4ClientRequest **request) {
        if (*request)
                n_dhcp4_client_request_free(*request);
}

static inline void n_dhcp4_client_request_freev(NDhcp4ClientRequest *request) {
        n_dhcp4_client_request_free(request);
}

static inline void n_dhcp4_client_freep(NDhcp4Client **client) {
        if (*client)
                n_dhcp4_client_free(*client);
}

static inline void n_dhcp4_client_freev(NDhcp4Client *client) {
        n_dhcp4_client_free(client);
}

static inline void n_dhcp4_client_lease_freep(NDhcp4ClientLease **lease) {
        if (*lease)
                n_dhcp4_client_lease_free(*lease);
}

static inline void n_dhcp4_client_lease_freev(NDhcp4ClientLease *lease) {
        n_dhcp4_client_lease_free(lease);
}

#ifdef __cplusplus
}
#endif
