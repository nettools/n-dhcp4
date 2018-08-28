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

/*
 * Client
 */

int n_dhcp4_client_new(NDhcp4Client **clientp);
NDhcp4Client *n_dhcp4_client_free(NDhcp4Client *client);

int n_dhcp4_client_get_fd(NDhcp4Client *client);
int n_dhcp4_client_dispatch(NDhcp4Client *client);

/*
 * Convenience Wrappers
 */

static inline void n_dhcp4_client_freep(NDhcp4Client **clientp) {
        if (*clientp)
                n_dhcp4_client_free(*clientp);
}

#ifdef __cplusplus
}
#endif
