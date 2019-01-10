/*
 * XXX
 */

#include <assert.h>
#include <c-list.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "n-dhcp4.h"
#include "n-dhcp4-private.h"

/**
 * n_dhcp4_server_lease_new() - XXX
 */
int n_dhcp4_server_lease_new(NDhcp4ServerLease **leasep, NDhcp4Incoming *message) {
        _cleanup_(n_dhcp4_server_lease_unrefp) NDhcp4ServerLease *lease = NULL;

        assert(leasep);

        lease = malloc(sizeof(*lease));
        if (!lease)
                return -ENOMEM;

        *lease = (NDhcp4ServerLease)N_DHCP4_SERVER_LEASE_NULL(*lease);

        lease->request = message;

        *leasep = lease;
        lease = NULL;
        return 0;
}

static void n_dhcp4_server_lease_free(NDhcp4ServerLease *lease) {
        assert(!lease->server);

        c_list_unlink(&lease->server_link);

        n_dhcp4_incoming_free(lease->request);
        free(lease);
}

/**
 * n_dhcp4_server_lease_ref() - XXX
 */
_public_ NDhcp4ServerLease *n_dhcp4_server_lease_ref(NDhcp4ServerLease *lease) {
        if (lease)
                ++lease->n_refs;
        return lease;
}

/**
 * n_dhcp4_server_lease_unref() - XXX
 */
_public_ NDhcp4ServerLease *n_dhcp4_server_lease_unref(NDhcp4ServerLease *lease) {
        if (lease && !--lease->n_refs)
                n_dhcp4_server_lease_free(lease);
        return NULL;
}

/**
 * n_dhcp4_server_lease_query() - XXX
 */
_public_ int n_dhcp4_server_lease_query(NDhcp4ServerLease *lease, uint8_t option, uint8_t **datap, size_t *n_datap) {
        switch (option) {
        case N_DHCP4_OPTION_PAD:
        case N_DHCP4_OPTION_REQUESTED_IP_ADDRESS:
        case N_DHCP4_OPTION_IP_ADDRESS_LEASE_TIME:
        case N_DHCP4_OPTION_OVERLOAD:
        case N_DHCP4_OPTION_MESSAGE_TYPE:
        case N_DHCP4_OPTION_SERVER_IDENTIFIER:
        case N_DHCP4_OPTION_PARAMETER_REQUEST_LIST:
        case N_DHCP4_OPTION_ERROR_MESSAGE:
        case N_DHCP4_OPTION_MAXIMUM_MESSAGE_SIZE:
        case N_DHCP4_OPTION_RENEWAL_T1_TIME:
        case N_DHCP4_OPTION_REBINDING_T2_TIME:
        case N_DHCP4_OPTION_END:
                return N_DHCP4_E_INTERNAL;
        }

        return n_dhcp4_incoming_query(lease->request, option, datap, n_datap);
}
