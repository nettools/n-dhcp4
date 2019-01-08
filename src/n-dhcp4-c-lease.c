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
 * n_dhcp4_client_lease_new() - XXX
 */
int n_dhcp4_client_lease_new(NDhcp4ClientLease **leasep, NDhcp4Incoming *message) {
        _cleanup_(n_dhcp4_client_lease_unrefp) NDhcp4ClientLease *lease = NULL;
        uint8_t *type;
        size_t n_type;
        int r;

        assert(leasep);

        lease = malloc(sizeof(*lease));
        if (!lease)
                return -ENOMEM;

        *lease = (NDhcp4ClientLease)N_DHCP4_CLIENT_LEASE_NULL(*lease);

        r = n_dhcp4_incoming_query(message, N_DHCP4_OPTION_MESSAGE_TYPE, &type, &n_type);
        if (r || n_type != 1)
                return N_DHCP4_E_MALFORMED;

        switch (*type) {
        case N_DHCP4_MESSAGE_OFFER:
                lease->state = N_DHCP4_CLIENT_LEASE_STATE_OFFERED;
                break;
        case N_DHCP4_MESSAGE_ACK:
                lease->state = N_DHCP4_CLIENT_LEASE_STATE_ACKED;
                break;
        default:
                return N_DHCP4_E_MALFORMED;
        }

        lease->message = message;

        *leasep = lease;
        lease = NULL;
        return 0;
}

static void n_dhcp4_client_lease_free(NDhcp4ClientLease *lease) {
        assert(!lease->probe);

        c_list_unlink(&lease->probe_link);

        n_dhcp4_incoming_free(lease->message);
        free(lease);
}

/**
 * n_dhcp4_client_lease_ref() - XXX
 */
_public_ NDhcp4ClientLease *n_dhcp4_client_lease_ref(NDhcp4ClientLease *lease) {
        if (lease)
                ++lease->n_refs;
        return lease;
}

/**
 * n_dhcp4_client_lease_unref() - XXX
 */
_public_ NDhcp4ClientLease *n_dhcp4_client_lease_unref(NDhcp4ClientLease *lease) {
        if (lease && !--lease->n_refs)
                n_dhcp4_client_lease_free(lease);
        return NULL;
}

/**
 * n_dhcp4_client_lease_query() - XXX
 */
_public_ int n_dhcp4_client_lease_query(NDhcp4ClientLease *lease, uint8_t option, uint8_t **datap, size_t *n_datap) {
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

        return n_dhcp4_incoming_query(lease->message, option, datap, n_datap);
}
