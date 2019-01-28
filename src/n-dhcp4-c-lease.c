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

static int n_dhcp4_client_lease_get_timeouts(NDhcp4ClientLease *lease, uint64_t *t1p, uint64_t *t2p, uint64_t *lifetimep) {
        uint64_t lifetime, t2, t1;
        uint32_t u32;
        int r;

        r = n_dhcp4_incoming_query_lifetime(lease->message, &u32);
        if (r == N_DHCP4_E_UNSET) {
                lifetime = 0;
        } else if (r) {
                return r;
        } else {
                lifetime = u32 * (1000000000ULL);
        }

        r = n_dhcp4_incoming_query_t2(lease->message, &u32);
        if (r == N_DHCP4_E_UNSET) {
                t2 = (lifetime * 7) / 8;
        } else if (r) {
                return r;
        } else {
                t2 = u32 * (1000000000ULL);
                if (t2 > lifetime)
                        t2 = (lifetime * 7) / 8;
        }

        r = n_dhcp4_incoming_query_t1(lease->message, &u32);
        if (r == N_DHCP4_E_UNSET) {
                t1 = (t2 * 4) / 7;
        } else if (r) {
                return r;
        } else {
                t1 = u32 * (1000000000ULL);
                if (t1 > t2)
                        t1 = (t2 * 4) / 7;
        }

        *lifetimep = lease->message->userdata.base_time + lifetime;
        *t2p = lease->message->userdata.base_time + t2;
        *t1p = lease->message->userdata.base_time + t1;
        return 0;
}

/**
 * n_dhcp4_client_lease_new() - XXX
 */
int n_dhcp4_client_lease_new(NDhcp4ClientLease **leasep, NDhcp4Incoming *_message) {
        _cleanup_(n_dhcp4_client_lease_unrefp) NDhcp4ClientLease *lease = NULL;
        _cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *message = _message;
        int r;

        assert(leasep);

        lease = malloc(sizeof(*lease));
        if (!lease)
                return -ENOMEM;

        *lease = (NDhcp4ClientLease)N_DHCP4_CLIENT_LEASE_NULL(*lease);
        lease->message = message;
        message = NULL;

        r = n_dhcp4_client_lease_get_timeouts(lease, &lease->t1, &lease->t2, &lease->lifetime);
        if (r)
                return r;

        *leasep = lease;
        lease = NULL;
        return 0;
}

static void n_dhcp4_client_lease_free(NDhcp4ClientLease *lease) {
        n_dhcp4_client_lease_unlink(lease);
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
 * n_dhcp4_client_lease_link() - XXX
 */
void n_dhcp4_client_lease_link(NDhcp4ClientLease *lease, NDhcp4ClientProbe *probe) {
        lease->probe = probe;
        c_list_link_tail(&probe->lease_list, &lease->probe_link);
}

/**
 * n_dhcp4_client_lease_unlink() - XXX
 */
void n_dhcp4_client_lease_unlink(NDhcp4ClientLease *lease) {
        lease->probe = NULL;
        c_list_unlink(&lease->probe_link);
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

_public_ int n_dhcp4_client_lease_select(NDhcp4ClientLease *lease) {
        NDhcp4ClientLease *l, *t_l;
        NDhcp4ClientProbe *probe;
        int r;

        /* XXX error handling, this must be an OFFER */

        if (!lease->probe)
                return -ENOTRECOVERABLE;
        if (lease->probe->current_lease)
                return -ENOTRECOVERABLE;

        r = n_dhcp4_client_probe_transition_select(lease->probe, lease->message, n_dhcp4_gettime(CLOCK_BOOTTIME));
        if (r)
                return r;

        /*
         * Only one of the offered leases can be select, so flush the list. All
         * offered lease, including this one are now dead.
         */
        probe = lease->probe;
        c_list_for_each_entry_safe(l, t_l, &probe->lease_list, probe_link)
                n_dhcp4_client_lease_unlink(l);

        return 0;
}

_public_ int n_dhcp4_client_lease_accept(NDhcp4ClientLease *lease) {
        int r;

        /* XXX error handling, this must be an ACK */

        if (!lease->probe)
                return -ENOTRECOVERABLE;
        if (lease->probe->current_lease != lease)
                return -ENOTRECOVERABLE;

        r = n_dhcp4_client_probe_transition_accept(lease->probe, lease->message);
        if (r)
                return r;

        n_dhcp4_client_lease_unlink(lease);

        return 0;
}

_public_ int n_dhcp4_client_lease_decline(NDhcp4ClientLease *lease, const char *error) {
        int r;

        /* XXX: error handling, this must be an ACK */

        if (!lease->probe)
                return -ENOTRECOVERABLE;
        if (lease->probe->current_lease != lease)
                return -ENOTRECOVERABLE;

        r = n_dhcp4_client_probe_transition_decline(lease->probe, lease->message, error, n_dhcp4_gettime(CLOCK_BOOTTIME));
        if (r)
                return r;

        lease->probe->current_lease = n_dhcp4_client_lease_unref(lease->probe->current_lease);
        n_dhcp4_client_lease_unlink(lease);

        return 0;
}
