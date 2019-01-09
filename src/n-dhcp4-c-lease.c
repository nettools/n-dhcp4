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

static int n_dhcp4_incoming_query_u32(NDhcp4Incoming *message, uint8_t option, uint32_t *u32p) {
        uint8_t *data;
        size_t n_data;
        uint32_t be32;
        int r;

        r = n_dhcp4_incoming_query(message, option, &data, &n_data);
        if (r)
                return r;
        else if (n_data != be32)
                return N_DHCP4_E_MALFORMED;

        memcpy(&be32, data, sizeof(be32));

        if (be32 == (uint32_t)-1)
                *u32p = 0;
        else
                *u32p = ntohl(be32);
        return 0;
}

static int n_dhcp4_client_lease_get_timeouts(NDhcp4ClientLease *lease, uint64_t *t1p, uint64_t *t2p, uint64_t *lifetimep) {
        uint64_t lifetime, t2, t1;
        uint32_t u32;
        int r;

        r = n_dhcp4_incoming_query_u32(lease->message, N_DHCP4_OPTION_IP_ADDRESS_LEASE_TIME, &u32);
        if (r == N_DHCP4_E_UNSET) {
                lifetime = 0;
        } else if (r) {
                return r;
        } else {
                lifetime = u32 * (1000000000ULL);
        }

        r = n_dhcp4_incoming_query_u32(lease->message, N_DHCP4_OPTION_REBINDING_T2_TIME, &u32);
        if (r == N_DHCP4_E_UNSET) {
                t2 = (lifetime * 7) / 8;
        } else if (r) {
                return r;
        } else {
                t2 = u32 * (1000000000ULL);
                if (t2 > lifetime)
                        t2 = (lifetime * 7) / 8;
        }

        r = n_dhcp4_incoming_query_u32(lease->message, N_DHCP4_OPTION_RENEWAL_T1_TIME, &u32);
        if (r == N_DHCP4_E_UNSET) {
                t1 = (t2 * 4) / 7;
        } else if (r) {
                return r;
        } else {
                t1 = u32 * (1000000000ULL);
                if (t1 > t2)
                        t1 = (t2 * 4) / 7;
        }

        *lifetimep = lifetime;
        *t2p = t2;
        *t1p = t1;
        return 0;
}

/**
 * n_dhcp4_client_lease_new() - XXX
 */
int n_dhcp4_client_lease_new(NDhcp4ClientLease **leasep, NDhcp4Incoming *message, uint64_t base_time) {
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

        r = n_dhcp4_client_lease_get_timeouts(lease, &lease->t1, &lease->t2, &lease->lifetime);
        if (r)
                return r;

        lease->message = message;
        lease->t1 += base_time;
        lease->t2 += base_time;
        lease->lifetime += base_time;

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
