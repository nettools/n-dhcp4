/*
 * DHCPv4 Client Probes
 *
 * The probe object is used to represent the lifetime of a DHCP client session.
 * A running probe discovers DHCP servers, requests a lease, and maintains that
 * lease.
 */

#include <assert.h>
#include <c-list.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "n-dhcp4.h"
#include "n-dhcp4-private.h"

/**
 * n_dhcp4_client_probe_config_new() - create new probe configuration
 * @configp:                    output argument to store new configuration
 *
 * This creates a new probe configuration object. The object is a collection of
 * parameters for probes. No data verification is done by the configuration
 * object. Instead, when passing the configuration to the constructor of a
 * probe, this constructor will perform parameter validation.
 *
 * A probe configuration is an unlinked object only used to pass information to
 * a probe constructor. The caller fully owns the returned configuration object
 * and is responsible to free it when no longer needed.
 *
 * Return: 0 on success, negative error code on failure.
 */
_public_ int n_dhcp4_client_probe_config_new(NDhcp4ClientProbeConfig **configp) {
        _cleanup_(n_dhcp4_client_probe_config_freep) NDhcp4ClientProbeConfig *config = NULL;

        config = calloc(1, sizeof(*config));
        if (!config)
                return -ENOMEM;

        *config = (NDhcp4ClientProbeConfig)N_DHCP4_CLIENT_PROBE_CONFIG_NULL(*config);

        *configp = config;
        config = NULL;
        return 0;
}

/**
 * n_dhcp4_client_probe_config_free() - destroy probe configuration
 * @config:                     configuration to operate on, or NULL
 *
 * This destroys a probe configuration object and deallocates all its
 * resources.
 *
 * If @config is NULL, this is a no-op.
 *
 * Return: NULL is returned.
 */
_public_ NDhcp4ClientProbeConfig *n_dhcp4_client_probe_config_free(NDhcp4ClientProbeConfig *config) {
        if (!config)
                return NULL;

        free(config);

        return NULL;
}

/**
 * n_dhcp4_client_probe_config_dup() - duplicate probe configuration
 * @config:                     configuration to operate on
 * @dupp:                       output argument for duplicate
 *
 * This duplicates the probe configuration given as @config and returns it in
 * @dupp to the caller.
 *
 * Return: 0 on success, negative error code on failure.
 */
int n_dhcp4_client_probe_config_dup(NDhcp4ClientProbeConfig *config,
                                    NDhcp4ClientProbeConfig **dupp) {
        _cleanup_(n_dhcp4_client_probe_config_freep) NDhcp4ClientProbeConfig *dup = NULL;
        int r;

        r = n_dhcp4_client_probe_config_new(&dup);
        if (r)
                return r;

        dup->inform_only = config->inform_only;
        dup->init_reboot = config->init_reboot;
        dup->requested_ip = config->requested_ip;

        *dupp = dup;
        dup = NULL;
        return 0;
}

/**
 * n_dhcp4_client_probe_config_set_inform_only() - set inform-only property
 * @config:                     configuration to operate on
 * @inform_only:                value to set
 *
 * This sets the inform-only property of the given configuration object. This
 * property controls whether the client probe should request a full lease, or
 * whether it should just ask for auxiliary information without requesting an
 * address.
 *
 * The default is to request a full lease and address. If inform-only is set to
 * true, only auxiliary information will be requested.
 */
_public_ void n_dhcp4_client_probe_config_set_inform_only(NDhcp4ClientProbeConfig *config, bool inform_only) {
        config->inform_only = inform_only;
}

/**
 * n_dhcp4_client_probe_config_set_init_reboot() - set init-reboot property
 * @config:                     configuration to operate on
 * @init_reboot:                value to set
 *
 * This sets the init-reboot property of the given configuration object.
 *
 * The default is false. If set to true, a probe will make use of the
 * INIT-REBOOT path, as described by the DHCP specification. In most cases, you
 * do not want this.
 *
 * Background: The INIT-REBOOT path allows a DHCP client to skip
 *             server-discovery when rebooting/resuming their machine. The DHCP
 *             client simply re-requests the lease it had acquired before. This
 *             saves one roundtrip in the success-case, since the DISCOVER step
 *             is skipped. However, there are little to no timeouts involved,
 *             so the roundtrip should be barely noticeable. In contrast, if
 *             the INIT-REBOOT fails (because the lease is no longer valid, or
 *             not valid on this network), the client has to wait for a
 *             possible answer to the request before actually starting the DHCP
 *             process all over. This significantly increases the time needed
 *             to switch networks.
 *             The INIT-REBOOT state might have been a real improvements with
 *             the old resend-timeouts mandated by the DHCP specification.
 *             However, on modern networks with improved timeout values we
 *             recommend against using it.
 */
_public_ void n_dhcp4_client_probe_config_set_init_reboot(NDhcp4ClientProbeConfig *config, bool init_reboot) {
        config->init_reboot = init_reboot;
}

/**
 * n_dhcp4_client_probe_config_set_requested_ip() - set requested-ip property
 * @config:                     configuration to operate on
 * @ip:                         value to set
 *
 * This sets the requested-ip property of the given configuration object.
 *
 * The default is all 0. If set to something else, the DHCP discovery will
 * include this IP in its requests to tell DHCP servers which address to pick.
 * Servers are not required to honor this, nor does this have any effect on
 * servers not serving this address.
 *
 * This field should always be set if the caller knows of an address that was
 * previously acquired on this network. It serves as hint to servers and will
 * allow them to provide the same address again.
 */
_public_ void n_dhcp4_client_probe_config_set_requested_ip(NDhcp4ClientProbeConfig *config, struct in_addr ip) {
        config->requested_ip = ip;
}

/**
 * n_dhcp4_client_probe_new() - XXX
 */
int n_dhcp4_client_probe_new(NDhcp4ClientProbe **probep,
                             NDhcp4ClientProbeConfig *config,
                             NDhcp4Client *client) {
        _cleanup_(n_dhcp4_client_probe_freep) NDhcp4ClientProbe *probe = NULL;
        bool active;
        int r;

        /*
         * If there is already a probe attached, we create the new probe in
         * detached state. It will not be linked into the epoll context and not
         * be useful in any way. We immediately raise the CANCELLED event to
         * notify the caller about it.
         */
        active = !client->current_probe;

        probe = calloc(1, sizeof(*probe));
        if (!probe)
                return -ENOMEM;

        *probe = (NDhcp4ClientProbe)N_DHCP4_CLIENT_PROBE_NULL(*probe);
        probe->client = n_dhcp4_client_ref(client);

        r = n_dhcp4_client_probe_config_dup(config, &probe->config);
        if (r)
                return r;

        /* XXX: pass on request_broadcast properly */
        r = n_dhcp4_c_connection_init(&probe->connection,
                                      client->config,
                                      probe->config,
                                      active ? client->fd_epoll : -1,
                                      false);
        if (r)
                return r;

        if (active) {
                probe->client->current_probe = probe;
        } else {
                r = n_dhcp4_client_probe_raise(probe,
                                               NULL,
                                               N_DHCP4_CLIENT_EVENT_CANCELLED);
                if (r)
                        return r;
        }

        *probep = probe;
        probe = NULL;
        return 0;
}

/**
 * n_dhcp4_client_probe_free() - XXX
 */
_public_ NDhcp4ClientProbe *n_dhcp4_client_probe_free(NDhcp4ClientProbe *probe) {
        NDhcp4CEventNode *node, *t_node;

        if (!probe)
                return NULL;

        c_list_for_each_entry_safe(node, t_node, &probe->event_list, probe_link)
                n_dhcp4_c_event_node_free(node);

        if (probe == probe->client->current_probe)
                probe->client->current_probe = NULL;

        n_dhcp4_c_connection_deinit(&probe->connection);
        n_dhcp4_client_unref(probe->client);
        n_dhcp4_client_probe_config_free(probe->config);

        assert(c_list_is_empty(&probe->lease_list));
        assert(c_list_is_empty(&probe->event_list));
        free(probe);

        return NULL;
}

/**
 * n_dhcp4_client_probe_set_userdata() - XXX
 */
_public_ void n_dhcp4_client_probe_set_userdata(NDhcp4ClientProbe *probe, void *userdata) {
        probe->userdata = userdata;
}

/**
 * n_dhcp4_client_probe_get_userdata() - XXX
 */
_public_ void n_dhcp4_client_probe_get_userdata(NDhcp4ClientProbe *probe, void **userdatap) {
        *userdatap = probe->userdata;
}

/**
 * n_dhcp4_client_probe_raise() - XXX
 */
int n_dhcp4_client_probe_raise(NDhcp4ClientProbe *probe, NDhcp4CEventNode **nodep, unsigned int event) {
        NDhcp4CEventNode *node;
        int r;

        r = n_dhcp4_client_raise(probe->client, &node, event);
        if (r)
                return r;

        switch (event) {
        case N_DHCP4_CLIENT_EVENT_OFFER:
                node->event.offer.probe = probe;
                break;
        case N_DHCP4_CLIENT_EVENT_GRANTED:
                node->event.granted.probe = probe;
                break;
        case N_DHCP4_CLIENT_EVENT_RETRACTED:
                node->event.retracted.probe = probe;
                break;
        case N_DHCP4_CLIENT_EVENT_EXTENDED:
                node->event.extended.probe = probe;
                break;
        case N_DHCP4_CLIENT_EVENT_EXPIRED:
                node->event.expired.probe = probe;
                break;
        case N_DHCP4_CLIENT_EVENT_CANCELLED:
                node->event.cancelled.probe = probe;
                break;
        default:
                assert(0);
                n_dhcp4_c_event_node_free(node);
                return -ENOTRECOVERABLE;
        }

        if (nodep)
                *nodep = node;
        return 0;
}

void n_dhcp4_client_probe_get_timeout(NDhcp4ClientProbe *probe, uint64_t *timeoutp) {
        uint64_t timeout;

        n_dhcp4_c_connection_get_timeout(&probe->connection, &timeout);

        if (probe->current_lease) {
                uint64_t t1 = probe->current_lease->t1;
                uint64_t t2 = probe->current_lease->t2;
                uint64_t lifetime = probe->current_lease->lifetime;

                switch (probe->state) {
                case N_DHCP4_CLIENT_PROBE_STATE_BOUND:
                        if (t1 && t1 < timeout)
                                timeout = t2;

                        /* fall-through */
                case N_DHCP4_CLIENT_PROBE_STATE_RENEWING:
                        if (t2 && t2 < timeout)
                                timeout = t2;

                        /* fall-through */
                case N_DHCP4_CLIENT_PROBE_STATE_REBINDING:
                        if (lifetime && lifetime < timeout)
                                timeout = lifetime;
                        break;
                default:
                        /* ignore */
                        break;
                }
        }

        *timeoutp = timeout;
}

static int n_dhcp4_client_probe_transition_t1(NDhcp4ClientProbe *probe) {
        switch (probe->state) {
        case N_DHCP4_CLIENT_PROBE_STATE_BOUND:
                probe->state = N_DHCP4_CLIENT_PROBE_STATE_RENEWING;
                break;

        case N_DHCP4_CLIENT_PROBE_STATE_INIT:
        case N_DHCP4_CLIENT_PROBE_STATE_SELECTING:
        case N_DHCP4_CLIENT_PROBE_STATE_INIT_REBOOT:
        case N_DHCP4_CLIENT_PROBE_STATE_REBOOTING:
        case N_DHCP4_CLIENT_PROBE_STATE_REQUESTING:
        case N_DHCP4_CLIENT_PROBE_STATE_RENEWING:
        case N_DHCP4_CLIENT_PROBE_STATE_REBINDING:
        default:
                /* ignore */
                break;
        }

        return 0;
}

static int n_dhcp4_client_probe_transition_t2(NDhcp4ClientProbe *probe) {
        switch (probe->state) {
        case N_DHCP4_CLIENT_PROBE_STATE_BOUND:
        case N_DHCP4_CLIENT_PROBE_STATE_RENEWING:
                probe->state = N_DHCP4_CLIENT_PROBE_STATE_REBINDING;
                break;

        case N_DHCP4_CLIENT_PROBE_STATE_INIT:
        case N_DHCP4_CLIENT_PROBE_STATE_SELECTING:
        case N_DHCP4_CLIENT_PROBE_STATE_INIT_REBOOT:
        case N_DHCP4_CLIENT_PROBE_STATE_REBOOTING:
        case N_DHCP4_CLIENT_PROBE_STATE_REQUESTING:
        case N_DHCP4_CLIENT_PROBE_STATE_REBINDING:
        default:
                /* ignore */
                break;
        }

        return 0;
}

static int n_dhcp4_client_probe_transition_lifetime(NDhcp4ClientProbe *probe) {
        switch (probe->state) {
        case N_DHCP4_CLIENT_PROBE_STATE_BOUND:
        case N_DHCP4_CLIENT_PROBE_STATE_RENEWING:
        case N_DHCP4_CLIENT_PROBE_STATE_REBINDING:
                probe->state = N_DHCP4_CLIENT_PROBE_STATE_INIT;
                break;

        case N_DHCP4_CLIENT_PROBE_STATE_INIT:
        case N_DHCP4_CLIENT_PROBE_STATE_SELECTING:
        case N_DHCP4_CLIENT_PROBE_STATE_INIT_REBOOT:
        case N_DHCP4_CLIENT_PROBE_STATE_REBOOTING:
        case N_DHCP4_CLIENT_PROBE_STATE_REQUESTING:
        default:
                /* ignore */
                break;
        }

        return 0;
}

static int n_dhcp4_client_probe_transition_offer(NDhcp4ClientProbe *probe) {
        switch (probe->state) {
        case N_DHCP4_CLIENT_PROBE_STATE_SELECTING:
                probe->state = N_DHCP4_CLIENT_PROBE_STATE_REQUESTING;
                break;

        case N_DHCP4_CLIENT_PROBE_STATE_INIT:
        case N_DHCP4_CLIENT_PROBE_STATE_INIT_REBOOT:
        case N_DHCP4_CLIENT_PROBE_STATE_REBOOTING:
        case N_DHCP4_CLIENT_PROBE_STATE_REQUESTING:
        case N_DHCP4_CLIENT_PROBE_STATE_BOUND:
        case N_DHCP4_CLIENT_PROBE_STATE_RENEWING:
        case N_DHCP4_CLIENT_PROBE_STATE_REBINDING:
        default:
                /* ignore */
                break;
        }

        return 0;
}

static int n_dhcp4_client_probe_transition_ack(NDhcp4ClientProbe *probe) {
        switch (probe->state) {
        case N_DHCP4_CLIENT_PROBE_STATE_INIT:
        case N_DHCP4_CLIENT_PROBE_STATE_SELECTING:
        case N_DHCP4_CLIENT_PROBE_STATE_INIT_REBOOT:
        case N_DHCP4_CLIENT_PROBE_STATE_REBOOTING:
        case N_DHCP4_CLIENT_PROBE_STATE_REQUESTING:
        case N_DHCP4_CLIENT_PROBE_STATE_BOUND:
        case N_DHCP4_CLIENT_PROBE_STATE_RENEWING:
        case N_DHCP4_CLIENT_PROBE_STATE_REBINDING:
        default:
                /* ignore */
                break;
        }

        return 0;
}

static int n_dhcp4_client_probe_transition_nak(NDhcp4ClientProbe *probe) {
        switch (probe->state) {
        case N_DHCP4_CLIENT_PROBE_STATE_REBOOTING:
        case N_DHCP4_CLIENT_PROBE_STATE_REQUESTING:
        case N_DHCP4_CLIENT_PROBE_STATE_RENEWING:
        case N_DHCP4_CLIENT_PROBE_STATE_REBINDING:
                probe->state = N_DHCP4_CLIENT_PROBE_STATE_INIT;
                break;

        case N_DHCP4_CLIENT_PROBE_STATE_SELECTING:
        case N_DHCP4_CLIENT_PROBE_STATE_INIT_REBOOT:
        case N_DHCP4_CLIENT_PROBE_STATE_INIT:
        case N_DHCP4_CLIENT_PROBE_STATE_BOUND:
        default:
                /* ignore */
                break;
        }

        return 0;
}

/**
 * n_dhcp4_client_probe_dispatch_timer() - XXX
 */
int n_dhcp4_client_probe_dispatch_timer(NDhcp4ClientProbe *probe, uint64_t ns_now) {
        int r;

        if (probe->current_lease) {
                switch (probe->state) {
                case N_DHCP4_CLIENT_PROBE_STATE_BOUND:
                case N_DHCP4_CLIENT_PROBE_STATE_RENEWING:
                case N_DHCP4_CLIENT_PROBE_STATE_REBINDING:
                        if (ns_now >= probe->current_lease->lifetime) {
                                r = n_dhcp4_client_probe_transition_lifetime(probe);
                                if (r)
                                        return r;
                        } else if (ns_now >= probe->current_lease->t2) {
                                r = n_dhcp4_client_probe_transition_t2(probe);
                                if (r)
                                        return r;
                        } else if (ns_now >= probe->current_lease->t1) {
                                r = n_dhcp4_client_probe_transition_t1(probe);
                                if (r)
                                        return r;
                        }

                        break;
                default:
                        /* ignore */
                        break;
                }
        }

        r = n_dhcp4_c_connection_dispatch_timer(&probe->connection, ns_now);
        if (r)
                return r;

        return 0;
}

/**
 * n_dhcp4_client_probe_dispatch_connection() - XXX
 */
int n_dhcp4_client_probe_dispatch_io(NDhcp4ClientProbe *probe, uint32_t events) {
        int r;

        for (unsigned int i = 0; i < 32; ++i) {
                _cleanup_(n_dhcp4_incoming_freep) NDhcp4Incoming *message = NULL;
                uint8_t type;

                r = n_dhcp4_c_connection_dispatch_io(&probe->connection, &message);
                if (r)
                        return r;

                if (!message)
                        continue;

                r = n_dhcp4_incoming_query_message_type(message, &type);
                if (r == N_DHCP4_E_UNSET || r == N_DHCP4_E_MALFORMED)
                        continue;

                switch (type) {
                case N_DHCP4_MESSAGE_OFFER:
                        r = n_dhcp4_client_probe_transition_offer(probe);
                        if (r)
                                return r;
                        break;
                case N_DHCP4_MESSAGE_ACK:
                        r = n_dhcp4_client_probe_transition_ack(probe);
                        if (r)
                                return r;
                        break;
                case N_DHCP4_MESSAGE_NAK:
                        r = n_dhcp4_client_probe_transition_nak(probe);
                        if (r)
                                return r;
                        break;
                }
        }

        return 0;
}

/**
 * n_dhcp4_client_probe_update_mtu() - XXX
 */
int n_dhcp4_client_probe_update_mtu(NDhcp4ClientProbe *probe, uint16_t mtu) {
        return 0;
}
