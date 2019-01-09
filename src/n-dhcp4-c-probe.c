/*
 * DHCPv4 Client Probes
 *
 * XXX
 */

#include <assert.h>
#include <c-list.h>
#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "n-dhcp4.h"
#include "n-dhcp4-private.h"

/**
 * n_dhcp4_client_probe_config_new() - XXX
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
 * n_dhcp4_client_probe_config_free() - XXX
 */
_public_ NDhcp4ClientProbeConfig *n_dhcp4_client_probe_config_free(NDhcp4ClientProbeConfig *config) {
        if (!config)
                return NULL;

        free(config);

        return NULL;
}

/**
 * n_dhcp4_client_probe_config_set_inform_only() - XXX
 */
_public_ void n_dhcp4_client_probe_config_set_inform_only(NDhcp4ClientProbeConfig *config, bool inform_only) {
        config->inform_only = inform_only;
}

/**
 * n_dhcp4_client_probe_config_set_init_reboot() - XXX
 */
_public_ void n_dhcp4_client_probe_config_set_init_reboot(NDhcp4ClientProbeConfig *config, bool init_reboot) {
        config->init_reboot = init_reboot;
}

/**
 * n_dhcp4_client_probe_config_set_requested_ip() - XXX
 */
_public_ void n_dhcp4_client_probe_config_set_requested_ip(NDhcp4ClientProbeConfig *config, struct in_addr ip) {
        config->requested_ip = ip;
}

/**
 * n_dhcp4_client_probe_new() - XXX
 */
int n_dhcp4_client_probe_new(NDhcp4ClientProbe **probep, NDhcp4Client *client) {
        _cleanup_(n_dhcp4_client_probe_freep) NDhcp4ClientProbe *probe = NULL;

        probe = calloc(1, sizeof(*probe));
        if (!probe)
                return -ENOMEM;

        *probe = (NDhcp4ClientProbe)N_DHCP4_CLIENT_PROBE_NULL(*probe);
        probe->client = n_dhcp4_client_ref(client);

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

        n_dhcp4_client_probe_uninstall(probe);
        n_dhcp4_c_connection_deinit(&probe->connection);
        n_dhcp4_client_unref(probe->client);
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

/**
 * n_dhcp4_client_probe_install() - XXX
 */
int n_dhcp4_client_probe_install(NDhcp4ClientProbe *probe) {
        if (probe->client->current_probe)
                return -ENOTRECOVERABLE;

        /* XXX: install epoll-events to probe->client->fd_epoll */

        probe->client->current_probe = probe;
        return 0;
}

/**
 * n_dhcp4_client_probe_uninstall() - XXX
 */
void n_dhcp4_client_probe_uninstall(NDhcp4ClientProbe *probe) {
        if (probe != probe->client->current_probe)
                return;

        n_dhcp4_c_connection_deinit(&probe->connection);

        probe->client->current_probe = NULL;
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

static uint64_t n_dhcp4_client_probe_gettime(void) {
        struct timespec ts;
        int r;

        r = clock_gettime(CLOCK_BOOTTIME, &ts);
        assert(r >= 0);

        return ts.tv_sec * 1000ULL * 1000ULL + ts.tv_nsec / 1000ULL;
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
int n_dhcp4_client_probe_dispatch_timer(NDhcp4ClientProbe *probe) {
        uint64_t now;
        int r;

        now = n_dhcp4_client_probe_gettime();

        if (probe->current_lease) {
                switch (probe->state) {
                case N_DHCP4_CLIENT_PROBE_STATE_BOUND:
                case N_DHCP4_CLIENT_PROBE_STATE_RENEWING:
                case N_DHCP4_CLIENT_PROBE_STATE_REBINDING:
                        if (now >= probe->current_lease->lifetime) {
                                r = n_dhcp4_client_probe_transition_lifetime(probe);
                                if (r)
                                        return r;
                        } else if (now >= probe->current_lease->t2) {
                                r = n_dhcp4_client_probe_transition_t2(probe);
                                if (r)
                                        return r;
                        } else if (now >= probe->current_lease->t1) {
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

        r = n_dhcp4_c_connection_dispatch_timer(&probe->connection, now);
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
                uint8_t *type;
                size_t n_type;

                r = n_dhcp4_c_connection_dispatch_io(&probe->connection, &message);
                if (r)
                        return r;

                if (!message)
                        continue;

                r = n_dhcp4_incoming_query(message, N_DHCP4_OPTION_MESSAGE_TYPE, &type, &n_type);
                if (r == N_DHCP4_E_UNSET || n_type != sizeof(type))
                        continue;

                switch (*type) {
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
