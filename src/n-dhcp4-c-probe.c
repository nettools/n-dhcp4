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

        /* XXX: uninstall epoll-events from probe->client->fd_epoll */

        probe->client->current_probe = NULL;
}

/**
 * n_dhcp4_client_probe_dispatch_timer() - XXX
 */
int n_dhcp4_client_probe_dispatch_timer(NDhcp4ClientProbe *probe) {
        return 0;
}

/**
 * n_dhcp4_client_probe_dispatch_connection() - XXX
 */
int n_dhcp4_client_probe_dispatch_connection(NDhcp4ClientProbe *probe, uint32_t events) {
        return 0;
}

/**
 * n_dhcp4_client_probe_update_mtu() - XXX
 */
int n_dhcp4_client_probe_update_mtu(NDhcp4ClientProbe *probe, uint16_t mtu) {
        return 0;
}
