/*
 * DHCPv4 Client Probes
 *
 * XXX
 */

#include <assert.h>
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
        if (!probe)
                return NULL;

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
