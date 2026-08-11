#include <stdio.h>
#include <linux/if_ether.h>

#include <glib.h>
#include <gio/gio.h>
#include <glib-unix.h>

#include "n-dhcp4.h"

#define DHCP4_START_DELAY_MS 10

typedef struct {
    GMainLoop *mainloop;
    int final_status;
    guint timeout_id;
    guint event_source_id;
    gboolean verbose;
    NDhcp4Client *dhcp_client;
} Context;

#define dhcp4_log(_format, _args...) fprintf (stderr, "check-dhcp4: " _format "\n", ##_args)

static guint8 *
get_hwaddr (const gchar *iface, GError **error)
{
    g_autofree gchar *path = g_strdup_printf ("/sys/class/net/%s/address", iface);
    g_autofree gchar *mac = NULL;
    guint8 *mac_addr_val;
    GError *suberror = NULL;
    gchar **tokens = NULL;

    if (!g_file_test (path, G_FILE_TEST_EXISTS)) {
        g_set_error (error, 1, 1, "unexisting interface '%s'", iface);
        return NULL;
    }

    g_file_get_contents (path, &mac, NULL, &suberror);
    if (suberror) {
        g_propagate_error (error, suberror);
        return NULL;
    }

    mac[strlen (mac) - 1] = '\0';
    dhcp4_log ("MAC address is %s", mac);

    mac_addr_val = g_new0 (guint8, ETH_ALEN);
    tokens = g_strsplit (mac, ":", -1);
    for (guint i = 0; tokens[i]; i++) {
        mac_addr_val[i] = g_ascii_strtoull (tokens[i], NULL, 16);
    }
    g_strfreev (tokens);
    return mac_addr_val;
}

static int
get_ifindex (const gchar *iface, GError **error)
{
    g_autofree gchar *path = g_strdup_printf ("/sys/class/net/%s/ifindex", iface);
    GError *suberror = NULL;
    gchar *contents = NULL;

    if (!g_file_test (path, G_FILE_TEST_EXISTS)) {
        g_set_error (error, 1, 1, "unexisting interface '%s'", iface);
        return -1;
    }

    g_file_get_contents (path, &contents, NULL, &suberror);
    if (suberror) {
        g_propagate_error (error, suberror);
        return -1;
    }
    return (int) g_ascii_strtoull (contents, NULL, 10);
}

static gboolean
stop_in_idle_cb (gpointer user_data)
{
    Context *ctx = (Context *) user_data;

    g_main_loop_quit (ctx->mainloop);

    return G_SOURCE_REMOVE;
}

static gboolean
dhcp_lease_timeout_cb (gpointer user_data)
{
    Context *ctx = (Context *) user_data;

    dhcp4_log ("DHCP lease timeout");
    ctx->final_status = -2;
    g_idle_add (stop_in_idle_cb, ctx);
    return G_SOURCE_REMOVE;
}

static void
dhcp4_pop_all_events_on_idle_cb (Context *ctx)
{
    NDhcp4ClientEvent *event;

    while (!n_dhcp4_client_pop_event (ctx->dhcp_client, &event) && event) {
        switch (event->event) {
        case N_DHCP4_CLIENT_EVENT_LOG:
            dhcp4_log ("(n-dhcp4) %s", event->log.message);
            break;
        case N_DHCP4_CLIENT_EVENT_OFFER:
            dhcp4_log ("DHCP OFFER received: OK");
            ctx->final_status = 0;
            g_idle_add (stop_in_idle_cb, ctx);
            break;
        case N_DHCP4_CLIENT_EVENT_RETRACTED:
            dhcp4_log ("DHCP event retracted");
            break;
        case N_DHCP4_CLIENT_EVENT_EXPIRED:
            dhcp4_log ("DHCP event expired");
            break;
        case N_DHCP4_CLIENT_EVENT_CANCELLED:
            dhcp4_log ("DHCP event cancelled");
            break;
        case N_DHCP4_CLIENT_EVENT_GRANTED:
            dhcp4_log ("DHCP event granted");
            break;
        case N_DHCP4_CLIENT_EVENT_EXTENDED:
            dhcp4_log ("DHCP event extended");
            break;
        case N_DHCP4_CLIENT_EVENT_DOWN:
            dhcp4_log ("DHCP event down");
            break;
        default:
            dhcp4_log ("DHCP unhandle event %d", event->event);
            break;
        }
    }
}

static gboolean
dhcp4_event_cb (int fd, GIOCondition condition, gpointer user_data)
{
    Context *ctx = (Context *) user_data;
    int res;

    res = n_dhcp4_client_dispatch (ctx->dhcp_client);
    if (res < 0) {
        dhcp4_log ("error %d dispatching events", res);
        ctx->event_source_id = 0;
        g_main_loop_quit (ctx->mainloop);
        return G_SOURCE_REMOVE;
    }

    dhcp4_pop_all_events_on_idle_cb (ctx);
    return G_SOURCE_CONTINUE;
}

static gboolean
nettools_create (Context *ctx, const gchar *iface, GError **error)
{
    NDhcp4ClientConfig *config = NULL;
    NDhcp4Client *client = NULL;
    int r, fd, if_index;
    GError *suberror = NULL;
    g_autofree guint8 *mac_addr_val = NULL;
    /*
        we will use mac address as our client id, so there is
        an additional byte at 0x01 (ethernet ARP type) followed
        by the MAC address
    */
    guint8 client_id[ETH_ALEN + 1];
    guint8 bcast_addr_val[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    mac_addr_val = get_hwaddr (iface, &suberror);
    if (suberror) {
        g_propagate_error (error, suberror);
        return FALSE;
    }

    client_id[0] = 0x01;
    memcpy (&client_id[1], mac_addr_val, ETH_ALEN);

    if_index = get_ifindex (iface, &suberror);
    if (suberror) {
        g_propagate_error (error, suberror);
        return FALSE;
    }

    r = n_dhcp4_client_config_new (&config);
    if (r) {
        g_set_error (error, 1, 1, "failed to create client-config");
        return FALSE;
    }

    n_dhcp4_client_config_set_ifindex (config, if_index);
    n_dhcp4_client_config_set_transport (config, N_DHCP4_TRANSPORT_ETHERNET);
    n_dhcp4_client_config_set_mac (config, mac_addr_val, ETH_ALEN);
    n_dhcp4_client_config_set_broadcast_mac (config, bcast_addr_val, ETH_ALEN);
    n_dhcp4_client_config_set_request_broadcast (config, FALSE);
    r = n_dhcp4_client_config_set_client_id (config, client_id, ETH_ALEN + 1);
    if (r) {
        g_set_error (error, 1, 1, "failed to set client-id");
        return FALSE;
    }

    r = n_dhcp4_client_new (&client, config);
    if (r) {
        g_set_error (error, 1, 1, "failed to create client");
        return FALSE;
    }

    n_dhcp4_client_set_log_level (client, ctx->verbose ? 7 : -1);
    n_dhcp4_client_get_fd (client, &fd);

    ctx->event_source_id = g_unix_fd_add (fd, G_IO_IN, dhcp4_event_cb, ctx);
    ctx->dhcp_client = client;
    return TRUE;
}

int
main (int argc, char **argv)
{
    GError *error = NULL;
    NDhcp4ClientProbeConfig *dhcp_config = NULL;
    NDhcp4ClientProbe *dhcp_probe = NULL;
    guint32 dhcp_timeout = 2;
    const gchar *iface = NULL;
    int res = -1;
    g_autofree Context *ctx = g_new0 (Context, 1);

    GOptionContext *opt_context = g_option_context_new ("- chechk-dhcp4 , a tool to check for DHCP liveness");
    GOptionEntry entries[] = {{"iface",
                               'i',
                               0,
                               G_OPTION_ARG_STRING,
                               &iface,
                               "The interface from which we will send/receive DHCP requests/replies",
                               NULL},
                              {"timeout",
                               't',
                               0,
                               G_OPTION_ARG_INT,
                               &dhcp_timeout,
                               "The time to wait for DHCP reply before giving up (default to 2s)",
                               NULL},
                              {"verbose", 'v', 0, G_OPTION_ARG_NONE, &ctx->verbose, "Be more verbose", NULL},
                              {NULL}};

    g_option_context_add_main_entries (opt_context, entries, NULL);
    if (!g_option_context_parse (opt_context, &argc, &argv, &error)) {
        dhcp4_log ("option parsing failed: %s", error->message);
        g_error_free (error);
        exit (EXIT_FAILURE);
    }
    g_option_context_free (opt_context);

    if (getuid () != 0) {
        dhcp4_log ("Must be run as root !");
        exit (EXIT_FAILURE);
    }
    if (!iface) {
        dhcp4_log ("An interface (-i/--iface) must be provided");
        exit (EXIT_FAILURE);
    }

    nettools_create (ctx, iface, &error);
    if (error) {
        dhcp4_log ("Unable to start dhcp client: %s", error->message);
        g_error_free (error);
        exit (EXIT_FAILURE);
    }

    res = n_dhcp4_client_probe_config_new (&dhcp_config);
    if (res) {
        dhcp4_log ("failed to create dhcp-client-probe-config");
        n_dhcp4_client_unref (ctx->dhcp_client);
        exit (EXIT_FAILURE);
    }

    n_dhcp4_client_probe_config_set_start_delay (dhcp_config, DHCP4_START_DELAY_MS);

    // Subnet mask
    n_dhcp4_client_probe_config_request_option (dhcp_config, 1);
    // Time offset
    n_dhcp4_client_probe_config_request_option (dhcp_config, 2);
    // Router
    n_dhcp4_client_probe_config_request_option (dhcp_config, 3);
    // Domain name server
    n_dhcp4_client_probe_config_request_option (dhcp_config, 6);
    // Host name
    n_dhcp4_client_probe_config_request_option (dhcp_config, 12);
    // Root path
    n_dhcp4_client_probe_config_request_option (dhcp_config, 17);
    // Interface mtu
    n_dhcp4_client_probe_config_request_option (dhcp_config, 26);
    // Broadcast
    n_dhcp4_client_probe_config_request_option (dhcp_config, 28);
    // Static route
    n_dhcp4_client_probe_config_request_option (dhcp_config, 33);
    // NIS domain
    n_dhcp4_client_probe_config_request_option (dhcp_config, 40);
    // NIS servers
    n_dhcp4_client_probe_config_request_option (dhcp_config, 41);
    // NTP server
    n_dhcp4_client_probe_config_request_option (dhcp_config, 42);
    // Domain search list
    n_dhcp4_client_probe_config_request_option (dhcp_config, 119);
    // Classless static route
    n_dhcp4_client_probe_config_request_option (dhcp_config, 121);
    // Private classless static route
    n_dhcp4_client_probe_config_request_option (dhcp_config, 249);
    // Private proxy autodiscovery
    n_dhcp4_client_probe_config_request_option (dhcp_config, 252);

    res = n_dhcp4_client_probe (ctx->dhcp_client, &dhcp_probe, dhcp_config);
    if (res) {
        dhcp4_log ("failed to start DHCP client");
        n_dhcp4_client_unref (ctx->dhcp_client);
        exit (EXIT_FAILURE);
    }

    ctx->final_status = -1;
    ctx->timeout_id = g_timeout_add_seconds (dhcp_timeout, dhcp_lease_timeout_cb, ctx);
    ctx->mainloop = g_main_loop_new (NULL, FALSE);

    dhcp4_log ("start in %u ms (timeout %u s)", DHCP4_START_DELAY_MS, dhcp_timeout);

    g_main_loop_run (ctx->mainloop);

    dhcp4_log ("ends with status %d", ctx->final_status);

    n_dhcp4_client_probe_config_free (dhcp_config);
    n_dhcp4_client_probe_free (dhcp_probe);
    n_dhcp4_client_unref (ctx->dhcp_client);
    return ctx->final_status;
}
