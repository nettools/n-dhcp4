/*
 * API Visibility Tests
 * This verifies the visibility and availability of the exported API.
 */

#include <assert.h>
#include <stdlib.h>
#include "n-dhcp4.h"

static void test_api(void) {
        NDhcp4Client *client;
        int r;

        r = n_dhcp4_client_new(&client);
        assert(!r);

        r = n_dhcp4_client_get_fd(client);
        assert(r >= 0);

        r = n_dhcp4_client_dispatch(client);
        assert(!r);

        client = n_dhcp4_client_free(client);
        assert(!client);
}

int main(int argc, char **argv) {
        test_api();
        return 0;
}
