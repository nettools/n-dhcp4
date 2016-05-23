/*
 * Tests for Public API
 * This test, unlikely the others, is linked against the real, distributed,
 * shared library. Its sole purpose is to test for symbol availability.
 */

#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "n-dhcp4.h"

static void test_api(void) {
        NDhcp4Client *client;
        int r;

        r = n_dhcp4_client_new(&client);
        assert(r >= 0);

        client = n_dhcp4_client_free(client);
        assert(!client);
}

int main(int argc, char **argv) {
        test_api();
        return 0;
}
