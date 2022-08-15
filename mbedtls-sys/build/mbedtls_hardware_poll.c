/*
 * AUTHORS
 *
 * The Veracruz Development Team.
 *
 * COPYRIGHT
 *
 * See the `LICENSE_MIT.markdown` file in the Veracruz root directory
 * for licensing and copyright information.
 *
 */

#include "psa/crypto.h"
#include <stdio.h>

int mbedtls_hardware_poll(void *data,
                          unsigned char *output, size_t len, size_t *olen)
{
    (void)data;

    // Workaround for Nitro machines affected by entropy shortage
    // TODO: Use Veracruz's platform services instead
    FILE *f = fopen("/dev/urandom", "r");
    ssize_t ret = fread(output, len, 1, f);
    fclose(f);

    if (ret == -1)
        return PSA_ERROR_GENERIC_ERROR;
    *olen = ret;
    return 0;
}
