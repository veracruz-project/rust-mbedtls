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

#include "mbedtls/platform.h"
#include "psa/crypto.h"
#include <signal.h>
#include <unistd.h>

#if 0
// This is what one would normally do to get the prototype for getrandom,
// but it does not work with version 1.1.19-1 of musl-tools, which comes
// with Ubuntu 18.04 and is currently used for the Nitro build of Veracruz.
#include <sys/random.h>
#else
// This currently works for all targets.
#include <sys/types.h>
ssize_t getrandom(void *buf, size_t buflen, unsigned int flags);
#endif

// Handle SIGALARM signal.
void handle_sigalarm(int signo)
{
    (void)signo;
    mbedtls_printf("getrandom() could not return before the timeout. The entropy bug might be back to haunt us! Aborting\n");
    mbedtls_exit(1);
}

int mbedtls_hardware_poll(void *data,
                          unsigned char *output, size_t len, size_t *olen)
{
    (void)data;

    // Configure a one-shot alarm that terminates the process with an error
    // message if `getrandom()` doesn't return pronto.
    // Cf. https://github.com/veracruz-project/veracruz/issues/507
    // TODO: Remove this mechanism when the entropy issue goes away
    struct sigaction act;
    act.sa_handler = &handle_sigalarm;
    act.sa_flags = SA_RESETHAND;
    sigaction(SIGALRM, &act, NULL);
    alarm(10);
#endif
    ssize_t ret = getrandom(output, len, 0);
    alarm(0);

    if (ret == -1)
        return PSA_ERROR_GENERIC_ERROR;
    *olen = ret;
    return 0;
}
