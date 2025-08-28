/**
 * @file hostname.c
 *
 * Container for system hostname utility functions
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "hostname.h"

#define MAX_HOSTNAME_LEN 256

/*********************************************************************//**
**
** tu_get_hostname
**
** Gets the system hostname.
**
** \param   hostname - Pointer to buffer where hostname will be stored
** \param   buf_len - Length of the buffer
**
** \return  0 if success, -1 if failure
**
**************************************************************************/
int
tu_get_hostname(char *hostname, size_t buf_len)
{
    if (hostname == NULL || buf_len == 0)
        return -1;

    if (gethostname(hostname, buf_len) != 0)
        return -1;

    // Ensure null termination
    hostname[buf_len - 1] = '\0';

    return 0;
}
