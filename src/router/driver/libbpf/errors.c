// +build linux

#include <string.h>
#include <errno.h>

#include "errors.h"

// report_errno return last set errno
char * report_errno()
{
	return strerror(errno);
}
