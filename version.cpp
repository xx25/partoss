#include "partoss.h"
#include "globext.h"

#include "version.h"
#include "lowlevel.h"

#define VERSION "1.10.071/SEC"

#define vertype 5
// 1 - alpha, 2 - beta, 3 - gamma, 4 - rev. x, 5 - developer, 0 - none
#if vertype == 0
#define vversion
#elif vertype == 1
#define vversion " alpha"
#elif vertype == 2
#define vversion " beta"
#elif vertype == 3
#define vversion " gamma"
#elif vertype == 4
#define vversion " rev. x"
#elif vertype == 5
#define vversion " devel"
#endif


void printversion(void)
{
#if defined( __DOS__ )
#define verplatform "/DOS"
#elif defined( __NT__ )
#define verplatform "/W32"
#elif defined( __OS2__)
#define verplatform "/OS2"
#elif defined( __EMX__)
#define verplatform "/EMX"
#elif defined( __linux__)
#define verplatform "/LNX"
#elif defined( __FreeBSD__)
#define verplatform "/FreeBSD"
#elif defined( SYSTEM_NAME)
/*
 * If there is any macro with the same function then this
 * one should be removed.
 */
#define verplatform SYSTEM_NAME
#else
#warning So, what system we are building for?
#define verplatform "/UNK"
#endif
  mystrncpy (version, VERSION verplatform vversion, MAX_VERSIONLEN - 1);
  logprintf("The Parma Tosser version %s", version);
  ccprintf("%s\r\n", logout);
#ifdef __NT__
  SetConsoleTitle(logout);
#endif

#ifndef __VERSION__
#ifdef __BORLANDC__
#define __VERSION__ "Borland C/C++"
#else
#ifdef __WATCOMC__
#define __VERSION__ "Watcom C/C++"
#else
#define __VERSION__ "Unknown C/C++ compiler"
#endif
#endif
#endif

  ccprintf("Compiled on %s %s with %s\r\n", __DATE__, __TIME__, __VERSION__);
}
