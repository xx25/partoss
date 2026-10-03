#define __WATCOM_10_6__
#ifdef __WATCOM_10_6__
#define ccprintf              cprintf
#else
#define ccprintf              printf
#endif
#ifndef ParToss
#define ParToss 1
/* #define __DOS__ 1 */

//#ifdef __EMX__
//#define __linux__
//#endif


/* $Id: partoss.h,v 1.12 2003/04/16 16:10:30 mozhaev Exp $ */
/* Ported partially */
#ifdef HAVE_CONFIG_H

#include "config.h"

#include <sys/types.h>
#include <sys/errno.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */

#include <stdio.h>

#if STDC_HEADERS
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#else /* STDC_HEADERS */

#if HAVE_MALLOC_H
// #include <malloc.h>
#endif

#if HAVE_STDARG_H
#include <stdarg.h>
#elif HAVE_VARARGS_H
#include <varargs.h>
#endif

/* Suppose, that we always have string.h. We'll check for other
   header here if this is not so... */
#include <string.h>

#endif /* STDC_HEADERS */

#if HAVE_DIRENT_H
#include <dirent.h>
#elif HAVE_SYS_NDIR_H
#include <sys/ndir.h>
#elif HAVE_SYS_DIR_H
#include <sys/dir.h>
#elif HAVE_NDIR_H
#include <ndir.h>
#else
#error There is no directory-related headers to include...
#endif /* Directory headers */

#if TIME_WITH_SYS_TIME
#include <time.h>
#include <sys/time.h>
#elif HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif

#if HAVE_IO_H
#include <io.h>
#endif

#if HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <sys/stat.h>
#include <ctype.h>

#if HAVE_LIMITS_H
#include <limits.h>
#endif

#if HAVE_FNMATCH_H
#include <fnmatch.h>
#endif

#if HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#ifndef WEXITSTATUS
#define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
#endif
#ifndef WIFEXITED
#define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
#endif

#if defined( MAXPATHLEN)
#define DirSize MAXPATHLEN
#elif defined( PATH_MAX)
#define DirSize PATH_MAX
#elif defined( _MAX_PATH)
#define DirSize _MAX_PATH
#else
#warning Cannot guess DirSize, suppose it to be 80
#define DirSize 80
#endif

#define BufSize 512
#define CSSize  300

#define HAVE__FULLPATH

// Actually, the only systems I know, which works
// with \ as with directory separator, is DOS-derived
// hunchbacks: DOS itself, Win*, OS/2. Since NT and OS/2 -
// the only systems in this family autoconf works under,
// and both of them works with / as directory separator
// we can define it here w/o any conditions. If there any
// place, where \ can be used then we should translate it
// into / there.
#define DIRSEP "/"

// #define SHELL_VAR "SHELL"
// #define SHELL_OPT "-c"

#ifndef O_BINARY
#define O_BINARY 0
#endif
#ifndef O_EXLOCK
#define O_EXLOCK 0
#endif

#else /* HAVE_CONFIG_H */

#ifdef __NT__
#pragma aux all "_*"
#include <windows.h>
#include <wincon.h>
#endif
#ifdef __OS2__
#define INCL_DOSPROCESS
#include <os2.h>
#include <except.h>
#endif
#include <stdio.h>

#if !defined(__linux__) && !defined(__FreeBSD__)
#include <conio.h>
#else
#include "_portlib.h"
#endif

#include <stdlib.h>
#include <string.h>
#if !defined(__linux__) && !defined(__FreeBSD__)
#ifdef __EMX__
#include <sys/types.h>
#include <sys/dir.h>
#else
#include <direct.h>
#endif
#include <dos.h>
#ifdef __DOS__
#include <bios.h>
#endif
#include <io.h>
#endif
#include <fcntl.h>
//#include <malloc.h>
#include <time.h>
#if defined(__linux__) || defined(__FreeBSD__)
#include <sys/stat.h>
#else
#include <sys/stat.h>
#endif
#include <ctype.h>
#include <errno.h>

#if !defined(__linux__) && !defined(__FreeBSD__)
#include <process.h>
#include <share.h>
#ifdef __EMX__
#include <dos.h>
#else
#ifndef __BORLANDC__
#include "i86.h"
#endif
#endif
extern int int86 (int intr_no, const union REGS *inreg, union REGS *outreg);
#endif

#ifdef __BORLANDC__
// Borland
#ifdef __WIN32__
 int _dos_findclose(struct find_t *__finfo) { return(1); };
 #ifndef __NT__
  #define __NT__
 #endif
#endif
// Watcom
/* group permission.  same as owner's on PC and PenPoint*/
#define S_IRWXG   0000070
/* other permission.  same as owner's on PC and PenPoint*/
#define S_IRWXO   0000007
// Windows
#include <windows.h>
// Watcom
int _os_handle( int handle ) { return handle; };
int _grow_handles( int new_count ) { return new_count; };
#endif // __BORLANDC__

// XM functions for memory control debugging
// #define XM_USED
// #include "xm.h"

#ifdef __DOS__
#define DirSize 80
#define CSSize 128
#define BufSize 256
#else
#define DirSize 256
#define CSSize 300
#define BufSize 512
#endif

#if (defined (__linux__) && !defined (__EMX__)) || defined(__FreeBSD__)
#define DIRSEP "/"
#define SHELL_VAR "SHELL"
#define SHELL_OPT "-c"
#define NULL_DEV "/dev/null"
#else
#define DIRSEP "\\"
#define SHELL_VAR "COMSPEC"
#define SHELL_OPT "/C"
#define NULL_DEV "NUL"
#endif



// The following definitions is necessary to support autoconf...
#define HAVE_SOPEN 1

// ... and automake.

#endif /* HAVE_CONFIG_H */

// Makes a string from x.
#define STRINGIFY(x) #x

#define MAX_HANDLES 255
#define arealength 60

#define MAX_VERSIONLEN 40

#define Close close
#define strichr(x,y) strchr(strupr(x),toupper(y))

// MaxiM: OUT changed to lowercase
#define OUT_MASK "*.out"
#define OUT_EXT  ".out"
#define PKT_MASK "*.pkt"
#define PKT_EXT  "pkt"

#include "list_tpl.h"

// Packet type 2 definitions

struct stoneage
{
  unsigned short fromnode, tonode;
  unsigned short year, month, day, hour, minute, second;
  unsigned short baud, pkttype;
  unsigned short fromnet, tonet;
  char prodcode, serialno;
  char password[8];
  unsigned short fromzone, tozone;
  char fill[20];
};

struct twoplus
{
  unsigned short fromnode, tonode;
  unsigned short year, month, day, hour, minute, second;
  unsigned short baud, pkttype;
  unsigned short fromnet, tonet;
  char prodcode, serialno;
  char password[8];
  unsigned short fromzone, tozone, auxnet;
  unsigned short cwvalcopy;
  char product, serminor;
  unsigned short cw;
  unsigned short origzone, destzone, frompoint, topoint;
  char specific[4];
};

struct twoptwo
{
  unsigned short fromnode, tonode, frompoint, topoint;
  unsigned short reserved[4];
  unsigned short subtype, pkttype;
  unsigned short fromnet, tonet;
  char prodcode, serialno;
  char password[8];
  unsigned short fromzone, tozone;
  char fromdomain[8], todomain[8];
  char specific[4];
};

union pktheader
{
  struct stoneage two;
  struct twoplus twop;
  struct twoptwo twot;
};

// Packed message

struct packmess
{
  unsigned short packtype;
  unsigned short fromnode, tonode, fromnet, tonet;
  unsigned short flags, cost;
  char datetime[20];
  unsigned short fromzone, frompoint, tozone, topoint;
  unsigned long timefrom, timeto;
  char *toname, *fromname, *subj, *text;
};

//Fido-style *.Msg message

#pragma pack(1)

struct message
{
  char fromname[36], toname[36], subj[72], datetime[20];
  unsigned short timesread, tonode, fromnode, cost;
  unsigned short fromnet, tonet;
//  unsigned short tozone,fromzone,topoint,frompoint;
  unsigned long timefrom, timeto;
  unsigned short replyto, flags, nextreply;
  char *text;
};

// Squish-style areas definitions

struct sqdfile
{
  unsigned short len, reserved1;
  unsigned long nummsg, highmsg, skipmsg, highwater, uid;
  char base[80];
  long first, last, firstf, lastf, endf;
  unsigned long maxmsg;
  unsigned short keepdays, szsqhdr;
  char reserved2[124];
};

struct sqdmshead
{
  unsigned long ident;
  long next, prev;
  unsigned long frlength, msglength, clen;
  unsigned short frametype, reserved;
  unsigned short flags, flags2;
  char fromname[36], toname[36], subj[72];
  unsigned short fromzone, fromnet, fromnode, frompoint;
  unsigned short tozone, tonet, tonode, topoint;
  unsigned long timefrom, timeto;
  unsigned short resflags;
  unsigned long replyto, nextreply[10];
  char datetime[20];
  char *text;
};

struct sqifile
{
  long offset;
  unsigned long umsgid, hash;
};

struct sqlfile
{
  unsigned long lastread;
};

struct pointers
{
  unsigned long ident, next, prev, frlength, msglength, clen;
  unsigned short frametype, reserved;
};

struct sqdhandle
{
  short sqd, sqi, sql, sqb, sqr, dupes;
};

// Chains and chain elements

struct myaddr
{
  unsigned short zone, net, node, point;
  char domain[8];
  unsigned short numaka, rdonly, passive, deny;
  struct myaddr *next;
};

struct addrchain
{
  struct myaddr *chain, *last;
  unsigned short numelem;
};

struct sysname
{
  char name[36], persarea[arealength], templ[(DirSize + 1)];
  unsigned short where, found, move, exact;
  struct myaddr address;
  struct sysname *next;
};

struct namechain
{
  struct sysname *chain, *last;
  unsigned short numelem;
};

struct uplname
{
  char upname[36], persarea[arealength], echolist[(DirSize + 1)], uppass[72];
  struct myaddr upaddr, myaka;
  unsigned short where, found, wild, touch, touched;
  struct uplname *next;
};

struct link
{
  struct myaddr address;
  unsigned short create, boxes, hold, style, autoadd, days, fake, hide,
    addarc, nokrep, noforward, written, manager, boxstyle, rules;
  long pktsize, arcsize, mask, sent;
  char packer[10], echopass[72], group[53], rog[53], name[36], password[9],
    crmask[arealength + 1];
  struct link *next;
};

struct linkchain
{
  struct link *chain, *last;
  unsigned short numelem;
};

struct shortaddr
{
  unsigned short net, node, hide;
  struct shortaddr *next;
};

struct shortchain
{
  struct shortaddr *chain, *last;
  unsigned short numelem;
};


struct route
{
  struct addrchain list;
  struct route *next;
};

struct zgate
{
  struct myaddr address;
  struct shortchain zseen;
  unsigned short numseen;
  struct zgate *next;
};

struct manname
{
  char name[36];
  struct manname *next;
};

struct incl
{
  char name[DirSize + 1];
  unsigned long stamp;
  char group;     //not for Include, but for group descriptions
  struct incl *next;
};

struct area
{
  char areaname[arealength], areafp[DirSize], group;
  unsigned short type, days, messages, skipmsg, passthr, numlinks, touched,
    linktype, duptouch, open, logged, killd, killd_modified, saveci;
  unsigned dupes;
  long curindex, pooloffs, poollen, delday;
  struct myaddr myaka;
  struct shortchain seenby;
  struct sqdhandle sqd;
  struct addrchain links;
};

struct areaindex
{
  char areaname[arealength];
  long areaoffs, descoffs, tossed;
  short scanned, type;
  unsigned short toss, sent, dupes, desclen;
  char group;
};

struct alists
{
  struct areaindex *alist;
  short numlists;
  struct alists *next;
};

struct dngate
{
  struct myaddr from, to, aka;
  unsigned short group, changes;
  char origin[72], where[41];
  struct dngate *next;
};

struct msglink
{
  short number;
  unsigned long crc;
};

struct pktname
{
  char name[(DirSize + 1)];
  unsigned long time;
  short where;
  struct pktname *next;
};

struct fwdrule
{
  char name[36];
  struct myaddr match, target;
  unsigned short exact, byaddr;
  struct fwdrule *next;
};

struct bincfg
{
  unsigned long maindt, packdt, areadt;
  // char version[20]; // This is original value.
  char version[40];   // Changed by Voland to handle OS names like
  // freebsd2.2.6-386.
  char packcfg[(DirSize + 1)], areacfg[(DirSize + 1)], logfile[(DirSize + 1)],
    swapfile[(DirSize + 1)], route[(DirSize + 1)], outbound[(DirSize + 1)],
    origin[81], areapath[(DirSize + 1)], defarc[10], boxes[(DirSize + 1)],
    workdir[(DirSize + 1)], post[(DirSize + 1)], help[(DirSize + 1)],
    areadesc[DirSize + 1], areapool[DirSize + 1], mandesc[DirSize + 1],
    subj[72], mantmpl[(DirSize + 1)], reptmpl[(DirSize + 1)], hides[27],
    killtempl[(DirSize + 1)], netin[arealength + 1], netout[arealength + 1],
    netserv[arealength + 1], creatfile[DirSize + 1], busy[DirSize + 1],
    fwdstr[BufSize + 1], guard, shablon[DirSize + 1], edlist[DirSize + 1],
    manfrom[36], manffrom[36], badtmpl[DirSize + 1], badlog[DirSize + 1],
    bshablon[DirSize + 1], unname[DirSize + 1], workout[DirSize + 1],
    netsem[DirSize + 1], echosem[DirSize + 1], sbu[DirSize + 1],
    sbp[DirSize + 1], saua[DirSize + 1], sau[DirSize + 1], sap[DirSize + 1],
    defdomain[8], dalist[DirSize + 1];
  long pktsize, mansize, arcsize, minunp, mintoss;
  unsigned short bunarc, bufsize, killdupes, loglevel, isnode, renbad, method,
    numaddr, numts, numnames, numseenby, numgates, numdg, numlink, numinbound,
    secure, create, swapping, swaptype, delinfo, addarc, quiet, autosend,
    pack, linktype, killtr, stripattr, linklength, nummans, mankill, rescan,
    bpack, grof, delkl, video, killorph, hiderestr, sort, manlen, safe,
    numincl, nofresh, scanall, lookpath, analyse, ktrash, netdupes, netlink,
    maxnet, numupl, vsleep, passpurge, delfiles, locked, savelog, trunc,
    numsem, fintl, kamikadze, sortarc, numbladv, killadd, fixaddr, binkdlo,
    untkill, delproc, gric, tossstat, sendstat, numgr, showall, createbad,
    savepath, nummans2, selfaka, asavail, asfull, carbnet, stripext, echoonly,
    single, fastlink, linkverb, transl, levels, rescdays, longfp, setloc,
    dnccsy, logoutl, boxstyle, test, dncbsy, dropbad, setdir, passci,
    rulesent, nocarbon, deldays, nrenum, strip2fts, dnsipkt, dncloselog,
    purgelr, dncfd, fixro, dnutid;
  unsigned maxdupes;
  struct area defarea;
  struct shortaddr delseen;
  struct incl *incl;
  struct addrchain address;
  struct addrchain seenby;
  struct addrchain tinysb;
  struct namechain myname;
  struct zgate *zonegate;
  struct dngate *dgate;
  struct linkchain links;
  struct manname *names;
  struct manname *names2;
  struct uplname *uplname;
  struct uplname *semaphore;
  struct pktname *inbound;
  struct uplname *bladv;
  struct incl *tgroup;
  struct fwdrule *fwdrules;
  struct manname *fwdskip;
};

struct packer
{
  char name[10], ext[4];
  char add[(CSSize + 1)], extr[(CSSize + 1)];
  char sign[10];
  short addbat, extrbat;
  long signoffs;
};

struct packet
{
  char *name;
  struct myaddr fromaddr, outaddr;
  short opened, handle, touched, filled, sent, file, gated;
  char password[8];
  struct packet *next;
};

struct kludge
{
  char *str;
  short left;
  struct kludge *next;
};

struct pool
{
  char *fullname, *shortname, *type;
  struct pool *next;
};

#if HAVE_CONFIG_H

/*
 * Here we define a set of platform-dependant function prototypes
 * and aliases.
 */

// need port
#if ! defined( HAVE_STRUPR)
extern const char *strupr (const char *);
#endif

#if ! defined( HAVE_STRSTR)
#error Need strstr to be realized!
#endif

#if ! defined( HAVE_FILELENGTH)
extern long filelength (int fhandle);
#endif

#if ! defined( HAVE_STRICMP)
#if HAVE_STRCASECMP
#define stricmp strcasecmp
#else
#error There is no neither stricmp nor strcasecmp
#endif
#endif

#if ! defined( HAVE_STRNICMP)
#if HAVE_STRNCASECMP
#define strnicmp strncasecmp
#else
#error There is no neither strnicmp nor strncasecmp
#endif
#endif

#if ! defined( HAVE_CPRINTF)
#define cprintf printf
#endif

#endif // HAVE_CONFIG_H

// needport to here

#endif // ParToss
