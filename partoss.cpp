// MaxiM: find_t _fullpath

#include "partoss.h"
#include "globfunc.h"

#include "lowlevel.h"
#include "morfiles.h"
#include "errors.h"
#include "arealias.h"
#include "version.h"
#include "rebuild.h"
#include "partsqd.h"
#include "environ.h"
#include "partset.h"
#include "partserv.h"
#include "scanbase.h"
#include "handyman.h"
#include "attach.h"
#include "killold.h"
#include "partpost.h"
#include "netfwd.h"
#include "tossarcs.h"
#include "packets.h"
#include "chains.h"

/***ash  Use wlink OPTION STACK instead of _stklen
#ifdef __DOS__
unsigned _stklen=16384;
#else
unsigned _stklen=65536;
#endif
*/

char version[MAX_VERSIONLEN] = { 0 };
char *duotrice = "0123456789abcdefghijklmnopqrstuv";
char *indicator = "|/-\\";
short indpos = 0;

int hhandle, hdst, holdh;
int hhandle2, hdst2, holdh2;

char *arcsh[7] = { "*.mo?", "*.tu?", "*.we?", "*.th?", "*.fr?", "*.sa?", "*.su?" };
char confile[(DirSize + 1)];

char *keys[] = { "When", "Area", "From", "To", "Subj", "Flags", "TearLine", "Origin",
  "Text"
};

char *days[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
char *months[12] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
  "Nov", "Dec"
};
char *flags[] = { "Pvt", "Cra", "Att", "K/S", "Hld", "Dir", "Frq", "Rrq", "Arq", "Urq",
  "IMM", "KFS", "TFS"
};

unsigned short _openfd[MAX_HANDLES + 1];
unsigned char newHandleArray[MAX_HANDLES + 1];
unsigned char *oldArray = NULL;
unsigned short hcnt = 0, oldcnt = 0, afh = 0, cfh = 0, nfh = 0;

char ppassword[9];

unsigned long firstkey = 0, secondkey = 0, firsttest = 0xffffffffL, secondtest = 0xffffffffL;
unsigned long namehash = 0, namecrc = 0, addrhash = 0, addrcrc = 0;
unsigned short ver = 0, indv = 0;

short isdupe = 0, create = 0, mustcopy = 0, addorig = 0, unclosed =
  0, lineno[4], noreport = 0, forsed = 0, fake = 0, hide = 0;
unsigned short dupecur = 0, dupemax = 0, local = 0, netmail = 0, flags2 = 0, lkludnum = 0, lkludlen = 0, gkludlen = 0;
unsigned long msgcrc32 = 0, smsgcrc32 = 0, *dupbuf = NULL, mflags = 0;
unsigned short szpacker = 0, szmessage = 0, szchar = 0, szlong =
  0, sztwoplus = 0, szpackmess = 0, szpacket = 0, szmyaddr = 0, szincl = 0;
unsigned short szbincfg = 0, szshortaddr = 0, szsysname = 0, szzgate =
  0, szarea = 0, szareaindex = 0, szlink = 0, szsqdfile = 0;
unsigned short szpktname = 0, szkludge = 0, szroute = 0;
unsigned short tottoss = 0, loctoss = 0, totsent = 0, locsent = 0, totdupes =
  0, totbad = 0, totpers = 0, numlf = 0, rehwm = 0;

short pkt = 0, setf = 0, numpack = 0, dupreserv = 0, logfile = 0, tempsrv = 0, thelp = 0, crtrep = 0, prttemp = 0;
long pctrlpos = 0, ptolen = 0, pfromlen = 0, psubjlen = 0, ptextlen = 0, pmsglen = 0, pbigmess = 0, pcmsglen = 0;
long sctrlpos = 0, stolen = 0, sfromlen = 0, ssubjlen = 0, stextlen = 0, smsglen = 0, sbigmess = 0, scmsglen = 0;
long mctrlpos = 0, mtolen = 0, mfromlen = 0, msubjlen = 0, mtextlen = 0, mmsglen = 0, mbigmess = 0, rmbigmess = 0;
short mode = 0, quiet = 0, secure = 0, statistic = 0, ptnoscan = 0, good =
  0, pgood = 0, writes = 0, wipearea = 0, posting = 0, diskfull = 0, arealock;
short nummsg = 0, endmsg = 0, temppkt = 0, tempsqd = 0, tempmsg = 0, badarea =
  0, mustlog = 0, alog = 0, blog = 0, wassend = 0, badtype = 0;
short endinput[4], endblock[4], endstring[4], numcr[4], toklen = 0, needout = 0, fatmode = 0;
short mainset = 0, areaset = 0, areandx = 0, areadesc = 0, areapool =
  0, arcset = 0, compset = 0, packset = 0, linkset = 0, numarea = 0, pos = 0, arealen = 0, ttempl = 0;
short arealenold = 0;
short badlocked = 0, dupelocked = 0, mustdie, maxtaglen = 0, globbad = 0;
unsigned short fmax = 0, buflen = 0, pcurpos = 0, scurpos = 0, both = 0, rescan = 0, carea = 0, linktype = 0;
unsigned short pkludnum = 0, skludnum = 0, mkludnum = 0, pkludlen = 0, skludlen = 0, mkludlen = 0;
unsigned curspos[4], curtpos[4], maxpos = 0, maxstr[4], maxstr2[4], maxlen[4];
long pointer = 0, poffset = 0, soffset = 0, ndxlen = 0, times = 0, arclen = 0, globold = 0, globnew = 0;
unsigned long *msgid = NULL, *reply = NULL;
unsigned long arctime = 0, gstamp = 0;
time_t sftime;
struct tm tmt;

char filemsg[(DirSize + 1)], inpath[(DirSize + 1)], outpath[(DirSize + 1)], servpath[(DirSize + 1)], strtimes[9];
char *pktbuf = NULL, *sqdbuf = NULL, *sbuffer[4], *string = NULL, *token = NULL, *point = NULL, tstrtime[40];
char curarea[arealength], rcurarea[arealength], oldarea[arealength], tarea[arealength], defarc[10];
char areasbbs[(DirSize + 1)], mainconf[(DirSize + 1)], echolog[(DirSize + 1)],
  echologt[(DirSize + 1)], areafile[(DirSize + 1)], arealist[(DirSize + 1)],
  outbound[(DirSize + 1)], ftstime[20], cfname[DirSize + 1],
  blogname[DirSize + 1], homedir[DirSize + 1], logfilename[DirSize + 1];
short logfileok = 0;
char logout[BufSize + 1], *tail = NULL, *tbuffer = NULL, temppktn[DirSize + 1], tempsqdn[DirSize + 1];
char gltoname[36], glfromname[36], glsubj[72], errname[DirSize + 1];
char curmsgid[9], curreply[9];
char bsyname[DirSize + 1], bsynamef[DirSize + 1], crtreprt[DirSize + 1];
char pttmpl[DirSize + 1];

struct packmess bufpkt, bufsqd, bufmess, *buftemp = NULL, *buftemps = NULL;
struct message bufmsg;
struct sqdfile sqbuf;
struct sqdmshead sqhead, head;
struct sqifile sqibuf;
struct tm ftm;
struct myaddr pktaddr, node, mfnode, ufnode, rnode, defaddr, caddr;
struct myaddr *tsend = NULL;
struct addrchain ptosend, stosend;
struct area *newarea = NULL, *badmess = NULL, *dupes = NULL, *persarea = NULL;
struct bincfg bcfg;
struct packer pack;
struct packet *pkts = NULL, *tpack = NULL;
struct pktname *fpkt = NULL, *apkt = NULL;
struct shortchain psnb, ppath, ssnb, spath, tnsnb;
struct kludge *pckludge = NULL, *sckludge = NULL, *mckludge = NULL;
struct route *roulist = NULL, *direct = NULL, *notouch = NULL;
struct incl *tincl = NULL, *ttincl = NULL;

struct alists *rlist = NULL, *tlist = NULL, *ttlist = NULL;
unsigned short gran = 0, bufsqi = 0;
struct sqifile *nindex = NULL, *pindex = NULL, *bindex = NULL, *dindex = NULL;
short edlist = 0;
short gheadclen = 0;
short gheadgarb = 0;
short addrfake = 0;
short gpers = 0;
short pcreate = 0;
short glmove;
short rescandays;
short logdebug = 0;
short lich = 0;

#ifdef __NT__
// short findattr=0x827;
short findattr = 0;
#else
// short findattr=0x27;
short findattr = 0;
#endif
short setdir = 0;
short fullscan = 0;
short nowpurge = 0;
struct myaddr pfrom, pto;
unsigned long curhash = 0;

struct pool *glpool = NULL;

list < areaalias > areaaliaslist;

#if defined (__linux__) || defined (__FreeBSD__)
long int umask_val;
char lockname[DirSize + 1];
short lck;
#endif

int main(int argc, char **argv)
{
#ifdef __NT__
  SetConsoleTitle("Parma Tosser");
#endif
  mode = 0;
  mustlog = 0;
  mustdie = 1;
  nummsg = 1;
  forsed = 0;
  bufsqi = 256;
  short i, asis, tpost = 0, sinv = 0, pinv = 0, tmode = 0, killlog = 0, fastlink = 0;
  long loglen = 0;
  struct route *trou = NULL, *ttrou = NULL;
  struct shortaddr *tsnb = NULL, *ttsnb = NULL;
  struct zgate *zg = NULL, *zgt = NULL;
  struct manname *tmname = NULL, *ttmname = NULL;

#if HAVE_OPENDIR
  DIR *dirp;
  struct dirent *direntry;
#else
  short olds = 0;
  struct find_t fblk;
#endif /* HAVE_OPENDIR */
  struct link *blink = NULL;
  char hfile[DirSize + 1], badname[DirSize + 1], tmpname[DirSize + 1], *temp = NULL;

//  init_SPAWNO(NULL,SWAP_DISK);
  moreHandles();
  szpacker = sizeof(struct packer);
  szmessage = sizeof(struct message);
  szchar = sizeof(char *);
  szlong = sizeof(long);
  sztwoplus = sizeof(struct twoplus);
  szpackmess = sizeof(struct packmess);
  szpacket = sizeof(struct packet);
  szmyaddr = sizeof(struct myaddr);
  szbincfg = sizeof(struct bincfg);
  szshortaddr = sizeof(struct shortaddr);
  szsysname = sizeof(struct sysname);
  szzgate = sizeof(struct zgate);
  szarea = sizeof(struct area);
  szareaindex = sizeof(struct areaindex);
  szlink = sizeof(struct link);
  szsqdfile = sizeof(struct sqdfile);
  szpktname = sizeof(struct pktname);
  szkludge = sizeof(struct kludge);
  szroute = sizeof(struct route);
  szincl = sizeof(struct incl);
//  ccprintf("Memory - %lu\r\n",coreleft());
// The following #if added by Voland
//#ifdef HAVE__FULLPATH
//  _fullpath(homedir,argv[0],DirSize);
//#elif HAVE_REALPATH


#if defined (__linux__) || defined (__FreeBSD__)
  realpath(argv[0], homedir);
#else
  _fullpath(homedir, argv[0], DirSize);
#endif


//#else
//#error There is no way to resolve full pathname!
//#endif
  temp = strrchr(homedir, DIRSEP[0]);   // Changed by Voland.
  if(temp)
    *(temp + 1) = 0;
  else
    memset(homedir, 0, DirSize + 1);

  printversion();

//  ccprintf("The Parma Tosser has started from directory\r\n  %s\r\n",homedir);
  ver = (unsigned short)dvtest();
  if((dupreserv = (short)open(NULL_DEV, O_WRONLY)) == -1)
  {
    perror("open/create error");
    mystrncpy(errname, NULL_DEV, DirSize);
    errexit(2, __FILE__, __LINE__);
  }
  memset(echolog, 0, (DirSize + 1));
  mystrncpy(mainconf, homedir, DirSize);
  mystrncat(mainconf, (char *)"partoss.cfg", 16, DirSize);
  if(bcfg.workdir[0])
  {
    mystrncpy(crtreprt, bcfg.workdir, DirSize);
    mystrncpy(pttmpl, bcfg.workdir, DirSize);
#if defined (__linux__) || defined (__FreeBSD__)
    mystrncpy(lockname, bcfg.workdir, DirSize);
#endif
  }
  else
  {
    mystrncpy(crtreprt, homedir, DirSize);
    mystrncpy(pttmpl, homedir, DirSize);
#if defined (__linux__) || defined (__FreeBSD__)
    mystrncpy(lockname, homedir, DirSize);
#endif
  }
  mystrncat(crtreprt, (char *)"crtreprt.$$$", 16, DirSize);
  mystrncat(pttmpl, (char *)"parttmpl.$$$", 16, DirSize);
#if defined (__linux__) || defined (__FreeBSD__)
  mystrncat(lockname, (char *)"partoss.pid", 16, DirSize);
#endif
  if(argc == 1)
    errexit(10, __FILE__, __LINE__);
  blog = secure = 0;
  short hand_argv_number = 0;

  for(i = 1; i < argc; i++)
  {
    if(argv[i][0] == '-' && !(mode & 1024))
    {
      switch (argv[i][1])
      {
      case '8':                // 8.3 mode for echoareas
        fatmode = 1;
        break;
      case 'a':
      case 'A':                // смена файла Areas.bbs
        mystrncpy(areasbbs, &argv[i][2], DirSize);
        break;
/*
        case 'b': case 'B':
          mystrncpy(blogname,&argv[i][2],DirSize);
          if((blog=sopen(blogname,O_RDWR|O_BINARY,SH_DENYWR))<=0)
            if((blog=sopen(blogname,O_RDWR|O_BINARY|O_CREAT,SH_DENYWR,S_IRWXU|S_IRWXG|S_IRWXO))<=0)
             {
              mystrncpy(errname,blogname,DirSize);
              errexit(2,__FILE__,__LINE__);
             }
          break;
*/
      case 'c':
      case 'C':                // смена файла конфигуpации
        mystrncpy(mainconf, &argv[i][2], DirSize);
        break;
      case 'd':
      case 'D':                // отладочный уровень лога
        logdebug = 1;
        break;
      case 'k':
      case 'K':                // смена файла Echotoss.log и его удаление
        killlog = 1;
      case 'f':
      case 'F':                // смена файла Echotoss.log
        mystrncpy(echolog, &argv[i][2], DirSize);
        break;
      case 'l':
      case 'L':
      case 'o':
      case 'O':                // BinkleyTerm only
        ccprintf("BinkleyTerm mode keys are not supported (%s)\r\n", argv[i]);
        break;
      case 'q':
      case 'Q':                // Quiet mode
        quiet = 1;
        break;
      case 's':
      case 'S':                // Scan all messages
        fullscan = 1;
        break;
      case 't':
      case 'T':                // Toggle secure mode
        secure = 1;
        break;
      case 'v':
      case 'V':                // Toggle statistic mode
        statistic = !statistic;
        break;
      case 'w':
      case 'W':
        mustdie = 0;
        break;
      case 'z':
      case 'Z':                // Don't scan passthru areas
        ptnoscan = 1;
        break;
      }
    }
    else
    {
      if(stricmp(argv[i], "IN") == 0)
      {
        mode |= 1;
        sinv = pinv = 1;
      }
      else if(stricmp(argv[i], "OUT") == 0)
        mode |= 2;
      else if(stricmp(argv[i], "RESCAN") == 0)
        mode |= 4;
      else if((stricmp(argv[i], "SEND") == 0) || (stricmp(argv[i], "SQUASH") == 0) || (stricmp(argv[i], "PACK") == 0))
        mode |= 8;
      else if(strnicmp(argv[i], "LINK", 4) == 0)
      {
        mode |= 16;
        if(toupper(argv[i][4]) == 'F')
          fastlink = 1;
      }
      else if(strnicmp(argv[i], "POST", 4) == 0)
      {
        mode |= 32;
        if(toupper(argv[i][4]) == 'F')
          forsed = 1;
        if(toupper(argv[i][4]) == 'D')
          forsed = 2;
      }
      else if(stricmp(argv[i], "SERV") == 0)
      {
        mode |= 64;
        sinv = 0;
      }
      else if(stricmp(argv[i], "PURGE") == 0)
      {
        mode |= 128;
        pinv = 0;
      }
      else if(stricmp(argv[i], "REBUILD") == 0 || stricmp(argv[i], "FIX") == 0)
        mode |= 256;
      else if(stricmp(argv[i], "KILL") == 0)
        mode |= 512;
      else if(strnicmp(argv[i], "HAND", 4) == 0)
      {
        mode |= 1024;
        hand_argv_number = i;
      }
      else if(strnicmp(argv[i], "BAD", 3) == 0)
        mode |= 2048;
      else if(strnicmp(argv[i], "UNTOSS", 6) == 0)
        mode |= 4096;
      else if(strnicmp(argv[i], "RELINK", 6) == 0)
        mode |= 8192;
      else
        parseaddr(argv[i], &rnode, (short)strlen(argv[i]));
    }
  }
  if(!mode)
    errexit(10, __FILE__, __LINE__);
  newarea = (struct area *)myalloc(szarea, __FILE__, __LINE__);
  memset(newarea, 0, szarea);
  nindex = (struct sqifile *)myalloc((12 * bufsqi), __FILE__, __LINE__);
  persarea = (struct area *)myalloc(szarea, __FILE__, __LINE__);
  memset(persarea, 0, szarea);
  pindex = (struct sqifile *)myalloc((12 * bufsqi), __FILE__, __LINE__);
  sbuffer[0] = (char *)myalloc(4096, __FILE__, __LINE__);
  sbuffer[2] = (char *)myalloc(1024, __FILE__, __LINE__);
  sbuffer[3] = (char *)myalloc(1024, __FILE__, __LINE__);
  rlist = (struct alists *)myalloc(sizeof(struct alists), __FILE__, __LINE__);
  memset(&pktaddr, 0, szmyaddr);
  readsetup();
  if(mode & 2048)
    bcfg.scanall = 1;
  if(fastlink)
    bcfg.fastlink = 1;
  if(rnode.zone | rnode.net | rnode.node | rnode.point)
  {
    if(!rnode.zone)
      rnode.zone = bcfg.address.chain->zone;
    if(!rnode.net)
      rnode.net = bcfg.address.chain->net;
    if(!rnode.node)
      rnode.node = bcfg.address.chain->node;
//    if(!rnode.point)
//      rnode.point=bcfg.address.chain->point;
  }
  if(secure)
    bcfg.secure = !bcfg.secure;
  buflen = bcfg.bufsize;
  tottoss = totsent = 0;
  pktbuf = (char *)myalloc(buflen, __FILE__, __LINE__);
  sqdbuf = (char *)myalloc(buflen, __FILE__, __LINE__);
  if(bcfg.maxdupes)
    dupbuf = (unsigned long *)myalloc((szlong * bcfg.maxdupes), __FILE__, __LINE__);
//  ccprintf("Allocated space for %u dupe entries\r\n",bcfg.defarea.dupes);
  if(bcfg.loglevel)
  {
    addhome(logfilename, bcfg.logfile);
#if HAVE_SOPEN
// Why so strange way of opening logfile?
// O_RDWR|O_BINARY|O_APPEND|O_CREAT should be enough!
    if((logfile = (short)sopen(logfilename, O_RDWR | O_BINARY, SH_DENYNO)) == -1)
      if((logfile =
          (short)sopen(logfilename, O_RDWR | O_BINARY | O_CREAT, SH_DENYNO, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
      {
        mystrncpy(errname, logfilename, DirSize);
        logfileok = 0;
        errexit(2, __FILE__, __LINE__);
      }
    lseek(logfile, 0, SEEK_END);
#else
// Perm. mode (S_I*) here must be changed to use value, got from
// configuration. I.e. it must be possible for user to define his
// own mode for the logfile.
    if((logfile =
        open(logfilename,
             O_WRONLY | O_BINARY | O_CREAT | O_APPEND | O_EXLOCK, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1)
    {
      mystrncpy(errname, logfilename, DirSize);
      logfileok = 0;
      errexit(2, __FILE__, __LINE__);
    }
#endif
    logfileok = 1;
    sprintf(logout, "Begin, ParToss %s", version);
    logwrite(1, 1);
    sprintf(logout, "Executed: ");
    for(i = 0; i < argc; i++)
    {
      mystrncat(logout, argv[i], (unsigned short)(strlen(argv[i]) + 5), DirSize);
      mystrncat(logout, " ", 5, DirSize);
    }
    logwrite(1, 9);
  }
  mystrncpy(hfile, bcfg.workdir, DirSize);
  mystrncat(hfile, "keytempl.$$$", DirSize, DirSize);
#if HAVE_SOPEN
  if((ttempl = (short)sopen(hfile, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
#else
  if((ttempl = (short)open(hfile, O_RDWR | O_BINARY | O_CREAT | O_EXLOCK, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1)
#endif
  {
    mystrncpy(errname, hfile, DirSize);
    errexit(2, __FILE__, __LINE__);
  }
  mystrncpy(temppktn, bcfg.workdir, DirSize);
  mystrncat(temppktn, "temppkt.$$$", 16, DirSize);
#if HAVE_SOPEN
  if((temppkt = (short)sopen(temppktn, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
#else
  if((temppkt =
      (short)open(temppktn, O_RDWR | O_BINARY | O_CREAT | O_EXLOCK, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1)
#endif
  {
    mystrncpy(errname, temppktn, DirSize);
    errexit(2, __FILE__, __LINE__);
  }
  if(echolog[0])
  {
#if HAVE_SOPEN
    alog = (short)sopen(echolog, O_RDWR | O_BINARY, SH_DENYNO);
#else
    alog = (short)open(echolog, O_RDWR | O_BINARY);
#endif
    if(alog == -1)
    {
      if(mode & 2081)
      {
#if HAVE_SOPEN
        if((alog = (short)sopen(echolog, O_RDWR | O_BINARY | O_CREAT, SH_DENYNO, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
#else
        if((alog =
            (short)open(echolog, O_RDWR | O_BINARY | O_CREAT | O_EXLOCK, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1)
#endif
        {
          mystrncpy(errname, echolog, DirSize);
          errexit(2, __FILE__, __LINE__);
        }
        mustlog = 1;
      }
      else
        alog = 0;
    }
    else
      mustlog = 1;
  }
  if(indv)
    ccprintf("\r\nDesQView version %d.%d detected\r\n", (int)((ver >> 8) & 0xff), (int)(ver & 0xff));
  i = 0;
  i |= cfgexist(bcfg.post);
  i |= cfgexist(bcfg.help);
  i |= cfgexist(bcfg.mantmpl);
  i |= cfgexist(bcfg.reptmpl);
  if(i)
  {
    sprintf(logout, "Parma Tosser may not work correctly!");
    logwrite(1, 1);
    ccprintf("\r\n%s\r\n", logout);
  }
#if defined(__DOS__) && !defined(M_I386)
  sprintf(logout, "You have %d file handles available", hcnt);
  logwrite(1, 3);
  ccprintf("\r\n%s\r\n", logout);
#endif
  mystrncpy(badname, outbound, DirSize);
// The following #if added by Voland.
#if HAVE_OPENDIR
  dirp = opendir(badname);
  if(dirp)
  {
    while((direntry = readdir(dirp)) != NULL)
    {
      if((strcmp(direntry->d_name, ".") == 0) || (strcmp(direntry->d_name, "..") == 0))
      {
        continue;
      }
      if(fnmatch(OUT_MASK, direntry->d_name, 0) == 0)
      {
        mystrncpy(tmpname, outbound, DirSize);
        mystrncat(tmpname, direntry->d_name, 16, DirSize);
        unlink(tmpname);
      }
    }
    // Here we must check for a result unless CLOSEDIR_VOID defined.
    closedir(dirp);
  }
#else /* HAVE_OPENDIR */
  mystrncat(badname, OUT_EXT, 16, DirSize);
  olds = (short)_dos_findfirst(badname, findattr, &fblk);
  while(olds == 0)
  {
    if(fblk.size == 0)
    {
      mystrncpy(tmpname, outbound, DirSize);
      mystrncat(tmpname, fblk.name, 16, DirSize);
      unlink(tmpname);
    }
    olds = (short)_dos_findnext(&fblk);
  }
  _dos_findclose(&fblk); /***ash***/
#endif /* HAVE_OPENDIR */
  if(mode & 8192)
    relink();
  if(mode & 4096)
    scanbase(echolog, 5);
  if(mode & 2048)
    tossbad();
  if(mode & 1024)
  {
    int new_argc = argc - hand_argv_number + 1;
    int new_argv_i;
    char **new_argv = (char **)malloc(new_argc * sizeof(char *));

    new_argv[0] = argv[0];
    for(new_argv_i = hand_argv_number; new_argv_i < argc; new_argv_i++)
    {
      //printf("%i -> %i\n",new_argv_i,new_argv_i-hand_argv_number+1);
      new_argv[new_argv_i - hand_argv_number + 1] = argv[new_argv_i];
    }
    handyman((short)new_argc, new_argv);
    makeattach(0);
  }
  if(mode & 512)
    killold();
  if(mode & 128 && pinv)
  {
    closesqd(persarea, 1);
    scanbase(echolog, 3);
    opensqd(persarea, pindex, 0, 1);
  }
  if(mode & 64 && sinv)
    server();
  if(mode & 32)
    tpost = poster(1);
  setbadarea();
  both = rescan = 0;
  tmode = mode;
  mode &= 0x0f;
  switch (mode)
  {
  case 1:
  case 9:                      // in
    tossarcs();
    break;
  case 2:
  case 10:                     // out
    if(!(tmode & 1632))
    {
      closesqd(badmess, 0);
      if(!bcfg.killdupes)
        closesqd(dupes, 0);
//         closesqd(persarea,1);
      closesqd(newarea, 1);
      if(mustlog >= 0)
        scanbase(echolog, 1);
      else
        scanbase(echologt, 1);
    }
    break;
  case 3:
  case 11:                     // in out
    both = 1;
    tossarcs();
    break;
  case 4:
  case 5:
  case 6:
  case 7:
  case 12:
  case 13:
  case 14:
  case 15:
    rescan = 1;
    scanbase(echolog, 1);
    break;
  }
  closesqd(badmess, 0);
  if(!bcfg.killdupes)
    closesqd(dupes, 0);
  closesqd(persarea, 1);
  closesqd(newarea, 1);
  mode = tmode;
  if(mode & 8)
  {
    createpkts();
    makeattach(0);
    delpkts();
  }
  if(mode & 128 && !pinv)
  {
    if(mustlog >= 0)
      scanbase(echolog, 3);
    else
      scanbase(echologt, 3);
  }
  if(mode & 64 && !sinv)
    server();
  if(mode & 16)
  {
    if(mustlog >= 0)
      scanbase(echolog, 2);
    else
      scanbase(echologt, 2);
  }
  killpkts();
  if(access(crtreprt, 0) == 0)
  {
    tmode = mode;
    mode &= 16;
    tpost = poster(0);
    mode = tmode;
    mode &= 32;
    if(tpost >= 0)
      unlink(crtreprt);
  }
  if(mode & 1632)               // Hand or Kill or Serv or Post
  {
    if(!(mode & 32) || (tpost > 0))
    {
      tmode = mode;
      mode &= 0x0f;
      if(mode & 2)
      {
        closesqd(newarea, 1);
        if((badmess == NULL) || (badmess->sqd.sqd) == 0)
          setbadarea();
//        bcfg.autosend=1;
        if(mustlog >= 0)
          scanbase(echolog, 1);
        else
          scanbase(echologt, 1);
      }
      mode = tmode;
    }
  }
  if(bcfg.pack && needout)
  {
    tmode = mode;
    mode &= 0x0f;
    i = alog;
    alog = 0;
    scanbase(bcfg.netout, 1);
    alog = i;
    mode = tmode;
  }
  loglen = (alog ? filelength(alog) : 0);
  if(mustlog)
    cclose(&alog, __FILE__, __LINE__);
  if(mustlog == -1 && !bcfg.savelog)
    unlink(echologt);
  else if(((loglen == 0) || killlog) && echolog[0])
    unlink(echolog);
  if(bcfg.loglevel >= 4)
  {
    tlist = rlist;
    while(tlist)
    {
      for(i = 0; i < tlist->numlists; i++)
      {
        if(tlist->alist[i].type < 2)
        {
          if(tlist->alist[i].toss || tlist->alist[i].sent || tlist->alist[i].dupes)
          {
            asis = 0;
            sprintf(logout, "%s:", tlist->alist[i].areaname);
            if(tlist->alist[i].toss)
            {
              sprintf(areasbbs, " toss - %u", tlist->alist[i].toss);
              mystrncat(logout, areasbbs, DirSize, BufSize);
              if(bcfg.tossstat && tlist->alist[i].type == 1)
              {
                sprintf(areasbbs, " (%ld bytes)", tlist->alist[i].tossed);
                mystrncat(logout, areasbbs, DirSize, BufSize);
              }
              asis = 1;
            }
            if(tlist->alist[i].sent)
            {
              sprintf(areasbbs, "%s sent - %u", asis ? "," : "", tlist->alist[i].sent);
              mystrncat(logout, areasbbs, DirSize, BufSize);
              asis = 1;
            }
            if(tlist->alist[i].dupes)
            {
              sprintf(areasbbs, "%s dupes - %u", asis ? "," : "", tlist->alist[i].dupes);
              mystrncat(logout, areasbbs, DirSize, BufSize);
              asis = 1;
            }
            logwrite(1, 4);
          }
        }
      }
      tlist = tlist->next;
    }
  }
  tlist = rlist;
  while(tlist)
  {
    myfree((void **)&tlist->alist, __FILE__, __LINE__);
    ttlist = tlist->next;
    myfree((void **)&tlist, __FILE__, __LINE__);
    tlist = ttlist;
  }
  if(bcfg.sendstat)
  {
    blink = bcfg.links.chain;
    while(blink)
    {
      if(blink->sent)
      {
        sprintf(logout, "Sent to %u:%u/%u.%u - %ld bytes",
                blink->address.zone, blink->address.net, blink->address.node, blink->address.point, blink->sent);
        logwrite(1, 4);
      }
      blink = blink->next;
    }
  }
//  myfree((void **)&rlist,__FILE__,__LINE__);
  myfree((void **)&sqdbuf, __FILE__, __LINE__);
  myfree((void **)&pktbuf, __FILE__, __LINE__);
  closesqd(badmess, 0);
  myfree((void **)&(bindex), __FILE__, __LINE__);
  myfree((void **)&badmess, __FILE__, __LINE__);
  if(!bcfg.killdupes)
  {
    closesqd(dupes, 0);
    myfree((void **)&(dindex), __FILE__, __LINE__);
    myfree((void **)&dupes, __FILE__, __LINE__);
  }
  closesqd(persarea, 1);
  myfree((void **)&(pindex), __FILE__, __LINE__);
  myfree((void **)&persarea, __FILE__, __LINE__);
  closesqd(newarea, 1);
  myfree((void **)&(nindex), __FILE__, __LINE__);
  myfree((void **)&newarea, __FILE__, __LINE__);
  if(bcfg.maxdupes)
    myfree((void **)&dupbuf, __FILE__, __LINE__);
  trou = roulist;
  while(trou)
  {
    ttrou = trou->next;
    deladdr(&(trou->list));
    myfree((void **)&trou, __FILE__, __LINE__);
    trou = ttrou;
  }
  roulist = NULL;
  if(direct)
  {
    deladdr(&(direct->list));
    myfree((void **)&direct, __FILE__, __LINE__);
  }
  if(notouch)
  {
    deladdr(&(notouch->list));
    myfree((void **)&notouch, __FILE__, __LINE__);
  }
  deladdr(&(bcfg.tinysb));
  deladdr(&(bcfg.address));
  delname(&(bcfg.myname));
  fwdfree();
  deladdr(&(bcfg.seenby));
  zg = bcfg.zonegate;
  while(zg)
  {
    zgt = zg->next;
    tsnb = zg->zseen.chain;
    while(tsnb)
    {
      ttsnb = tsnb->next;
      myfree((void **)&tsnb, __FILE__, __LINE__);
      tsnb = ttsnb;
    }
    myfree((void **)&zg, __FILE__, __LINE__);
    zg = zgt;
  }
  bcfg.zonegate = NULL;
  tmname = bcfg.names;
  while(tmname)
  {
    ttmname = tmname->next;
    myfree((void **)&tmname, __FILE__, __LINE__);
    tmname = ttmname;
  }
  dellink(&(bcfg.links));
  tincl = bcfg.incl;
  while(tincl)
  {
    ttincl = tincl->next;
    myfree((void **)&tincl, __FILE__, __LINE__);
    tincl = ttincl;
  }
  bcfg.incl = NULL;
  myfree((void **)&sbuffer[3], __FILE__, __LINE__);
  myfree((void **)&sbuffer[2], __FILE__, __LINE__);
  myfree((void **)&sbuffer[0], __FILE__, __LINE__);
//  ccprintf("Memory - %lu\r\n",coreleft());
  errexit(0, __FILE__, __LINE__);
  return 0;
}

short cfgexist(char *cfgfile)
{
  char hfile[DirSize + 1];

  if(cfgfile[0])
  {
    addhome(hfile, cfgfile);
    if(access(hfile, 0) == -1)
    {
      sprintf(logout, "??? WARNING!!! File %s not found!", hfile);
      if(logfileok)
        logwrite(1, 1);
      ccprintf("\r\n%s", logout);
      return 1;
    }
    mystrncpy(cfgfile, hfile, DirSize);
  }
  return 0;
}

// #ifdef __OS2__
// void oblom(void)
//  {
//   sprintf(logout,"Exception occurs!");
//   if(logfileok)
//     logwrite(1,1);
//   ccprintf("\r\n%s\r\n",logout);
//   sprintf(logout,"Exception name: %s",__ThrowExceptionName());
//   if(logfileok)
//     logwrite(1,1);
//   ccprintf("\r\n%s\r\n",logout);
//   sprintf(logout,"Exception occurs in file: %s",__ThrowFileName());
//   if(logfileok)
//     logwrite(1,1);
//   ccprintf("\r\n%s\r\n",logout);
//   sprintf(logout,"Exception occurs in line: %s",__ThrowLineNumber());
//   if(logfileok)
//     logwrite(1,1);
//   ccprintf("\r\n%s\r\n",logout);
//   exit(0);
//   errexit(0,__FILE__,__LINE__);
//  }
// #endif

void addhome(char *dest, char *source)
{
  char *temp;

  temp = strrchr(source, DIRSEP[0]);
  if(temp == NULL)
  {
    mystrncpy(dest, homedir, DirSize);
    mystrncat(dest, source, DirSize, DirSize);
  }
  else
    mystrncpy(dest, source, DirSize);
}

#ifdef __DOS__
void _dos_findclose(void *)
{
}
void _grow_handles(unsigned w)
{
  if(w == 0)
    return;
}
#endif
