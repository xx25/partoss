// MaxiM: Ported, not changed

#include "partoss.h"
#include "globext.h"

#include "errors.h"
#include "lowlevel.h"
#include "morfiles.h"
#include "partsqd.h"

#if defined (__linux__) || defined (__FreeBSD__)
#include "locks.h"
#endif

void errexit(short error, char *file, unsigned short line)
{
  short retcode = 0, asis = 0;

/*  long bloglen=0;  */
  char hfile[DirSize + 1];

  switch (error)
  {
  case 0:
    retcode = 0;
    break;
  case 1:
    logprintf("!!! Memory allocation error");
    retcode = -1;
    break;

  case 2:
    logprintf("!!! File %s open/create error, OS error %d", errname, errno);
    retcode = -1;
    break;

  case 3:
#ifdef __DOS__
    logprintf("!!! SWAP error - not enough memory or disk space for swapping");
#else
    logprintf("!!! SPAWN error - not enough resources for run external progpam");
#endif
    retcode = -2;
    break;

  case 4:
    logprintf("!!! Internal program error, OS error %d", errno);
    retcode = -3;
    break;

  case 5:
    logprintf("!!! Unknown area name %s", errname);
    retcode = 11;
    break;

  case 6:
    logprintf("!!! Can't find file %s", errname);
    retcode = 10;
    break;

  case 7:
    logprintf("!!! Read/write error, OS error %d", errno);
    retcode = -1;
    break;

  case 8:
  case 9:
    logprintf("!!! Can't find %s", error == 8 ? "BadArea" : "DupeArea");
    retcode = 11;
    break;

  case 10:
    ccprintf("\r\nUsage:\r\n  ParToss [<key...>] <command...> [<node>],\r\n\r\n");
    ccprintf("Keys:  -c<filename> | -f<filename> | -q | -t\r\n");
    ccprintf("Commands:  In, Out, Pack, Send, Squash, Link, LinkF, Post, PostF, PostD,\r\n");
    ccprintf("           Purge, Kill, Serv, Hand, HandN, ReScan, Bad, ReLink, UnToss\r\n");
    ccprintf("Node - full or short 4-D FTN address\r\n\r\n");
    ccprintf("For further information about keys and commands read ParToss.Doc\r\n");
    retcode = 9;
    break;

  case 11:
    logprintf("!!! Write error (maybe disk full)");
    retcode = -1;
    break;

  case 12:
    logprintf("!!! Area %s damaged, use SQFix", rcurarea);
    retcode = 12;
    break;

  case 13:
    logprintf("!!! Error while file %s rename/move", errname);
    retcode = 13;
    break;

  case 14:
    logprintf("!!! It's seems that ParToss already ran");
    retcode = 14;
    break;

  case 15:
    logprintf("!!! Emergency exit - internal error");
    retcode = 15;
    break;
  }
  closesqd(newarea, 0);
  closesqd(persarea, 0);
  closesqd(badmess, 0);
  closesqd(dupes, 0);
  if(bsyname[0])
    unlink(bsyname);
  if(bsynamef[0])
    unlink(bsynamef);
  if(retcode && retcode != 9)
  {
    if(logfileok)
      logwrite(1, 1);
    ccprintf("%s\r\n", logout);
  }
  if(retcode < 0)
  {
    logprintf("!!! Error was encountered in line %u of source file %s", line, file);
    if(logfileok)
      logwrite(1, 1);
    ccprintf("%s\r\n", logout);
  }
  if(tottoss || totsent || totpers || totdupes || totbad)
  {
    asis = 0;
    logprintf("Total:");
    if(tottoss)
    {
      sprintf(areasbbs, " toss - %u", tottoss);
      mystrncat(logout, (char *)areasbbs, DirSize, BufSize);
      asis = 1;
    }
    if(totsent)
    {
      sprintf(areasbbs, "%s sent - %u", asis ? "," : "", totsent);
      mystrncat(logout, areasbbs, DirSize, BufSize);
      asis = 1;
    }
    if(totpers)
    {
      sprintf(areasbbs, "%s personal - %u", asis ? "," : "", totpers);
      mystrncat(logout, areasbbs, DirSize, BufSize);
      asis = 1;
    }
    if(totdupes)
    {
      sprintf(areasbbs, "%s dupes - %u", asis ? "," : "", totdupes);
      mystrncat(logout, areasbbs, DirSize, BufSize);
      asis = 1;
    }
    if(totbad)
    {
      sprintf(areasbbs, "%s bad - %u", asis ? "," : "", totbad);
      mystrncat(logout, areasbbs, DirSize, BufSize);
      asis = 1;
    }
    if(logfileok)
      logwrite(1, 1);
    ccprintf("\r\n%s\r\n", logout);
  }
  if(ttempl)
  {
    Close(ttempl);
    ttempl = 0;
    mystrncpy(hfile, bcfg.workdir, DirSize);
    mystrncat(hfile, "keytempl.$$$", DirSize, DirSize);
    unlink(hfile);
  }
  if(temppkt)
  {
    Close(temppkt);
    temppkt = 0;
    unlink(temppktn);
  }
  if(areaset)
  {
    Close(areaset);
    areaset = 0;
  }
#if defined (__linux__) || defined (__FreeBSD__)
  removelock(lockname);
  lck = 0;
#endif
  cfname[strlen(cfname) - 1] = 'a';
  unlink(cfname);
  if(areandx)
  {
    Close(areandx);
    areandx = 0;
  }
  cfname[strlen(cfname) - 1] = 'i';
  unlink(cfname);
  if(areadesc)
  {
    Close(areadesc);
    areadesc = 0;
  }
  cfname[strlen(cfname) - 1] = 'd';
  unlink(cfname);
  if(areapool)
  {
    Close(areapool);
    areapool = 0;
  }
  cfname[strlen(cfname) - 1] = 'p';
  unlink(cfname);
  if(compset)
  {
    Close(compset);
    compset = 0;
  }
  cfname[strlen(cfname) - 1] = 'c';
  unlink(cfname);
  if(logfileok)
  {
    logprintf("End, ParToss %s\r\n", version);
    logwrite(1, 1);
    Close(logfile);
    logfile = 0;
    logfileok = 0;
  }
  ccprintf("The Parma Tosser version %s finished.\r\n", version);
  if(alog)
  {
    Close(alog);
    alog = 0;
  }
  if(dupreserv)
  {
    Close(dupreserv);
    dupreserv = 0;
  }
#ifdef __DOS__
  unclosed = closeHandles();
  if(unclosed)
    ccprintf("%d unclosed handle(s) found\r\n", unclosed);
  disableHandles();
#endif
#ifdef __NT__
  SetConsoleTitle("ParToss was here");
#endif
  exit(retcode);
}
