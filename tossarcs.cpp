// MaxiM: find_t

#include "partoss.h"
#include "globext.h"

#include "tossarcs.h"
#include "lowlevel.h"
#include "morfiles.h"
#include "errors.h"
#include "archives.h"
#include "partserv.h"
#include "control.h"
#include "attach.h"
#include "partsqd.h"
#include "crc32.h"
#include "parsrout.h"
#include "buftopkt.h"
#include "buftomsg.h"
#include "buftosqd.h"
#include "headers.h"
#include "netfwd.h"
#include "pkttobuf.h"
#include "template.h"
#include "scanbase.h"
#include "packets.h"

long badpos;

// Inbound archive names come from the mailer and are passed to the shell
// (BeforeUnpack, batch/script unpackers): allow plain file names only
static short safearcname(char *name)
{
  char *temp = strrchr(name, DIRSEP[0]);

  temp = temp ? temp + 1 : name;
  if(!*temp)
    return 0;
  for(; *temp; temp++)
    if(!isalnum((unsigned char)*temp) && !strchr("._-~+", *temp))
      return 0;
  return 1;
}

static void unsafearc(char *name)
{
  logprintf("??? Archive %s has an unsafe name, not unpacked", name);
  if(logfileok)
    logwrite(1, 1);
  ccprintf("\r\n%s\r\n", logout);
}

void tossarcs(void)
{
  short i, t, cycle = 1, wasunp = 2;
  char packname[(DirSize + 1)], fullname[(DirSize + 1)],
    tempsqdn[(DirSize + 1)], currname[DirSize + 1], cext[8], ssystem[DirSize + 1];
  struct find_t fblk;
  struct pktname *tinbound = NULL, *tapkt = NULL /*,*tbpkt=NULL */ ;

  while(cycle)
  {
    cycle = 0;
    if(wasunp == 1)
      wasunp = 0;
    mystrncpy(packname, bcfg.workdir, DirSize);
    mystrncat(packname, "ptbackup.tkp", 16, DirSize);
    mystrncpy(fullname, bcfg.workdir, DirSize);
    mystrncat(fullname, "ptbackup.pkt", 16, DirSize);
    if(access(packname, 0) == 0)
      if(!globbad)
        rrename(packname, fullname);
    createpkts();
    chsize(temppkt, 0);
    lseek(temppkt, 0, SEEK_SET);
    if(both)
    {
      mystrncpy(tempsqdn, bcfg.workdir, DirSize);
      mystrncat(tempsqdn, "tempsqd.$$$", 16, DirSize);
      if((tempsqd = (short)sopen(tempsqdn, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
      {
        mystrncpy(errname, tempsqdn, DirSize);
        errexit(2, __FILE__, __LINE__);
      }
    }
//    mystrncpy(packname,bcfg.workdir,DirSize);
    mystrncpy(packname, PKT_MASK, DirSize);
    if(alog == 0)
    {
      mustlog = -1;
      mystrncpy(echologt, bcfg.workdir, DirSize);
      mystrncat(echologt, "echolog.$$$", DirSize, DirSize);
      if((alog = (short)sopen(echologt, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
      {
        mystrncpy(errname, echologt, DirSize);
        errexit(2, __FILE__, __LINE__);
      }
      chsize(alog, 0);
      lseek(alog, 0, SEEK_SET);
    }
    for(i = 0; i < 7; i++)
    {
      for(t = 0; t <= bcfg.levels; t++)
      {
        mystrncpy(cext, arcsh[i], 7);
        if(t)
          cext[3] += (char)t;
        tinbound = bcfg.inbound;
        while(tinbound)
        {
          mystrncpy(fullname, tinbound->name, DirSize);
          mystrncat(fullname, cext, 16, DirSize);
          pgood = (short)_dos_findfirst(fullname, findattr, &fblk);
          while(pgood == 0)
          {
            if(!(fblk.attrib & 0x1f))
            {
              if(fblk.name[strlen(fblk.name) - 4] == '.')
              {
                if(bcfg.sortarc)  // если SortArc - просто запомним пакет, иначе же сразу распакуем и растоссим
                  addarcs(tinbound->name, &fblk, tinbound->where ? 1 : 0);
                else
                {
                  mystrncpy(currname, tinbound->name, DirSize);
                  mystrncat(currname, fblk.name, DirSize, DirSize);
                  if(!safearcname(currname))
                  {
                    unsafearc(currname);
                    goto nextarc;
                  }
                  if(bcfg.sbu[0]) // Запускаем процесс BeforeUnpack
                  {
                    mystrncpy(ssystem, bcfg.sbu, DirSize);
                    mystrncat(ssystem, "  ", 5, DirSize);
                    mystrncat(ssystem, currname, DirSize, DirSize);
#ifdef __NT__
                    GetConsoleTitle(logout, BufSize);
#endif
                    system(ssystem);
#ifdef __NT__
                    SetConsoleTitle(logout);
#endif
                  }
                  archiver(currname, packname, 1); // Распаковываем
                  wasunp = 1;
                  if(bcfg.sau[0]) // Запускаем процесс AfterUnpack
                  {
                    ccprintf("Execute [%s]\r\n", bcfg.sau);
#ifdef __NT__
                    GetConsoleTitle(logout, BufSize);
#endif
                    system(bcfg.sau);
#ifdef __NT__
                    SetConsoleTitle(logout);
#endif
                  }
                  if(!bcfg.bunarc)
                    cycle |= tosspkts();
                }
              }
            }
          nextarc:
            pgood = (short)_dos_findnext(&fblk);
          }
          _dos_findclose(&fblk);
          tinbound = tinbound->next;
        }
      }
    }
    if(bcfg.sortarc) // если SortArc
    {
      sortfpkt(0);
      tapkt = apkt;
      while(tapkt)
      {
        if(!safearcname(tapkt->name))
        {
          unsafearc(tapkt->name);
          goto freearc;
        }
        if(bcfg.sbu[0]) // Запускаем процесс BeforeUnpack
        {
          mystrncpy(ssystem, bcfg.sbu, DirSize);
          mystrncat(ssystem, "  ", 5, DirSize);
          mystrncat(ssystem, tapkt->name, DirSize, DirSize);
#ifdef __NT__
          GetConsoleTitle(logout, BufSize);
#endif
          system(ssystem);
#ifdef __NT__
          SetConsoleTitle(logout);
#endif
        }
        archiver(tapkt->name, packname, 1);
        wasunp = 1;
        if(bcfg.sau[0]) // запускаем AfterUnpack
        {
          ccprintf("Execute [%s]\r\n", bcfg.sau);
#ifdef __NT__
          GetConsoleTitle(logout, BufSize);
#endif
          system(bcfg.sau);
#ifdef __NT__
          SetConsoleTitle(logout);
#endif
        }
        if(!bcfg.bunarc)
          cycle |= tosspkts();
      freearc:
        tinbound = tapkt->next;
        myfree((void **)&tapkt, __FILE__, __LINE__);
        tapkt = tinbound;
      }
    }
    if(bcfg.saua[0] && wasunp) // запускаем процесс AfterUnpackAll
    {
#ifdef __NT__
      GetConsoleTitle(logout, BufSize);
#endif
      system(bcfg.saua);
#ifdef __NT__
      SetConsoleTitle(logout);
#endif
    };
    wasunp = 1;
    apkt = NULL;
    cycle |= tosspkts();
    if(!cycle)
    {
      closesqd(badmess, 0);
      if(!bcfg.killdupes)
        closesqd(dupes, 0);
      closesqd(persarea, 1);
      closesqd(newarea, 1);
    }
    if(mode & 0x08 || bcfg.autosend)
      makeattach(0);
    delpkts();
    if(both)
    {
      cclose(&tempsqd, __FILE__, __LINE__);
      unlink(tempsqdn);
    }
    delpkts();
    if(bcfg.single)
      cycle = 0;
  }
}

short tosspkts(void)
{
  struct pktname *cpkt = NULL, *tpkt = NULL, *tinbound = NULL;
  char pbadname[(DirSize + 1)], *temp = NULL;
  short retcode, retc = 0;

  if(!bcfg.dnsipkt)
  {
    tinbound = bcfg.inbound;
    while(tinbound)
    {
      addpacket(tinbound->name, 0);
      tinbound = tinbound->next;
    }
  }
  addpacket(bcfg.workdir, 0);
  sortfpkt(1);
  cpkt = fpkt;
  while(cpkt)
  {
    retcode = tosspkt(cpkt);
    if(retcode == 0)
    {
      unlink(cpkt->name);
      temp = strrchr(cpkt->name, DIRSEP[0]);
      if(temp)
        temp++;
      else
        temp = cpkt->name;
      if(strnicmp(temp, "ptbackup", 8))
        retc = 1;
    }
    else
    {
      if(retcode == 1 || retcode == 2 || retcode == 3)
      {
        mystrncpy(pbadname, cpkt->name, DirSize);
        pbadname[strlen(pbadname) - 3] = 'b';
//        if(logfileok)
//         {
        if(retcode == 1)
          logprintf("??? Inbound packet %s is damaged, look near offset %lx", cpkt->name, badpos);
        else if(retcode == 2)
          logprintf("??? Inbound packet %s - wrong password", cpkt->name);
        else
          logprintf("??? Inbound packet %s - not for us", cpkt->name);
        ccprintf("\r\n%s\r\n", logout);
        logwrite(1, 1);
        if(!rrename(cpkt->name, pbadname))
        {
          logprintf("??? Renamed to %s for Your intervence", pbadname);
          ccprintf("\r\n%s\r\n", logout);
          logwrite(1, 1);
        }
//         }
      }
      else
      {
        logprintf("??? Can't open inbound packet %s", cpkt->name);
        if(logfileok)
          logwrite(1, 1);
        ccprintf("\r\n%s\r\n", logout);
      }
    }
    if(both && (mode & 0x08 || bcfg.autosend) && bcfg.bpack)
      makeattach(1);
    cpkt = cpkt->next;
  }
  cpkt = fpkt;
  while(cpkt)
  {
    tpkt = cpkt->next;
    myfree((void **)&cpkt, __FILE__, __LINE__);
    cpkt = tpkt;
  }
  fpkt = NULL;
  if(both && ((mode & 0x08) || bcfg.autosend) && !bcfg.bpack)
    makeattach(1);
  return retc;
}

short tosspkt(struct pktname *tpkt)
{
  struct myaddr *ttaddr = NULL, *tttaddr = NULL, *taddr = NULL;
  struct link *blink = NULL;
  char *temp = NULL;
  char *fromdir[] = { "Inbound", "Secure ", "WorkDir" };
  unsigned short i, topack, badpack = 0, badfr, isbackup = 0;
  short pktype;
  long pktsz;
  struct kludge *tkludge = NULL;

  memset(oldarea, 0, arealength);
  if((pkt = (short)sopen(tpkt->name, O_RDONLY | O_BINARY, SH_DENYWR)) == -1)
    return -1;
  pktsz = filelength(pkt);
  pktype = readhead(pkt, &pktaddr, &node);
#ifdef __LOG_DEBUG__
  logprintf("[D] PKT (%ld bytes) From %u:%u/%u.%u to %u:%u/%u.%u",
          pktsz, pktaddr.zone, pktaddr.net, pktaddr.node, pktaddr.point, node.zone, node.net, node.node, node.point);
  ccprintf("\n%s\n", logout);
  logwrite(1, 1);
#endif
  if(pktype < 0)
    goto endfunc;
  taddr = bcfg.address.chain;
  while(taddr)
  {
    if(pktype == 0)
    {
      if(taddr->zone == node.zone && taddr->net == node.net && taddr->node == node.node)
        break;
    }
    else
    {
      if(cmpaddr(taddr, &node) == 0)
        break;
    }
    taddr = taddr->next;
  }
  if((taddr == NULL) && bcfg.secure)
  {
    badpack = 3;
    goto endfunc;
  }
  temp = strrchr(tpkt->name, DIRSEP[0]);
  if(temp)
    temp++;
  else
    temp = tpkt->name;
  if(strnicmp(temp, "ptbackup.pkt", 12) == 0)
    isbackup = 1;
  ccprintf("\r\n[%s] %s (%ld bytes) - %u:%u/%u.%u\r\n", fromdir[tpkt->where],
           temp, pktsz, pktaddr.zone, pktaddr.net, pktaddr.node, pktaddr.point);
  logprintf("[%s] %s (%ld bytes) from %u:%u/%u.%u to %u:%u/%u.%u",
          fromdir[tpkt->where], temp, pktsz, pktaddr.zone, pktaddr.net,
          pktaddr.node, pktaddr.point, node.zone, node.net, node.node, node.point);
  logwrite(1, 3);
  blink = bcfg.links.chain;
  while(blink)
  {
    if(cmpaddr(&blink->address, &pktaddr) == 0)
      break;
    blink = blink->next;
  }
  if(blink && blink->password[0])
  {
    if(blink->mask & (2L << 20))
    {
      if((strlen(blink->password) != strlen(ppassword)) ||
         (strncmp(blink->password, ppassword, strlen(ppassword)) != 0))
      {
        badpack = 2;
        goto endfunc;
      }
    }
  }
  create = bcfg.create;
  if(blink)
    if(create)
      create = (blink->create != 65535u);
    else
      create = (blink->create == 1);
  poffset = 58;
  loctoss = 0;
  while((fmax = (unsigned short)rreadz(pkt, pktbuf, buflen, __FILE__, __LINE__)) > 0)
  {
    if(fmax < 34)
      break;
    pcurpos = 0;
    badfr = 0;
    pctrlpos = 0;
    for(i = pcurpos; i < fmax && (*(pktbuf + i + 1) || (*(pktbuf + i) != 2)); i++);
    if(i > pcurpos)
    {
      badpack = 1;
      badpos = poffset;
      if(bcfg.dropbad)
        goto endfunc;
    }
    pcurpos = i;
    if((pcurpos + 34) >= fmax)
      break;
    isdupe = 0;
    if(pkttobuf())
    {
      badpack = 1;
      badpos = poffset;
      goto endfunc;
    }
    lseek(pkt, poffset, SEEK_SET);
    if(badfr)
    {
      wipearea = 0;
      totbad++;
      badtype = 1;
      if(badlocked)
      {
        logprintf("BackUp: BadArea is locked");
        logwrite(1, 3);
        backup(1);
      }
      else
        buftosqd(badmess, bindex, 1);
      delctrl(1);
      wipearea = 1;
    }
    else
    {
      if(!netmail)
      {
        badarea = setarea(curarea, 0);
        if(badarea == -2)
        {
          logprintf("Message in DeletedArea %s!", curarea);
          logwrite(1, 3);
          goto deleted;
        }
        if(badarea)
        {
          wipearea = 0;
          totbad++;
          if(badarea > 0 && (bcfg.locked == 4))
          {
            logprintf("BackUp: Area %s is locked", curarea);
            logwrite(1, 3);
            totbad--;
            backup(1);
          }
          else
          {
            if(badarea < 0)
              badtype = 2;
            else
              badtype = 5;
            if(badlocked)
            {
              logprintf("BackUp: BadArea is locked");
              logwrite(1, 3);
              backup(1);
            }
            else
              buftosqd(badmess, bindex, 1);
          }
          wipearea = 1;
        }
        else
        {
          ttaddr = newarea->links.chain;
          while(ttaddr)
          {
            if(cmpaddr(ttaddr, &pktaddr) == 0)
            {
              if(ttaddr->rdonly)
              {
                wipearea = 0;
                totbad++;
                badtype = 3;
                if(badlocked)
                {
                  logprintf("BackUp: BadArea is locked");
                  logwrite(1, 3);
                  backup(1);
                }
                else
                  buftosqd(badmess, bindex, 1);
                wipearea = 1;
              }
              else
              {
                if(!isdupe)
                  dupcheck(1);
                if(newarea->dupes && isdupe)
                {
                  if(tlist)
                    tlist->alist[carea].dupes++;
                  totdupes++;
                  if(!newarea->killd)
                  {
                    wipearea = 0;
                    if(dupelocked)
                    {
                      logprintf("BackUp: DupeArea is locked");
                      logwrite(1, 3);
                      backup(1);
                    }
                    else
                    {
                      //
                      // For Jury Fradkin
                      //
                      if(bcfg.loglevel > 9)
                      {
                        logprintf("Moved to DupeArea, reason - %s", (isdupe == 1) ? "CRC32 match" : "@PATH loop");
                        logwrite(1, 10);
                      }
                      //
                      // For Jury Fradkin
                      //
                      buftosqd(dupes, dindex, 1);
                    }
                    wipearea = 1;
                  }
                }
                else
                  writeboth(1);
              }
              break;
            }
            ttaddr = ttaddr->next;
          }
          if(ttaddr == NULL)
          {
            if(cmpaddr(&(newarea->myaka), &pktaddr) == 0)
            {
              if(!isdupe)
                dupcheck(1);
              if(newarea->dupes && isdupe)
              {
                if(tlist)
                  tlist->alist[carea].dupes++;
                totdupes++;
                if(!newarea->killd)
                {
                  wipearea = 0;
                  if(dupelocked)
                  {
                    logprintf("BackUp: DupeArea is locked");
                    logwrite(1, 3);
                    backup(1);
                  }
                  else
                  {
                      logprintf("Moved to DupeArea, reason - %s", (isdupe == 1) ? "CRC32 match" : "@PATH loop");
                      logwrite(1, 10);
                    buftosqd(dupes, dindex, 1);
                  }
                  wipearea = 1;
                }
              }
              else
                writeboth(1);
            }
            else
            {
              if(!bcfg.secure || isbackup)
              {
                if(!isdupe)
                  dupcheck(1);
                if(newarea->dupes && isdupe)
                {
                  if(tlist)
                    tlist->alist[carea].dupes++;
                  totdupes++;
                  if(!newarea->killd)
                  {
                    wipearea = 0;
                    if(dupelocked)
                    {
                      logprintf("BackUp: DupeArea is locked");
                      logwrite(1, 3);
                      backup(1);
                    }
                    else
                    {
                        logprintf("Moved to DupeArea, reason - %s", (isdupe == 1) ? "CRC32 match" : "@PATH loop");
                        logwrite(1, 10);
                      buftosqd(dupes, dindex, 1);
                    }
                    wipearea = 1;
                  }
                }
                else
                  writeboth(1);
              }
              else
              {
                wipearea = 0;
                totbad++;
                badtype = 4;
                if(badlocked)
                {
                  logprintf("BackUp: BadArea is locked");
                  logwrite(1, 3);
                  backup(1);
                }
                else
                {
/*********************************************
 Emergency exit in case of this uncatched bug
*********************************************/
                  if(stricmp(newarea->areaname, curarea))
                  {
                    logprintf("***** Debug at dead:");
                    logwrite(1, 11);
                    logprintf("***** Newarea:  %s", newarea->areaname);
                    logwrite(1, 11);
                    logprintf("***** Persarea: %s", persarea->areaname);
                    logwrite(1, 11);
                    logprintf("***** Badarea:  %s", badmess->areaname);
                    logwrite(1, 11);
                    logprintf("***** Dupearea: %s", dupes->areaname);
                    logwrite(1, 11);
                    logprintf("***** Curarea:  %s", curarea);
                    logwrite(1, 11);
                    logprintf("***** Oldarea:  %s", oldarea);
                    logwrite(1, 11);
                    logprintf("***** Message parameters:");
                    logwrite(1, 11);
                    logprintf("***** Packet parameters:");
                    logwrite(1, 11);
                    logprintf(
                            "*** Packet from %u:%u/%u.%u", pktaddr.zone, pktaddr.net, pktaddr.node, pktaddr.point);
                    logwrite(1, 11);
                    logprintf("***** Message parameters:");
                    logwrite(1, 11);
                    logprintf("***** From: %s", bufpkt.fromname);
                    logwrite(1, 11);
                    logprintf("***** To: %s", bufpkt.toname);
                    logwrite(1, 11);
                    logprintf("***** Subj: %s", bufpkt.subj);
                    logwrite(1, 11);
                    logprintf("***** Date: %s", bufpkt.datetime);
                    logwrite(1, 11);
                    logprintf("***** Kludges:");
                    logwrite(1, 11);
                    tkludge = pckludge;
                    while(tkludge)
                    {
                      if(tkludge->str[0] == 1)
                        tkludge->str[0] = '@';
                      logprintf("%s", tkludge->str);
                      logwrite(1, 11);
                      tkludge = tkludge->next;
                    }
                    errexit(15, __FILE__, __LINE__);
                  }
/*********************************************
 Emergency exit in case of this uncatched bug
*********************************************/
                  buftosqd(badmess, bindex, 1);
                  logprintf(
                          "*** Packet was from %u:%u/%u.%u", pktaddr.zone, pktaddr.net, pktaddr.node, pktaddr.point);
                  logwrite(1, 10);
                  logprintf("*** Packet address was not found in links of area %s:", newarea->areaname);
                  logwrite(1, 10);
                  tttaddr = newarea->links.chain;
                  while(tttaddr)
                  {
                    logprintf("**** %u:%u/%u.%u", tttaddr->zone, tttaddr->net, tttaddr->node, tttaddr->point);
                    logwrite(1, 10);
                    tttaddr = tttaddr->next;
                  }
                  // More precisely debug info
                  logprintf("***** Debug info 2: [%s] [%s] [%s]", newarea->areaname, persarea->areaname, curarea);
                  logwrite(1, 11);
                }
                wipearea = 1;
              }
            }
          }
        }
      deleted:
        delctrl(1);
      }
      else
      {
        memcpy(&bufmess, &bufpkt, szpackmess);
        tottoss++;
        loctoss++;
        tempmsg = temppkt;
        mckludge = pckludge;
        mkludlen = pkludlen;
        mbigmess = pbigmess;
        mtolen = ptolen;
        mfromlen = pfromlen;
        msubjlen = psubjlen;
        mtextlen = ptextlen;
        taddr = bcfg.address.chain;
        while(taddr)
        {
          if(cmpaddr(taddr, &node) == 0)
            break;
          taddr = taddr->next;
        }
        if(taddr)
        {
          fwdprepare();
          buftomsg(2);
          fwdsend();
        }
        else
        {
          if(both && bcfg.pack)
          {
            if(!notouch || compaddr(notouch->list.chain, &node))
            {
              if(mflags & 0x18e5el)
                topack = 0;
              else if(mflags & 0x80)
                topack = 2;
              else
                topack = 1;
              if(topack)
                if(bcfg.killtr)
                  topack = 2;
              if(topack == 1)
                bufmess.flags |= 0x8;
              if(mmsgout() || topack < 2)
              {
                bufmess.flags |= 0x20;
                buftomsg(2);
              }
            }
            else
            {
              bufmess.flags |= 0x20;
              buftomsg(2);
            }
          }
          else
          {
            bufmess.flags |= 0x20;
            buftomsg(2);
          }
        }
        mckludge = NULL;
        delctrl(1);
        if(both && bcfg.pack)
        {
          tlist = rlist;
          while(tlist)
          {
            for(carea = 0; carea < tlist->numlists; carea++)
            {
              if(tlist->alist[carea].type == 0 && tlist->alist[carea].scanned == 0)
              {
                if(newarea->open)
                  closesqd(newarea, 1);
                lseek(areaset, tlist->alist[carea].areaoffs, SEEK_SET);
                rread(areaset, newarea, szarea, __FILE__, __LINE__);
                scanmsg();
                tlist->alist[carea].scanned = 1;
              }
            }
            tlist = tlist->next;
          }
        }
      }
    }
  }
endfunc:
  if(!netmail)
  {
    closesqd(newarea, 1);
    memset(curarea, 0, arealength);
  }
  cclose(&pkt, __FILE__, __LINE__);
  return badpack;
}

void writeboth(short type)
{
  struct sysname *tname = NULL, *ttname = NULL, *ttt = NULL;
  struct myaddr tpktaddr;
  unsigned short tcarea, tarealen, tlkludlen, templen;
  short tmpl, move, wascopy = 0;

  tottoss++;
  loctoss++;
  memcpy(arealist, newarea->areaname, 80);
  if(tlist)
  {
    tlist->alist[carea].toss++;
    if(bcfg.tossstat)
//      tlist->alist[carea].tossed+=(265+pkludlen+ptextlen);
      tlist->alist[carea].tossed += (265 + pmsglen);
  }
  tcarea = carea;
  move = 0;
  if(newarea->passthr && bcfg.nocarbon)
    goto nfound;
  tname = bcfg.myname.chain;
  while(tname)
  {
    mustcopy = 0;
    if(tname->where & 1) // To:
    {
      if(tname->name[0])
      {
        mystrncpy(logout, gltoname, BufSize);
        if(tname->exact)
        {
          if((strncmp(logout, tname->name, strlen(tname->name)) == 0) && (strlen(logout) == strlen(tname->name)))
            mustcopy = 1;
        }
        else
        {
          if(strstr(strupr(logout), strupr(tname->name)) != NULL)
            mustcopy = 1;
        }
      }
      else
      {
        if((caddr.zone == tname->address.zone
            || tname->address.zone == 65535u)
           && (caddr.net == tname->address.net
               || tname->address.net == 65535u)
           && (caddr.node == tname->address.node
               || tname->address.node == 65535u)
           && (caddr.point == tname->address.point || tname->address.point == 65535u))
          mustcopy = 1;
      }
    }
    if(tname->where & 2) // From:
    {
      if(tname->name[0])
      {
        mystrncpy(logout, glfromname, BufSize);
        if(tname->exact)
        {
          if((strncmp(logout, tname->name, strlen(tname->name)) == 0) && (strlen(logout) == strlen(tname->name)))
            mustcopy = 1;
        }
        else
        {
          if(strstr(strupr(logout), strupr(tname->name)) != NULL)
            mustcopy = 1;
        }
      }
      else
      {
        if(!addrfake)
        {
          if((bufpkt.fromzone == tname->address.zone
              || tname->address.zone == 65535u)
             && (bufpkt.fromnet == tname->address.net
                 || tname->address.net == 65535u)
             && (bufpkt.fromnode == tname->address.node
                 || tname->address.node == 65535u)
             && (bufpkt.frompoint == tname->address.point || tname->address.point == 65535u))
            mustcopy = 1;
        }
      }
    }
    if(tname->where & 4) // Subj
    {
      mystrncpy(logout, glsubj, BufSize);
      if(tname->exact)
      {
        if((strncmp(logout, tname->name, strlen(tname->name)) == 0) && (strlen(logout) == strlen(tname->name)))
          mustcopy = 1;
      }
      else
      {
        if(strstr(strupr(logout), strupr(tname->name)) != NULL)
          mustcopy = 1;
      }
    }
    if(mustcopy)
    {
      if(tname->move)
        move = 1;
      if(ttname == NULL)
      {
        ttname = (struct sysname *)myalloc(szsysname, __FILE__, __LINE__);
        ttt = ttname;
      }
      else
      {
        ttt = ttname;
        while(ttt)
        {
          if((strlen(tname->persarea) == strlen(ttt->persarea)) && (strcmp(tname->persarea, ttt->persarea) == 0))
            goto copied;
          ttt = ttt->next;
        }
        ttt = ttname;
        while(ttt->next)
          ttt = ttt->next;
        ttt->next = (struct sysname *)myalloc(szsysname, __FILE__, __LINE__);
        ttt = ttt->next;
      }
      memcpy(ttt->persarea, tname->persarea, arealength);
      ttt->next = NULL;
      if((setarea(tname->persarea, 1)) == 0)
      {
        wipearea = 0;
        wascopy = 1;
        totpers++;
        gpers = 1;
        buftosqd(persarea, pindex, 1);
        gpers = 0;
      }
      if(type == 1)
      {
        if(tname->templ[0])
        {
          if((tmpl = (short)sopen(tname->templ, O_RDONLY | O_BINARY, SH_DENYWR)) != -1)
          {
            bufmess.toname = (char *)myalloc(36, __FILE__, __LINE__);
            bufmess.fromname = (char *)myalloc(36, __FILE__, __LINE__);
            bufmess.subj = (char *)myalloc(72, __FILE__, __LINE__);
            bufmess.tozone = bufpkt.fromzone;
            bufmess.tonet = bufpkt.fromnet;
            bufmess.tonode = bufpkt.fromnode;
            bufmess.topoint = bufpkt.frompoint;
            bufmess.fromzone = newarea->myaka.zone;
            bufmess.fromnet = newarea->myaka.net;
            bufmess.fromnode = newarea->myaka.node;
            bufmess.frompoint = newarea->myaka.point;
            mystrncpy(bufmess.toname, bufpkt.fromname, 35);
            mystrncpy(bufmess.fromname, "Parma Tosser", 35);
            mystrncpy(bufmess.subj, bufpkt.subj, 71);
            mtolen = strlen(bufmess.toname);
            mfromlen = strlen(bufmess.fromname);
            msubjlen = strlen(bufmess.subj);
            bufmess.flags = 0x181;
            mbigmess = 1;
            tempmsg = templat(0, tmpl);
            lseek(tempmsg, 0, SEEK_SET);
            templen = (unsigned short)ptextlen;
            pmsglen = ptextlen = filelength(tempmsg);
            pmsglen += pkludlen - 1;
            mckludge = NULL;
            buftomsg(4);
            pmsglen = ptextlen = templen;
            cclose(&tempmsg, __FILE__, __LINE__);
            cclose(&tmpl, __FILE__, __LINE__);
            unlink(pttmpl);
            myfree((void **)&bufmess.subj, __FILE__, __LINE__);
            myfree((void **)&bufmess.toname, __FILE__, __LINE__);
            myfree((void **)&bufmess.fromname, __FILE__, __LINE__);
          }
        }
      }
      mustcopy = 0;
      wipearea = 1;
    }
  copied:
    tname = tname->next;
  }
  ttt = ttname;
  while(ttt)
  {
    ttname = ttt->next;
    myfree((void **)&ttt, __FILE__, __LINE__);
    ttt = ttname;
  }
  mustcopy = 0;
  if(wascopy)
  {
    tlist = rlist;
    while(tlist)
    {
      for(carea = 0; carea < tlist->numlists; carea++)
        if(stricmp(tlist->alist[carea].areaname, arealist) == 0 &&
           strlen(tlist->alist[carea].areaname) == strlen(arealist))
          goto nfound;
      tlist = tlist->next;
    }
  }
nfound:
  if(type == 1 && both)
  {
    tarealen = arealen;
    tlkludlen = lkludlen;
    if(tlist)
    {
      if(!tlist->alist[carea].scanned)
      {
        memcpy(&tpktaddr, &pktaddr, szmyaddr);
        scansqd();
        memcpy(&pktaddr, &tpktaddr, szmyaddr);
        tlist->alist[carea].scanned = 1;
      }
    }
    if(newarea->numlinks > 1)
      msgout(1);
    arealen = tarealen;
    lkludlen = tlkludlen;
  }
  if(type == 1 && !(both && newarea->passthr) && !move)
  {
    buftosqd(newarea, nindex, 1);
  }
  else
    inecholog(newarea->areaname);
  carea = tcarea;
  if(move)
    glmove = 1;
}

void backup(short type)
{
  struct packet btpack;

  btpack.name = (char *)myalloc(DirSize + 1, __FILE__, __LINE__);
  mystrncpy(btpack.name, bcfg.workdir, DirSize);
  mystrncat(btpack.name, "ptbackup.tkp", 16, DirSize);
  btpack.touched = 1;
  if((btpack.handle = (short)sopen(btpack.name, O_RDWR | O_BINARY, SH_DENYWR)) == -1)
  {
    if((btpack.handle =
        (short)sopen(btpack.name, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
    {
      mystrncpy(errname, btpack.name, DirSize);
      errexit(2, __FILE__, __LINE__);
    }
    btpack.touched = 0;
  }
  btpack.opened = 1;
  btpack.fromaddr.zone = pktaddr.zone;
  btpack.fromaddr.net = pktaddr.net;
  btpack.fromaddr.node = pktaddr.node;
  btpack.fromaddr.point = pktaddr.point;
  btpack.outaddr.zone = bcfg.address.chain->zone;
  btpack.outaddr.net = bcfg.address.chain->net;
  btpack.outaddr.node = bcfg.address.chain->node;
  btpack.outaddr.point = bcfg.address.chain->point;
  btpack.filled = btpack.sent = btpack.file = 0;
  memcpy(btpack.password, ppassword, 8);
  lseek(btpack.handle, 0, SEEK_END);
  tpack = &btpack;
  buftopkt(4);
  tpack = NULL;
  cclose(&btpack.handle, __FILE__, __LINE__);
  btpack.opened = 0;
  myfree((void **)&btpack.name, __FILE__, __LINE__);
  if(type)
    dupundo();
  return;
}
