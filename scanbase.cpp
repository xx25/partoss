// MaxiM: find_t

#include "partoss.h"
#include "globext.h"

#include "scanbase.h"
#include "lowlevel.h"
#include "morfiles.h"
#include "errors.h"
#include "rebuild.h"
#include "linkbase.h"
#include "packets.h"
#include "control.h"
#include "attach.h"
#include "chains.h"
#include "partsqd.h"
#include "sqdtobuf.h"
#include "times.h"
#include "crc32.h"
#include "parsrout.h"
#include "buftopkt.h"
#include "msgtobuf.h"

void scanbase (char *arealist, short type)  // 1 - scan, 2 - link, 3 - purge, 4 - fix
{
  char tempsqdn[(DirSize + 1)];
/*  short finis=0; */
  pkts = NULL;
  createpkts ();
  mystrncpy (tempsqdn, bcfg.workdir, DirSize);
  mystrncat (tempsqdn, "tempsqd.$$$", 16, DirSize);
  if (!tempsqd)
    if ((tempsqd =
   (short)sopen (tempsqdn, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR,
           S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
      {
  mystrncpy (errname, tempsqdn, DirSize);
  errexit (2, __FILE__, __LINE__);
      }
  if (bcfg.pack && (mode & 1632))
    {
      chsize (temppkt, 0);
      lseek (temppkt, 0, SEEK_SET);
    }
  switch (type)
    {
    case 1:
      mystrncpy (logout, "Scanning areas", 20);
      break;
    case 2:
      mystrncpy (logout, "Linking areas", 20);
      break;
    case 3:
      globold = globnew = 0;
      mystrncpy (logout, "Purging areas", 20);
      break;
    case 4:
      mystrncpy (logout, "ReBuild areas", 20);
      break;
    case 5:
      mystrncpy (logout, "UnToss areas", 20);
      break;
    }
  logwrite (1, 4);
  if (!quiet)
    ccprintf ("\r\n%s\r\n", logout);
  if (arealist[0] == 0 && !(mode & 1092))
    {
      if (type == 3) // purge
  {
    mustlog = -1;
    if (alog <= 0)
      {
         mystrncpy (echologt, bcfg.workdir, DirSize);
        mystrncat (echologt, "echolog.$$$", DirSize, DirSize);
        if ((alog =
       (short)sopen (echologt, O_RDWR | O_BINARY,
         SH_DENYWR)) == -1)
    {
      if ((alog =
           (short)sopen (echologt, O_RDWR | O_BINARY | O_CREAT,
             SH_DENYWR,
             S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
        {
          mystrncpy (errname, echologt, DirSize);
          errexit (2, __FILE__, __LINE__);
        }
      chsize (alog, 0);
    }
      }
    lseek (alog, 0, SEEK_SET);
  }
      tlist = rlist;
      while (tlist)
  {
    for (carea = 0; carea < tlist->numlists; carea++)
      scanarea (tlist->alist[carea].areaoffs, type);
    tlist = tlist->next;
  }
    }
  else
    {
      if (alog == 0)
  {
    tlist = rlist;
    while (tlist)
      {
        for (carea = 0; carea < tlist->numlists; carea++)
    if (wildcard (arealist, tlist->alist[carea].areaname) == 0)
    {
      logprintf ("Scanning area %s", tlist->alist[carea].areaname);
      logwrite (1, 9);
      scanarea (tlist->alist[carea].areaoffs, type);
    }
//          if(stricmp(tlist->alist[carea].areaname,arealist)==0 &&
//             strlen(tlist->alist[carea].areaname)==strlen(arealist))
//            goto nfound;
        tlist = tlist->next;
      }
//      nfound:
//      if((tlist==NULL) || (carea==tlist->numlists))
//       {
//        mystrncpy(errname,arealist,DirSize);
//        errexit(5,__FILE__,__LINE__);
//       }
  }
      else
  {
    lseek (alog, 0, SEEK_SET);
    endinput[2] = 0;
    while (!endinput[2])
      {
        readblock (alog, 2);
        endblock[2] = 0;
        do
    {
      getstring (2);
      while (!endstring[2])
        {
          gettoken (2);
          tlist = rlist;
          while (tlist)
      {
        for (carea = 0; carea < tlist->numlists; carea++)
          if (strnicmp
        (token, tlist->alist[carea].areaname,
         toklen) == 0
        && strlen (tlist->alist[carea].areaname) ==
        toklen)
            {
        logprintf ("Scanning area %s", tlist->alist[carea].areaname);
        logwrite (1, 5);
        scanarea (tlist->alist[carea].areaoffs, type);
        goto nfound2;
            }
        tlist = tlist->next;
      }
        }
    nfound2:
      ;
    }
        while (!endblock[2]);
      }
  }
    }
  if ((mode & 0x08) || bcfg.autosend)
    makeattach (0);
  cclose (&tempsqd, __FILE__, __LINE__);
  unlink (tempsqdn);
  if (type == 3 && globold && globnew)
    {
      if (globold < 1024)
  logprintf ("Total compressing: %ldb -> %ldb, %d%%",
     globold, globnew, (globnew * 100) / globold);
      else
  logprintf ("Total compressing: %ldK -> %ldK, %d%%",
     globold >> 10, globnew >> 10,
     /*(globnew*100)/globold */ globnew / (globold / 100));
      if (bcfg.loglevel)
  logwrite (1, 1);
      ccprintf ("%s\r\n", logout);
    }
  delpkts ();
}

void scanarea (long aoffset, short type)
{
  switch (type)
    {
    case 1:
      scansqds (aoffset);
      break;
    case 2:
      linksqds (aoffset);
      break;
    case 3:
    case 4:
    case 5:
      rebuild (aoffset, (short)(type - 2));
      break;
    }
}

void scansqds (long aoffset)
{
  short i, frompers = 0;
  long null = 0;
  struct myaddr tsnd;
  lseek (areaset, aoffset, SEEK_SET);
  rread (areaset, newarea, szarea, __FILE__, __LINE__);
  newarea->links.chain = newarea->links.last = NULL;
  newarea->links.numelem = 0;
  if (newarea->type == 0)
    {
      if (bcfg.pack)
  scanmsg ();
    }
  else
    {
      if (newarea->type == 1 && (!newarea->passthr || bcfg.scanall))
  {
    if (newarea->numlinks)
      {
        newarea->links.chain = newarea->links.last = NULL;
        newarea->links.numelem = 0;
        for (i = 0; i < newarea->numlinks; i++)
    {
      rread (areaset, &tsnd, szmyaddr, __FILE__, __LINE__);
      addaddr (&(newarea->links), &tsnd);
    }
        if ((strcmpi (newarea->areaname, persarea->areaname) == 0)
      && (mode & 3) && !(mode & 1))
    {
      frompers = 1;
      arealock = 0;
      newarea->sqd.sqd = persarea->sqd.sqd;
      newarea->sqd.sqi = persarea->sqd.sqi;
      newarea->sqd.sqb = persarea->sqd.sqb;
      lseek (newarea->sqd.sqi, 0, SEEK_SET);
      rread (newarea->sqd.sqi, nindex,
       (unsigned short)(bufsqi * 12), __FILE__, __LINE__);
    }
        else
    {
      opensqd (newarea, nindex, 1, 0);
      if (arealock)
        {
          if (strcmpi (newarea->areaname, persarea->areaname) ==
        0)
      {
        frompers = 1;
        arealock = 0;
        newarea->sqd.sqd = persarea->sqd.sqd;
        newarea->sqd.sqi = persarea->sqd.sqi;
        newarea->sqd.sqb = persarea->sqd.sqb;
        lseek (newarea->sqd.sqi, 0, SEEK_SET);
        rread (newarea->sqd.sqi, nindex,
         (unsigned short)(bufsqi * 12), __FILE__,
         __LINE__);
      }
        }
    }
        if (!arealock)
    {
      scansqd ();
      if (newarea->passthr && !bcfg.passpurge
          && (newarea->sqd.sqd > 0))
        {
          lseek (newarea->sqd.sqd, 4, SEEK_SET);
          wwrite (newarea->sqd.sqd, &null, 4, __FILE__, __LINE__);
        }
      if (!frompers)
        closesqd (newarea, 1);
    }
      }
  }
    }
}

void scansqd (void)
{
//  struct sqifile curr;
  long pfirst, maxmsg, i;
  unsigned long currtime;
  unsigned short j, diff;
  short scanned;
  if (newarea->sqd.sqd <= 0)
    return;
  locsent = 0;
  lseek (newarea->sqd.sqd, 8, SEEK_SET);
  rread (newarea->sqd.sqd, &maxmsg, 4, __FILE__, __LINE__);
  if (maxmsg)
    {
      if (rescan || fullscan)
  pfirst = 0;
      else
  {
    rread (newarea->sqd.sqd, &pfirst, 4, __FILE__, __LINE__);
    rread (newarea->sqd.sqd, &pfirst, 4, __FILE__, __LINE__);
    if (pfirst)
      {
        newarea->curindex = 0;
        lseek (newarea->sqd.sqi, 0, SEEK_SET);
        j =
    (unsigned short)rread (newarea->sqd.sqi, nindex,
               (unsigned short)(bufsqi * 12),
               __FILE__, __LINE__);
        while (j)
    {
      for (i = 0; i < j / 12; i++)
        if (nindex[(unsigned)i].umsgid > pfirst)
          goto ifound;
      if (j / 12 == bufsqi)
        {
          newarea->curindex += bufsqi;
          j =
      (unsigned short)rread (newarea->sqd.sqi, nindex,
                 (unsigned short)(bufsqi * 12),
                 __FILE__, __LINE__);
          i = 0;
        }
      else
        j = 0;
    }
      ifound:
        pfirst = newarea->curindex + i;
      }
  }
      if ((maxmsg - pfirst) > 0)
  {
    logprintf ("%-60s (%ld - %ld)", newarea->areaname, pfirst + 1,
       maxmsg);
    logwrite (1, 5);
  }
      for (i = pfirst; i < maxmsg; i++)
  {
    scanned = sqdtobuf (newarea, nindex, i);
    if (scanned == -2)
      goto mnext5;  /* LMA!!! */
    if (!scanned && local)
      dupcheck (2);
    if (!scanned || rescan || mode & 4)
      {
        if (rescan && rescandays)
    {
      sftime = time (NULL);
      mylocaltime (&sftime, &tmt);
      mystrncpy (tstrtime, asctime (&tmt), 39);
      currtime = strtime (tstrtime);
      diff = diffdays (head.timeto, currtime);
      if (diff <= rescandays)
        msgout (2);
    }
        else
    msgout (2);
      }
    if (i > (newarea->curindex + bufsqi) || i < newarea->curindex)
      {
        newarea->curindex = (i / bufsqi) * bufsqi;
        lseek (newarea->sqd.sqi, newarea->curindex * 12, SEEK_SET);
        rread (newarea->sqd.sqi, nindex, (unsigned short)(bufsqi * 12),
         __FILE__, __LINE__);
      }
    lseek (newarea->sqd.sqd, 16, SEEK_SET);
    wwrite (newarea->sqd.sqd,
      &(nindex[(unsigned)(i - newarea->curindex)].umsgid), 4,
      __FILE__, __LINE__);
    delctrl (2);
  mnext5:
    ;
  }
    }
}

void scanmsg (void)
{
  short topack, nomore, msg;
  char tmpfile[(DirSize + 1)], tfile[(DirSize + 1)];
  struct find_t fblk;
  logprintf ("%-60s", newarea->areaname);
  if (!quiet)
    ccprintf ("%s\r\n", logout);
  logwrite (1, 5);
  chsize (temppkt, 0);
  lseek (temppkt, 0, SEEK_SET);
  mystrncpy (tmpfile, newarea->areafp, DirSize);
  mystrncat (tmpfile, "*.msg", 7, DirSize);
  nomore = (short)_dos_findfirst (tmpfile, findattr, &fblk);
  while (nomore == 0)
    {
      if (!(fblk.attrib & 0x1f))
  {
    mystrncpy (tfile, newarea->areafp, DirSize);
    mystrncat (tfile, fblk.name, 16, DirSize);
    topack = msgtobuf (tfile);
/*
      if(bcfg.method>3)
       {
        if(bufmsg.flags&0x8800)
          formfreq();
        else
          if(bufmsg.flags&0x10)
            formfatt();
       }
*/
    if (topack)
      {
        if (!notouch || compaddr (notouch->list.chain, &node))
    {
      if (mmsgout () == 0)
        {
          if (topack && bcfg.killtr)
      if (!(bufmsg.flags & 0x100))
        topack = 2;
          if (topack > 1)
      unlink (tfile);
          else
      {
        msg = mysopen (tfile, 1, __FILE__, __LINE__);
        rread (msg, &bufmsg,
         (unsigned short)(szmessage - szchar),
         __FILE__, __LINE__);
        bufmsg.flags |= 0x0008;
        lseek (msg, 0, SEEK_SET);
        wwrite (msg, &bufmsg,
          (unsigned short)(szmessage - szchar),
          __FILE__, __LINE__);
        cclose (&msg, __FILE__, __LINE__);
      }
        }
    }
      }
    delctrl (3);
  }
      nomore = (short)_dos_findnext (&fblk);
    }
  _dos_findclose (&fblk);/***ash***/
}

void msgout (short type)
{
  short first, nomore, numpa, match, gated, countp;
/*  char *temp=NULL;*/
  struct myaddr *plink = NULL, *glink = NULL, *ttaddr = NULL;
  struct dngate *tdn = NULL;
  wassend = numpa = first = countp = 0;
  plink = newarea->links.chain;
  while (plink)
    {
      match = 0;
      tdn = bcfg.dgate;
      while (tdn)
  {
    if (tdn->group)
      {
        if (bcfg.
      gric ? (strichr (tdn->where, newarea->group))
      : (strchr (tdn->where, newarea->group)))
    goto matched;
      }
    else
      {
/* remove unused variable LMA!!!        if((temp=strstr(tdn->where,"*"))!=NULL || (temp=strstr(tdn->where,"?"))!=NULL)*/
        if (strstr (tdn->where, "*") != NULL
      || strstr (tdn->where, "?") != NULL)
    {
//          if(strnicmp(newarea->areaname,tdn->where,temp-tdn->where)==0)
      if (wildcard (tdn->where, newarea->areaname) == 0)
        goto matched;
    }
        else if (stricmp (newarea->areaname, tdn->where) == 0)
    goto matched;
      }
    goto unmatch;
  matched:
    if (buftemp == NULL)
      buftemp = buftemps;
    if (buftemp == NULL)
      buftemp = &bufpkt;
    if (tdn->from.zone && tdn->to.zone)
      {
        if (((buftemp->fromzone == tdn->from.zone)
       || (tdn->from.zone == 65535u))
      && ((buftemp->fromnet == tdn->from.net)
          || (tdn->from.net == 65535u))
      && ((buftemp->fromnode == tdn->from.node)
          || (tdn->from.node == 65535u))
      && ((buftemp->frompoint == tdn->from.point)
          || (tdn->from.point == 65535u))
      && ((plink->zone == tdn->to.zone)
          || (tdn->to.zone == 65535u))
      && ((plink->net == tdn->to.net) || (tdn->to.net == 65535u))
      && ((plink->node == tdn->to.node)
          || (tdn->to.node == 65535u))
      && ((plink->point == tdn->to.point)
          || (tdn->to.point == 65535u)))
    match = 1;
      }
    else
      {
        if (tdn->from.zone)
    {
      if (((buftemp->fromzone == tdn->from.zone)
           || (tdn->from.zone == 65535u))
          && ((buftemp->fromnet == tdn->from.net)
        || (tdn->from.net == 65535u))
          && ((buftemp->fromnode == tdn->from.node)
        || (tdn->from.node == 65535u))
          && ((buftemp->frompoint == tdn->from.point)
        || (tdn->from.point == 65535u)))
        match = 1;
    }
        else
    {
      if (((plink->zone == tdn->to.zone)
           || (tdn->to.zone == 65535u))
          && ((plink->net == tdn->to.net)
        || (tdn->to.net == 65535u))
          && ((plink->node == tdn->to.node)
        || (tdn->to.node == 65535u))
          && ((plink->point == tdn->to.point)
        || (tdn->to.point == 65535u)))
        match = 1;
    }
      }
    if (match)
      goto stopit;
  unmatch:
    tdn = tdn->next;
  }
    stopit:
      gated = 0;
      if (match && (tdn->changes & 1))
  {
    if (tdn->aka.zone)
      {
        glink = &tdn->aka;
        gated = 1;
      }
    else
      {
        glink = bcfg.address.chain;
        while (glink)
    {
      if (glink->point || plink->point)
        {
          if ((glink->zone == plink->zone) &&
        (glink->net == plink->net) &&
        (glink->node == plink->node))
      break;
        }
      else if (glink->zone == plink->zone)
        break;
      glink = glink->next;
    }
        if (glink == NULL)
    glink = bcfg.address.chain;
      }
  }
      else
  {
    glink = &newarea->myaka;
    if (bcfg.fixaddr)
      {
        ttaddr = bcfg.address.chain;
        while (ttaddr)
    {
      if (ttaddr->point || plink->point)
        {
          if ((ttaddr->zone == plink->zone) &&
        (ttaddr->net == plink->net) &&
        (ttaddr->node == plink->node))
      break;
        }
      ttaddr = ttaddr->next;
    }
        if (ttaddr == NULL)
    {
      ttaddr = bcfg.address.chain;
      while (ttaddr)
        {
          if ((ttaddr->zone == plink->zone) &&
        (ttaddr->net == plink->net))
      break;
          ttaddr = ttaddr->next;
        }
    }
        if (ttaddr == NULL)
    {
      ttaddr = bcfg.address.chain;
      while (ttaddr)
        {
          if ((ttaddr->zone == plink->zone))
      break;
          ttaddr = ttaddr->next;
        }
    }
        if (ttaddr == NULL)
    ttaddr = bcfg.address.chain;
//        memcpy(&(tpack->fromaddr),ttaddr,szmyaddr);
        glink = ttaddr;
      }
  }
      nomore = 0;
      tpack = pkts;
      while (tpack)
  {
    if (!tpack->filled && !tpack->sent
        && (cmpaddr (&(tpack->outaddr), plink) == 0)
        && (cmpaddr (&(tpack->fromaddr), glink) == 0))
      break;
    tpack = tpack->next;
  }
      if (tpack)
  {
    if (!tpack->opened)
      {
        if ((tpack->handle =
       (short)sopen (tpack->name, O_RDWR | O_BINARY,
         SH_DENYWR)) == -1)
    {
      switch (errno)
        {
        case ENOENT:
          if ((tpack->handle =
         (short)sopen (tpack->name,
           O_RDWR | O_BINARY | O_CREAT,
           SH_DENYWR,
           S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
      {
        if (errno == EMFILE)
          {
            nomore = 1;
            tpack->opened = 0;
            tpack->outaddr.zone = tpack->outaddr.net =
        tpack->outaddr.node = tpack->outaddr.point =
        0;
          }
        else
          errexit (4, __FILE__, __LINE__);
      }
          break;
        case EMFILE:
          nomore = 1;
          break;
        default:
          errexit (4, __FILE__, __LINE__);
        }
    }
      }
    if (!nomore)
      {
        numpa++;
        lseek (tpack->handle, 0, SEEK_END);
        tpack->opened = 1;
      }
  }
      else
  {
    memcpy (&node, plink, szmyaddr);
    addtpack (glink);
    if ((tpack->handle =
         (short)sopen (tpack->name, O_RDWR | O_BINARY | O_CREAT,
           SH_DENYWR, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
      {
        if (errno != EMFILE)
    errexit (4, __FILE__, __LINE__);
        nomore = 1;
        tpack->opened = 0;
        tpack->outaddr.zone = tpack->outaddr.net = tpack->outaddr.node =
    tpack->outaddr.point = 0;
      }
    else
      {
        numpa++;
        lseek (tpack->handle, 0, SEEK_END);
        tpack->opened = 1;
      }
  }
      countp++;
      tpack->gated = gated;
      if (nomore || (numpa == newarea->numlinks)
    || (bcfg.safe && (countp >= bcfg.safe)))
  {
    pktwrite (first, numpa, type);
    tpack = pkts;
    first = numpa;
    if (nomore || (bcfg.safe && (countp >= bcfg.safe)))
      {
        while (tpack)
    {
      if (tpack->opened)
        {
          cclose (&tpack->handle, __FILE__, __LINE__);
          tpack->opened = 0;
        }
      tpack = tpack->next;
    }
        if (bcfg.safe && (countp >= bcfg.safe))
    countp = 0;
      }
  }
      if (!nomore)
  plink = plink->next;
    }
  if (wassend)
    {
      totsent++;
      locsent++;
      if (tlist)
  tlist->alist[carea].sent++;
    }
}

short mmsgout ()
{
  struct route *trou = NULL;
  if (!direct || compaddr (direct->list.chain, &node))
    {
      trou = roulist;
      while (trou)
  {
    if (compaddr (trou->list.chain, &node) == 0)
      break;
    trou = trou->next;
  }
      if (trou)
  memcpy (&node, trou->list.chain, szmyaddr);
      else
  return 1;
    }
  tpack = pkts;
  while (tpack)
    {
      if (!tpack->filled && !tpack->sent
    && (cmpaddr (&(tpack->outaddr), &node) == 0))
  break;
      tpack = tpack->next;
    }
  if (tpack)
    {
      if (!tpack->opened)
  {
    if ((tpack->handle =
         (short)sopen (tpack->name, O_RDWR | O_BINARY,
           SH_DENYWR)) == -1)
      if ((tpack->handle =
     (short)sopen (tpack->name, O_RDWR | O_BINARY | O_CREAT,
             SH_DENYWR, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
        {
    mystrncpy (errname, tpack->name, DirSize);
    errexit (2, __FILE__, __LINE__);
        }
    tpack->opened = 1;
  }
      lseek (tpack->handle, 0, SEEK_END);
    }
  else
    {
      addtpack (bcfg.address.chain);
      if ((tpack->handle =
     (short)sopen (tpack->name, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR,
       S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
  {
    mystrncpy (errname, tpack->name, DirSize);
    errexit (2, __FILE__, __LINE__);
  }
      lseek (tpack->handle, 0, SEEK_END);
      tpack->opened = 1;
    }
  buftopkt (3);
  totsent++;
  locsent++;
  if (tlist)
    tlist->alist[carea].sent++;
  cclose (&tpack->handle, __FILE__, __LINE__);
  tpack->opened = 0;
  return 0;
}

void pktwrite (short first, short last, short type)
{
  unsigned short k, l;
  long pktsize;
  struct myaddr *slink = NULL, *glink = NULL;
  struct myaddr *ttaddr = NULL;
  struct link *blink = NULL;
  slink = newarea->links.chain;
  for (k = 0; k < first; k++)
    slink = slink->next;
  for (l = first; l < last; l++)
    {
      tpack = pkts;
      while (tpack)
  {
    if (tpack->gated)
      glink = &tpack->fromaddr;
    else
      {
        glink = &newarea->myaka;
        if (bcfg.fixaddr)
    {
      ttaddr = bcfg.address.chain;
      while (ttaddr)
        {
          if (ttaddr->point || tpack->outaddr.point)
      {
        if ((ttaddr->zone == tpack->outaddr.zone) &&
            (ttaddr->net == tpack->outaddr.net) &&
            (ttaddr->node == tpack->outaddr.node))
          break;
      }
          ttaddr = ttaddr->next;
        }
      if (ttaddr == NULL)
        {
          ttaddr = bcfg.address.chain;
          while (ttaddr)
      {
        if ((ttaddr->zone == tpack->outaddr.zone) &&
            (ttaddr->net == tpack->outaddr.net) &&
            (ttaddr->node == tpack->outaddr.node))
          break;
        ttaddr = ttaddr->next;
      }
        }
      if (ttaddr == NULL)
        {
          ttaddr = bcfg.address.chain;
          while (ttaddr)
      {
        if ((ttaddr->zone == tpack->outaddr.zone) &&
            (ttaddr->net == tpack->outaddr.net))
          break;
        ttaddr = ttaddr->next;
      }
        }
      if (ttaddr == NULL)
        {
          ttaddr = bcfg.address.chain;
          while (ttaddr)
      {
        if ((ttaddr->zone == tpack->outaddr.zone))
          break;
        ttaddr = ttaddr->next;
      }
        }
      if (ttaddr == NULL)
        ttaddr = bcfg.address.chain;
//          memcpy(&(tpack->fromaddr),ttaddr,szmyaddr);
      glink = ttaddr;
    }
      }
    if (!tpack->filled && !tpack->sent
        && (cmpaddr (&(tpack->outaddr), slink) == 0)
        && (cmpaddr (&(tpack->fromaddr), glink) == 0))
      break;
    tpack = tpack->next;
  }
      if (tpack)
  {
    if (!rescan || (cmpaddr (slink, &rnode) == 0))
      {
        tsend = (type == 1 ? ptosend.chain : stosend.chain);
        while (tsend)
    {
      if (cmpaddr (tsend, &(tpack->outaddr)) == 0)
        break;
      tsend = tsend->next;
    }
        if (tsend)
    {
      blink = bcfg.links.chain;
      while (blink)
        {
          if (cmpaddr (&(blink->address), &(tpack->outaddr)) == 0)
      break;
          blink = blink->next;
        }
      pktsize = bcfg.pktsize;
      if (blink)
        if (blink->pktsize)
          pktsize = blink->pktsize;
      if (pktsize
          &&
          ((filelength (tpack->handle) +
      (type == 1 ? pmsglen : smsglen)) >= pktsize))
        tpack->filled = 1;
      buftopkt (type);
      wassend = 1;
      if (tpack->filled)
        {
          cclose (&tpack->handle, __FILE__, __LINE__);
          tpack->opened = 0;
        }
    }
      }
  }
      slink = slink->next;
      if (slink == NULL)
  break;
    }
}
