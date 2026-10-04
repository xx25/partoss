// MaxiM: ported, not changed.

#include "partoss.h"
#include "globext.h"

#include "buftosqd.h"
#include "partserv.h"
#include "lowlevel.h"
#include "morfiles.h"
#include "errors.h"
#include "control.h"
#include "tossarcs.h"
#include "partpost.h"

short buftosqd (struct area *ttarea, struct sqifile *tindex, short type)
{
  short kill = 0, kill2 = 0 /*,present=0 */ ;
  unsigned short fmax2 = 0, isarea = 0, isdog = 0;
  long tolen = 0, fromlen = 0, subjlen = 0, bigmess = 0;
  short tempfile = 0, msg = 0;
  short rlen = 0;
  char *temp = NULL, copystr[BufSize + 1], *one1 = "\1", *null1 =
    "\0", *tsbuf = NULL, *klbuf = NULL;
  char reason[40];
  struct sqifile tbuf;
  long current = 0, next = 0, prev = 0, prevf = 0, msgsize = 0, tpmsglen =
    0, textlen = 0, reallen = 0, i = 0, tkllen = 0, tislen = 0;
  struct pointers pcurr, pnext, pprev;
  struct kludge *tkludge = NULL, *ttkludge = NULL;
  if (ttarea->type == 0)
    return -1;
  memcpy (rcurarea, curarea, arealength);
  logprintf ("***** Debug info: [%s] [%s] [%s] [%s]",
     ttarea->areaname, newarea->areaname, persarea->areaname, curarea);
  logwrite (1, 12);
  if (type == 1)
    {
      tolen = ptolen;
      fromlen = pfromlen;
      subjlen = psubjlen;
      textlen = ptextlen;
      buftemp = &bufpkt;
      tsbuf = pktbuf;
      bigmess = pbigmess;
      tempfile = temppkt;
      tkludge = pckludge;
      tkllen = pkludlen;
      kill = 0;
    }
  else
    {
      tolen = stolen;
      fromlen = sfromlen;
      subjlen = ssubjlen;
      textlen = stextlen;
      buftemp = &bufsqd;
      tsbuf = sqdbuf;
      bigmess = sbigmess;
      tempfile = tempsqd;
      tkludge = sckludge;
      tkllen = skludlen;
      wipearea = 1;
      kill = (mode & 2176 && flags2
        && (ttarea->type == 1 || ttarea->type == 3) && bcfg.ktrash);
    }
// /*
  if (ttarea->type == 2)
    {
      memset (reason, 0, 40);
      mystrncpy (reason, "\1Reason: ", 39);
      switch (badtype)
  {
  case 1:
    mystrncat (reason, (char *)"Corrupted packet", 19, 39);
    rlen = 25;
    break;
  case 2:
    mystrncat (reason, (char *)"Unknown area", 15, 39);
    rlen = 21;
    break;
  case 3:
    mystrncat (reason, (char *)"Read-Only area", 17, 39);
    rlen = 23;
    break;
  case 4:
    mystrncat (reason, (char *)"Security violation", 21, 39);
    rlen = 27;
    break;
  case 5:
    mystrncat (reason, (char *)"Locked area", 15, 39);
    rlen = 20;
    break;
  }
      if (!(tkludge))
  {
    tkludge = (struct kludge *)myalloc (szkludge, __FILE__, __LINE__);
    ttkludge = tkludge;
  }
      else
  {
    ttkludge = tkludge;
    while (ttkludge->next)
      ttkludge = ttkludge->next;
    ttkludge->next =
      (struct kludge *)myalloc (szkludge, __FILE__, __LINE__);
    ttkludge = ttkludge->next;
  }
      ttkludge->next = NULL;
      ttkludge->str = (char *)myalloc (rlen + 3, __FILE__, __LINE__);
      memset (ttkludge->str, 0, rlen + 3);
      memcpy (ttkludge->str, reason, rlen + 1);
      ttkludge->left = 0;
      rlen++;
//    lkludlen+=rlen;
//    lkludnum++;
      tkllen += rlen;
      if (type == 1)
  {
    pkludlen += rlen;
    pkludnum++;
  }
      else
  {
    skludlen += rlen;
    skludnum++;
  }
    }
// */

  tkllen += arealen + 1;
  klbuf = (char *)myalloc ((unsigned)(tkllen + 21), __FILE__, __LINE__);
  kill2 = (short)((type == 1) ? (both || ttarea->numlinks <= 1) : kill);
  lseek (ttarea->sqd.sqd, 0, SEEK_SET);
  rread (ttarea->sqd.sqd, &sqbuf, 256, __FILE__, __LINE__);
  if (!ttarea->passthr)
    {
      if (sqbuf.maxmsg && sqbuf.nummsg >= sqbuf.maxmsg)
  {
    if (sqbuf.skipmsg > (ttarea->curindex + bufsqi)
        || sqbuf.skipmsg < ttarea->curindex)
      {
        ttarea->curindex = (sqbuf.skipmsg / bufsqi) * bufsqi;
        lseek (ttarea->sqd.sqi, ttarea->curindex * 12, SEEK_SET);
        rread (ttarea->sqd.sqi, tindex, (unsigned short)(bufsqi * 12),
         __FILE__, __LINE__);
      }
    memcpy (&sqibuf,
      &tindex[(unsigned)(sqbuf.skipmsg - ttarea->curindex)], 12);
    current = sqibuf.offset;
    if (sqread (ttarea, current, &pcurr, __FILE__, __LINE__) == -1)
      return -1;
    while (sqbuf.nummsg >= sqbuf.maxmsg)
      {
        pcurr.frametype = 1;
        next = sqbuf.first = pcurr.next;
        if (sqread (ttarea, next, &pnext, __FILE__, __LINE__) == -1)
    return -1;
        pnext.prev = 0;
        lseek (ttarea->sqd.sqd, next, SEEK_SET);
        wwrite (ttarea->sqd.sqd, &pnext, 28, __FILE__, __LINE__);
        if (sqbuf.lastf)
    {
      pcurr.prev = prevf = sqbuf.lastf;
      pcurr.next = 0;
      if (sqread (ttarea, prevf, &pprev, __FILE__, __LINE__) ==
          -1)
        return -1;
      sqbuf.lastf = pprev.next = current;
      lseek (ttarea->sqd.sqd, prevf, SEEK_SET);
      wwrite (ttarea->sqd.sqd, &pprev, 28, __FILE__, __LINE__);
      lseek (ttarea->sqd.sqd, current, SEEK_SET);
      wwrite (ttarea->sqd.sqd, &pcurr, 28, __FILE__, __LINE__);
    }
        else
    {
      sqbuf.firstf = sqbuf.lastf = current;
      pcurr.next = pcurr.prev = 0;
      lseek (ttarea->sqd.sqd, current, SEEK_SET);
      wwrite (ttarea->sqd.sqd, &pcurr, 28, __FILE__, __LINE__);
    }
        for (i = sqbuf.skipmsg + 1; i <= sqbuf.nummsg; i++)
    {
      lseek (ttarea->sqd.sqi, i * 12, SEEK_SET);
      rread (ttarea->sqd.sqi, &tbuf, 12, __FILE__, __LINE__);
      lseek (ttarea->sqd.sqi, (i - 1) * 12, SEEK_SET);
      wwrite (ttarea->sqd.sqi, &tbuf, 12, __FILE__, __LINE__);
    }
        if (sqbuf.skipmsg > (ttarea->curindex + bufsqi)
      || sqbuf.skipmsg < ttarea->curindex)
    {
      ttarea->curindex = (sqbuf.skipmsg / bufsqi) * bufsqi;
      lseek (ttarea->sqd.sqi, ttarea->curindex * 12, SEEK_SET);
      rread (ttarea->sqd.sqi, tindex,
       (unsigned short)(bufsqi * 12), __FILE__, __LINE__);
    }
        sqbuf.nummsg--;
        sqbuf.highmsg--;
        flushbuf (ttarea->sqd.sqd);
        flushbuf (ttarea->sqd.sqi);
        current = next;
        if (sqread (ttarea, next, &pcurr, __FILE__, __LINE__) == -1)
    return -1;
      }
    chsize (ttarea->sqd.sqi, sqbuf.maxmsg * 12);
  }
    }
  if (mode & 128 && !(mode & 32))
    sqbuf.uid = rehwm;
  sqibuf.umsgid = sqbuf.uid;
  sqbuf.uid++;
  if ((bcfg.delinfo && !ttarea->saveci) && kill2 && ttarea->type == 1)
    switch (bcfg.delinfo)
      {
      case 1:
  tpmsglen = (type == 1) ? pcmsglen : scmsglen;
  break;
      case 2:
  tpmsglen = (type == 1) ? pcmsglen : scmsglen;
  char *temp, *temp2, *temp3;
  if (bigmess)
    temp = tsbuf;
  else
    temp = buftemp->text;
  if ((temp2 = locpath (temp)) != NULL)
    {
      tpmsglen += strlen (temp2);
      if (((temp3 = locseenby (temp)) != NULL) && (temp3 < temp2))
        memmove (temp3, temp2, strlen (temp2) + 1);   // overlapping
    }
  break;
      }
  else
    tpmsglen = (type == 1) ? pmsglen : smsglen;
  if (wipearea)
    {
      tpmsglen -= arealen;
      if (mode & 2048)
  tpmsglen--;
    }
  else if (type == 1 && !netmail)
    tpmsglen++;
  if ((mode & 2048) && (ttarea->type == 3 || ttarea->type == 2))
    tpmsglen += arealen + 1;
  if (bcfg.delkl && kill2)
    tpmsglen -= lkludlen;
  tpmsglen += rlen;
  if (mustcopy)
    {
      mystrncpy (copystr, bcfg.fwdstr, BufSize);
      trans (copystr, BufSize);
      tpmsglen += strlen (copystr);
    }
  msgsize = tpmsglen + 267;
  if (addorig)
    msgsize += strlen (tail);
  current = sqbuf.firstf;
  pcurr.prev = pcurr.next = pcurr.frlength = pcurr.msglength = 0;
  lseek (ttarea->sqd.sqd, current, SEEK_SET);
  rread (ttarea->sqd.sqd, &pcurr, 28, __FILE__, __LINE__);
  while (current && pcurr.frlength < (msgsize - sqbuf.szsqhdr))
    {
      current = pcurr.next;
      if (current)
  if (sqread (ttarea, current, &pcurr, __FILE__, __LINE__) == -1)
    return -1;
    }
  if (current)
    {
      if (current == sqbuf.firstf)
  sqbuf.firstf = pcurr.next;
      if (current == sqbuf.lastf)
  sqbuf.lastf = pcurr.prev;
      if (pcurr.prev)
  {
    if (sqread (ttarea, pcurr.prev, &pprev, __FILE__, __LINE__) == -1)
      return -1;
    pprev.next = pcurr.next;
    lseek (ttarea->sqd.sqd, pcurr.prev, SEEK_SET);
    wwrite (ttarea->sqd.sqd, &pprev, 28, __FILE__, __LINE__);
  }
      if (pcurr.next)
  {
    if (sqread (ttarea, pcurr.next, &pnext, __FILE__, __LINE__) == -1)
      return -1;
    pnext.prev = pcurr.prev;
    lseek (ttarea->sqd.sqd, pcurr.next, SEEK_SET);
    wwrite (ttarea->sqd.sqd, &pnext, 28, __FILE__, __LINE__);
  }
      prev = sqbuf.last;
      if (prev)
  {
    if (sqread (ttarea, prev, &pprev, __FILE__, __LINE__) == -1)
      return -1;
    pcurr.prev = prev;
    pprev.next = current;
    lseek (ttarea->sqd.sqd, prev, SEEK_SET);
    wwrite (ttarea->sqd.sqd, &pprev, 28, __FILE__, __LINE__);
  }
      else
  {
    sqbuf.first = current;
    pcurr.prev = 0;
  }
    }
  else
    {
      current = sqbuf.endf;
      prev = sqbuf.last;
      if (prev)
  {
    if (sqread (ttarea, prev, &pprev, __FILE__, __LINE__) == -1)
      return -1;
    pcurr.prev = prev;
    pprev.next = current;
    pcurr.frlength = 0;
    lseek (ttarea->sqd.sqd, prev, SEEK_SET);
    wwrite (ttarea->sqd.sqd, &pprev, 28, __FILE__, __LINE__);
  }
    }
  pcurr.next = 0;
  sqbuf.last = current;
  if (!sqbuf.first)
    sqbuf.first = current;
  lseek (ttarea->sqd.sqd, current, SEEK_SET);
  sqhead.ident = 0xAFAE4453L;
  sqhead.next = pcurr.next;
  sqhead.prev = pcurr.prev;
  sqhead.frlength = pcurr.frlength;
  sqhead.msglength = msgsize - sqbuf.szsqhdr + (type == 1 ? 1 : 0);
  if (type == 1)
    {
      sqhead.msglength -= pkludnum;
      sqhead.clen = pkludlen - pkludnum + 1;
      if (!wipearea && !netmail)
  sqhead.clen++;
    }
  else
    {
      if (skludlen)
  sqhead.clen = skludlen + 1;
      else
  {
    sqhead.clen = 0;
  }
    }
  if (wipearea)
    {
      sqhead.clen -= arealen;
      if (mode & 2048)
  sqhead.clen--;
    }
  if (bcfg.delkl && kill2)
    sqhead.clen -= lkludlen;
  if ((mode & 2048) && (ttarea->type == 3 || ttarea->type == 2))
    sqhead.clen += arealen + 1;
  if (sqhead.clen == 0)
    sqhead.clen = 1;
  if (sqhead.frlength < sqhead.msglength)
    sqhead.frlength = sqhead.msglength;
  sqhead.frametype = sqhead.reserved = sqhead.flags2 = 0;
  if (bigmess)
    {
      lseek (tempfile, 0, SEEK_SET);
      rread (tempfile, buftemp->toname, (unsigned short)(tolen + 1), __FILE__,
       __LINE__);
      rread (tempfile, buftemp->fromname, (unsigned short)(fromlen + 1),
       __FILE__, __LINE__);
      rread (tempfile, buftemp->subj, (unsigned short)(subjlen + 1), __FILE__,
       __LINE__);
    }
  mystrncpy (sqhead.fromname, buftemp->fromname, 35);
  mystrncpy (sqhead.toname, buftemp->toname, 35);
  mystrncpy (sqhead.subj, buftemp->subj, 71);
  sqhead.fromzone = pktaddr.zone;
  sqhead.fromnet = pktaddr.net;
  sqhead.fromnode = pktaddr.node;
  sqhead.frompoint = pktaddr.point;
  sqhead.tozone = buftemp->tozone ? buftemp->tozone : buftemp->fromzone;
  sqhead.tonet = buftemp->tonet;
  sqhead.tonode = buftemp->tonode;
  sqhead.topoint = buftemp->topoint;
  sqhead.timefrom = buftemp->timefrom;
  sqhead.timeto = buftemp->timeto;

  if (ttarea->type == 2)
    {
      logprintf (
         "* Message in area %s from %s to %s (%s) moved to BadArea",
         curarea, sqhead.fromname, sqhead.toname, sqhead.subj);
      logwrite (1, 6);
      switch (badtype)
  {
  case 1:
    logprintf ("** Reason: Corrupted packet from %u:%u/%u.%u",
       pktaddr.zone, pktaddr.net, pktaddr.node, pktaddr.point);
    break;
  case 2:
    logprintf ("** Reason: Unknown area %s", curarea);
    break;
  case 3:
    logprintf ("** Reason: Read-Only area %s", curarea);
    break;
  case 4:
    logprintf (
       "** Reason: Security violation (packet from %u:%u/%u.%u)",
       pktaddr.zone, pktaddr.net, pktaddr.node, pktaddr.point);
    break;
  case 5:
    logprintf ("** Reason: Locked area %s", curarea);
    break;
  }
      logwrite (1, 6);
    }

  if (posting)
    sqhead.flags = (short)(buftemp->flags & 0x50d);
  else
    sqhead.flags = (short)(buftemp->flags & 0x40d);
  if (mode & 128 || gpers)
    sqhead.flags2 = flags2;
  else if (both)
    {
      sqhead.flags2 = 1;
      sqbuf.highwater++;
    }
  if (gpers && bcfg.setloc)
    sqhead.flags |= 0x100;
  mystrncpy (sqhead.datetime, buftemp->datetime, 19);
  if (nowpurge)
    {
      sqhead.fromzone = pfrom.zone;
      sqhead.fromnet = pfrom.net;
      sqhead.fromnode = pfrom.node;
      sqhead.frompoint = pfrom.point;
      sqhead.tozone = pto.zone;
      sqhead.tonet = pto.net;
      sqhead.tonode = pto.node;
      sqhead.topoint = pto.point;
    }
  lseek (ttarea->sqd.sqd, current, SEEK_SET);
  wwrite (ttarea->sqd.sqd, &sqhead, 266, __FILE__, __LINE__);
  reallen = 266;
  tislen = 0;
  while (tkludge)
    {
      if (wipearea && !isarea)
  {
    if (memcmp (tkludge->str, "AREA:", 5) == 0)
      {
        isarea = 1;
        goto nextkl;
      }
    if ((mode & 2048) && (ttarea->type != 3 && ttarea->type != 2))
      {
        if (memcmp (tkludge->str, "\1AREA:", 6) == 0)
    {
      isarea = 1;
      goto nextkl;
    }
      }
  }
      if (!(bcfg.delkl && tkludge->left && kill2))
  {
    if ((memcmp (tkludge->str, "AREA:", 5) == 0)
        && (ttarea->type == 2 || ttarea->type == 3 || mustcopy))
      {
        if (!isdog)
    {
      memcpy (klbuf + (unsigned)tislen, one1, 1);
      tislen++;
      reallen++;
      isdog = 1;
    }
      }
    memcpy (klbuf + (unsigned)tislen, tkludge->str,
      strlen (tkludge->str));
    tislen += strlen (tkludge->str);
    reallen += strlen (tkludge->str);
  }
    nextkl:
      tkludge = tkludge->next;
    }
  if ((type == 2) || pckludge)
    {
      memcpy (klbuf + (unsigned)tislen, null1, 1);
      tislen++;
      reallen++;
    }
  wwrite (ttarea->sqd.sqd, klbuf, (unsigned short)(tislen), __FILE__,
    __LINE__);
  myfree ((void **)&klbuf, __FILE__, __LINE__);
  if (mustcopy)
    {
      mywrite (ttarea->sqd.sqd, copystr, __FILE__, __LINE__);
      reallen += strlen (copystr);
    }
  if (bigmess)
    {
      while ((fmax2 =
        (unsigned short)rreadz (tempfile, tsbuf, buflen, __FILE__,
             __LINE__)) != 0)
  {
    if ((bcfg.delinfo && !ttarea->saveci) && kill2 && ttarea->type == 1)
      {
//          if(type==1)
        switch (bcfg.delinfo)
    {
    case 1:
      temp = locseenby (tsbuf);
      break;
    case 2:
      temp = locpath (tsbuf);
      if (temp != NULL)
        temp = strchr (temp, 0);
      else
        temp = locseenby (tsbuf);
      break;
    }
//          else
//              temp=locseenby(tsbuf);
        if (temp && ((temp - tsbuf) < fmax2))
    {
      wwrite (ttarea->sqd.sqd, tsbuf,
        (unsigned short)(temp - tsbuf), __FILE__, __LINE__);
      reallen += (temp - tsbuf);
      break;
    }
        else
    {
      wwrite (ttarea->sqd.sqd, tsbuf, fmax2, __FILE__, __LINE__);
      reallen += fmax2;
    }
      }
    else
      {
        wwrite (ttarea->sqd.sqd, tsbuf, fmax2, __FILE__, __LINE__);
        reallen += fmax2;
      }
  }
    }
  else
    {
      if (textlen > 0)
  {
    if (type == 1 || kill)
      {
        if ((bcfg.delinfo && !ttarea->saveci) && kill2
      && ttarea->type == 1)
    {
      switch (bcfg.delinfo)
        {
        case 1:
          temp = locseenby (buftemp->text);
          break;
        case 2:
          temp = locpath (buftemp->text);
          if (temp != NULL)
      temp = strchr (temp, 0);
          else
      temp = locseenby (buftemp->text);
          break;
        }
      if (temp && ((temp - buftemp->text) < textlen))
        {
          wwrite (ttarea->sqd.sqd, buftemp->text,
            (unsigned short)(temp - buftemp->text),
            __FILE__, __LINE__);
          reallen += (temp - buftemp->text);
        }
      else
        {
          wwrite (ttarea->sqd.sqd, buftemp->text,
            (unsigned short)(textlen), __FILE__, __LINE__);
          reallen += textlen;
        }
    }
        else
    {
      wwrite (ttarea->sqd.sqd, buftemp->text,
        (unsigned short)(textlen), __FILE__, __LINE__);
      reallen += textlen;
    }
      }
    else
      {
        wwrite (ttarea->sqd.sqd, buftemp->text,
          (unsigned short)(textlen), __FILE__, __LINE__);
        reallen += textlen;
      }
  }
    }
  if (addorig)
    {
      mywrite (ttarea->sqd.sqd, tail, __FILE__, __LINE__);
      reallen += strlen (tail);
    }
  wwrite (ttarea->sqd.sqd, null1, 1, __FILE__, __LINE__);
  if (kill2)
    reallen++;
  reallen -= sqbuf.szsqhdr;
/*
  if(reallen!=sqhead.msglength)
   {
    logprintf("??? WARNING! Area %s, message %lu - size mismatch",
            ttarea->areaname,sqbuf.nummsg);
    logwrite(1,4);
   }
*/
  sqbuf.nummsg++;
  sqbuf.highmsg++;
  sqbuf.endf = filelength (ttarea->sqd.sqd);
  lseek (ttarea->sqd.sqd, 0, SEEK_SET);
  wwrite (ttarea->sqd.sqd, &sqbuf, 256, __FILE__, __LINE__);
  flushbuf (ttarea->sqd.sqd);
  ttarea->curindex = ((sqbuf.nummsg - 1) / bufsqi) * bufsqi;
  lseek (ttarea->sqd.sqi, ttarea->curindex * 12, SEEK_SET);
  rread (ttarea->sqd.sqi, tindex, (unsigned short)(bufsqi * 12), __FILE__,
   __LINE__);
  sqibuf.offset = current;
  if (nowpurge)
    sqibuf.hash = curhash;
  else
    sqibuf.hash = hash (sqhead.toname);
  memcpy (&tindex[(unsigned)(sqbuf.nummsg - ttarea->curindex - 1)], &sqibuf,
    12);
  lseek (ttarea->sqd.sqi, ttarea->curindex * 12, SEEK_SET);
  wwrite (ttarea->sqd.sqi, tindex,
    (unsigned
     short)((((sqbuf.nummsg - ttarea->curindex) >
        bufsqi) ? bufsqi : sqbuf.nummsg - ttarea->curindex) * 12),
    __FILE__, __LINE__);
  flushbuf (ttarea->sqd.sqi);
  if (!ttarea->logged)
    {
      if (mustlog /* && !(mode&160) */ )
  inecholog (ttarea->areaname);
      ttarea->logged = 1;
    }
  if (pcreate && bcfg.echosem[0])
    {
      cclose (&dupreserv, __FILE__, __LINE__);
      msg =
  (short)sopen (bcfg.echosem, O_RDWR | O_BINARY | O_CREAT, SH_DENYNO,
          S_IRWXU | S_IRWXG | S_IRWXO);
      if (msg != -1)
  cclose (&msg, __FILE__, __LINE__);
      if ((dupreserv = (short)open (NULL_DEV, O_WRONLY)) == -1)
  {
    mystrncpy (errname, NULL_DEV, DirSize);
    errexit (2, __FILE__, __LINE__);
  }
    }
  return 0;
}

short sqread (struct area *tarea, long pos, struct pointers *pnt, char *file,
        short line)
{
  lseek (tarea->sqd.sqd, pos, SEEK_SET);
  rread (tarea->sqd.sqd, pnt, 28, file, line);
  if (pnt->ident != 0xAFAE4453L)
    {
      badlog (tarea);
      logprintf ("BackUp: Area %s is corrupted", tarea->areaname);
      logwrite (1, 3);
      backup (0);
//    errexit(12,file,line);
      globbad = 1;
      return -1;
    }
  return 0;
}
