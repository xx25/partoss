// MaxiM: strupr strchr

#include "partoss.h"
#include "globext.h"

#include "buftopkt.h"
#include "arealias.h"
#include "lowlevel.h"
#include "morfiles.h"
#include "errors.h"
#include "times.h"
#include "control.h"
#include "headers.h"
#include "chains.h"

void buftopkt (short type)
{
  struct myaddr *taddr = NULL, *link = NULL, *glink = NULL;
  struct shortaddr *tsnb = NULL;
  struct zgate *zg = NULL;
  struct kludge *tkludge = NULL;
  struct link *blink = NULL;
  struct dngate *tdn = NULL;
  struct packmess tmess;
  long tolen = 0, fromlen = 0, subjlen = 0, textlen = 0, bigmess = 0;
  short bflags = 0, match = 0;
  unsigned short fmax2 = 0;
  short tempfile = 0, i = 0, j = 0;
  long tlmt = 0;
  struct tm ttmt;
  char *temp = NULL, *temp2 = NULL, *tbuf = NULL, msgid[9], *null3 = "\0\0\0";
  struct pool *tpool = NULL, *ttpool = NULL;
  char oufn[DirSize + 1];
  short ouf;
  switch (type)
    {
    case 1:
    case 4:
      tolen = ptolen;
      fromlen = pfromlen;
      subjlen = psubjlen;
      textlen = ptextlen;
      buftemp = &bufpkt;
      tbuf = pktbuf;
      bigmess = pbigmess;
      tempfile = temppkt;
      tkludge = pckludge;
      break;
    case 2:
      tolen = stolen;
      fromlen = sfromlen;
      subjlen = ssubjlen;
      textlen = stextlen;
      buftemp = &bufsqd;
      tbuf = sqdbuf;
      bigmess = sbigmess;
      tempfile = tempsqd;
      tkludge = sckludge;
      break;
    case 3:
      tolen = mtolen;
      fromlen = mfromlen;
      subjlen = msubjlen;
      textlen = mtextlen;
      buftemp = &bufmess;
      tbuf = pktbuf;
      bigmess = mbigmess;
      tempfile = temppkt;
      tkludge = mckludge;
      break;
    }
  if (textlen > 0)
    textlen--;
  bflags = buftemp->flags;
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
  if (type != 4)
    {
      blink = bcfg.links.chain;
      while (blink)
  {
    if (buftemp->fromzone == blink->address.zone &&
        buftemp->fromnet == blink->address.net &&
        buftemp->fromnode == blink->address.node &&
        buftemp->frompoint == blink->address.point)
      break;
    blink = blink->next;
  }
      if (blink)
  {
    fake = blink->fake;
//      if(blink->password[0])
//        memcpy(tpack->password,blink->password,8);
  }
      else
  {
    fake = 0;
//      memset(tpack->password,0,8);
  }
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
        if ((temp = strstr (tdn->where, "*")) != NULL)
    {
      if (strnicmp
          (newarea->areaname, tdn->where,
           (unsigned)(temp - tdn->where)) == 0)
        goto matched;
    }
        else if (stricmp (newarea->areaname, tdn->where) == 0)
    goto matched;
      }
    goto unmatch;
  matched:
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
      && ((tpack->outaddr.zone == tdn->to.zone)
          || (tdn->to.zone == 65535u))
      && ((tpack->outaddr.net == tdn->to.net)
          || (tdn->to.net == 65535u))
      && ((tpack->outaddr.node == tdn->to.node)
          || (tdn->to.node == 65535u))
      && ((tpack->outaddr.point == tdn->to.point)
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
      if (((tpack->outaddr.zone == tdn->to.zone)
           || (tdn->to.zone == 65535u))
          && ((tpack->outaddr.net == tdn->to.net)
        || (tdn->to.net == 65535u))
          && ((tpack->outaddr.node == tdn->to.node)
        || (tdn->to.node == 65535u))
          && ((tpack->outaddr.point == tdn->to.point)
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
      if (match && (tdn->changes & 1))
  {
    if (tdn->aka.zone)
      {
        glink = &tdn->aka;
        if (tdn->aka.point == 65535u)
    glink->point = buftemp->frompoint;
      }
    else
      {
        glink = bcfg.address.chain;
        while (glink)
    {
      if (glink->point || tpack->outaddr.point)
        {
          if ((glink->zone == tpack->outaddr.zone) &&
        (glink->net == tpack->outaddr.net) &&
        (glink->node == tpack->outaddr.node))
      break;
        }
      else if (glink->zone == tpack->outaddr.zone)
        break;
      glink = glink->next;
    }
        if (glink == NULL)
    glink = bcfg.address.chain;
      }
  }
      else
  glink = &newarea->myaka;
/*
      buftemp->fromzone=glink->zone;
      buftemp->fromnet=glink->net;
      buftemp->fromnode=glink->node;
      buftemp->frompoint=glink->point;
*/
    }
  if (!tpack->touched)
    {
      temp = strrchr (tpack->name, DIRSEP[0]);
      if (temp)
  temp++;
      else
  temp = tpack->name;
      if (type != 4)
  logprintf ("Create packet %s from %u:%u/%u.%u to %u:%u/%u.%u",
     temp, tpack->fromaddr.zone, tpack->fromaddr.net,
     tpack->fromaddr.node, tpack->fromaddr.point,
     tpack->outaddr.zone, tpack->outaddr.net, tpack->outaddr.node,
     tpack->outaddr.point);
      else
  logprintf ("??? Create temporary packet");
      logwrite (1, 3);
      if (!quiet)
  ccprintf ("\r\n%s\r\n", logout);
      writehead ();
    }
  else
    lseek (tpack->handle, -2L, SEEK_END);
  buftemp->packtype = 2;
  memcpy (&tmess, buftemp, 34);
  if (type != 3)
    {
      buftemp->tozone = tpack->outaddr.zone;
      buftemp->tonet = tpack->outaddr.net;
      buftemp->tonode = tpack->outaddr.node;
      buftemp->topoint = tpack->outaddr.point;
      buftemp->fromnet = tpack->fromaddr.net;
      buftemp->fromnode = tpack->fromaddr.node;
    }
  if (type != 4)
    {
      if (fake)
  buftemp->frompoint = 0;
      buftemp->flags &= 0x7493; // Zero some attributes
      if (buftemp->datetime[0] == 0)
  {
    if (buftemp->timefrom == 0)
      {
        sftime = time (NULL);
        mylocaltime (&sftime, &tmt);
      }
    else
      {
        tlmt = buftemp->timefrom;
        i = (short)tlmt;
        j = (short)(tlmt >> 16);
        tlmt = i;
        tlmt <<= 16;
        tlmt += j;
        memcpy (&ttmt, &tlmt, szlong);
        tmt.tm_year = ttmt.tm_year + 80;
        tmt.tm_mon = ttmt.tm_mon;
        tmt.tm_mday = ttmt.tm_mday;
        tmt.tm_hour = ttmt.tm_hour;
        tmt.tm_min = ttmt.tm_min;
        tmt.tm_sec = ttmt.tm_sec << 1;
      }
    mystrncpy (tstrtime, asctime (&tmt), 39);
    converttime (tstrtime);
    mystrncpy (buftemp->datetime, ftstime, 19);
  }
    }
  wwrite (tpack->handle, buftemp, 34, __FILE__, __LINE__);
  wwrite (tpack->handle, buftemp->toname, (unsigned short)(tolen + 1),
    __FILE__, __LINE__);
  wwrite (tpack->handle, buftemp->fromname, (unsigned short)(fromlen + 1),
    __FILE__, __LINE__);
  wwrite (tpack->handle, buftemp->subj, (unsigned short)(subjlen + 1),
    __FILE__, __LINE__);
  memcpy (buftemp, &tmess, 34);
  while (tkludge)
    {
      if (strncmp (tkludge->str, "AREA:", 5) == 0)
  {
    char *tmpareaname = tkludge->str + 5;
    //printf("tmpareaname=%s\n",tmpareaname);
    tmpareaname = areaaliasrestorer (tmpareaname);
    //printf("tmpareaname=%s\n",tmpareaname);
    if (tmpareaname == NULL)
      {
        mywrite (tpack->handle, tkludge->str, __FILE__, __LINE__);
        if (tkludge->str[strlen (tkludge->str) - 1] != '\r')
    mywrite (tpack->handle, "\r", __FILE__, __LINE__);
      }
    else
      {
        mywrite (tpack->handle, "AREA:", __FILE__, __LINE__);
        mywrite (tpack->handle, tmpareaname, __FILE__, __LINE__);
        if (tmpareaname[strlen (tmpareaname) - 1] != '\r')
    mywrite (tpack->handle, "\r", __FILE__, __LINE__);
      }
    goto msgidc;
  }
      if (strncmp (tkludge->str, "\1Reason:", 8) == 0)
  goto msgidc;
      if (strncmp (tkludge->str, "\1MSGID: ", 8) == 0)
  {
    if (fake)
      {
        temp = strchr (tkludge->str, '.');
        if (temp)
    {
      temp++;
      *temp = '0';
      temp++;
      temp2 = temp;
      while (isdigit (*temp2))
        temp2++;
      pkludlen -= (unsigned short)(temp2 - temp);
      while (*temp2)
        {
          *temp = *temp2;
          temp++;
          temp2++;
        }
      *temp = 0;
    }
      }
    else
      {
        if (match && tdn->changes & 2)
    {
      sftime = time (NULL);
      times = sftime + nummsg;
      nummsg++;
      hexascii (times, strtimes);
      mystrncpy (msgid, strtimes, 8);
      msgid[8] = 0;
      logprintf ("\1MSGID: %u:%u/%u.%u %s\r", tdn->aka.zone,
         tdn->aka.net, tdn->aka.node, tdn->aka.point,
         msgid);
      mywrite (tpack->handle, logout, __FILE__, __LINE__);
      tkludge = tkludge->next;
      goto msgidc;
    }
      }
  }
      if (!(fake && (strncmp (tkludge->str, "\1FMPT ", 6) == 0)))
  {
    mywrite (tpack->handle, tkludge->str, __FILE__, __LINE__);
    if (tkludge->str[strlen (tkludge->str) - 1] != '\r')
      mywrite (tpack->handle, "\r", __FILE__, __LINE__);
  }
    msgidc:
      tkludge = tkludge->next;
    }
  if (bigmess)
    {
      while ((fmax2 =
        (unsigned short)rreadz (tempfile, tbuf, buflen, __FILE__,
             __LINE__)) != 0)
  {
    if (match && tdn->changes & 4)
      {
        temp = strstr (tbuf, " * Origin: ");
        if (temp)
    {
      if (tdn->origin[0])
        {
          wwrite (tpack->handle, tbuf,
            (unsigned short)(temp - tbuf + 11), __FILE__,
            __LINE__);
          mywrite (tpack->handle, tdn->origin, __FILE__,
             __LINE__);
        }
      else
        {
          temp = strchr (temp, '\r');
          while (*temp != '(')
      temp--;
          wwrite (tpack->handle, tbuf,
            (unsigned short)(temp - tbuf), __FILE__,
            __LINE__);
        }
      logprintf ("(%u:%u/%u.%u)\r", glink->zone,
         glink->net, glink->node, glink->point);
      mywrite (tpack->handle, logout, __FILE__, __LINE__);
    }
        else
    wwrite (tpack->handle, tbuf, fmax2, __FILE__, __LINE__);
      }
    else
      {
        fakeorigin (fake, tbuf, fmax2);
        if (type < 3)
        {
           temp = locseenby (tbuf, 0);
           if ((bcfg.delinfo == 2) && (temp == NULL))
              temp = locpath (tbuf, 0);
        };
        if (temp == NULL || type > 2)
    {
      if (fmax2 == buflen)
        wwrite (tpack->handle, tbuf, fmax2, __FILE__, __LINE__);
      else
        {
          wwrite (tpack->handle, tbuf, fmax2, __FILE__, __LINE__);
          if (tbuf[fmax2 - 1] != '\r')
      {
        lseek (tpack->handle, -1L, SEEK_CUR);
        mywrite (tpack->handle, "\r", __FILE__, __LINE__);
      }
        }
    }
        else
    {
      wwrite (tpack->handle, tbuf, (unsigned short)(temp - tbuf),
        __FILE__, __LINE__);
      break;
    }
      }
  }
    }
  else
    {
      if (match && tdn->changes & 4)
  {
    temp = strstr (buftemp->text, " * Origin: ");
    if (temp)
      {
        if (tdn->origin[0])
    {
      wwrite (tpack->handle, buftemp->text,
        (unsigned short)(temp - buftemp->text + 11),
        __FILE__, __LINE__);
      mywrite (tpack->handle, tdn->origin, __FILE__, __LINE__);
    }
        else
    {
      temp = strchr (temp, '\r');
      while (*temp != '(')
        temp--;
      wwrite (tpack->handle, buftemp->text,
        (unsigned short)(temp - buftemp->text), __FILE__,
        __LINE__);
    }
        logprintf (" (%u:%u/%u.%u)\r", glink->zone,
           glink->net, glink->node, glink->point);
        mywrite (tpack->handle, logout, __FILE__, __LINE__);
      }
    else
      wwrite (tpack->handle, buftemp->text, (unsigned short)(textlen),
        __FILE__, __LINE__);
  }
      else
  {
    fakeorigin (fake, buftemp->text, textlen);
    if (type < 3)
    {
       temp = locseenby (buftemp->text);
       if ((bcfg.delinfo == 2) && (temp == NULL))
           temp = locpath (buftemp->text);
    };
    if (temp == NULL || type > 2)
      {
        if (textlen > 0)
    {
      if (buftemp->text[(unsigned)(textlen - 1)] == 0)
        textlen--;
      wwrite (tpack->handle, buftemp->text,
        (unsigned short)(textlen), __FILE__, __LINE__);
      if (buftemp->text[(unsigned)(textlen - 1)] != '\r')
        mywrite (tpack->handle, "\r", __FILE__, __LINE__);
    }
      }
    else
      wwrite (tpack->handle, buftemp->text,
        (unsigned short)(temp - buftemp->text), __FILE__,
        __LINE__);
  }
    }
  if (type == 4)
    goto endwork;
  if (type == 3)
    {
//    if(!(bflags&0x100))
//     {
      sftime = time (NULL);
      mylocaltime (&sftime, &tmt);
      mystrncpy (tstrtime, asctime (&tmt), 39);
      converttime (tstrtime);
/*
      logprintf("\1Via %u:%u/%u.%u @%4d%02d%02d.%02d%02d%02d ParToss %s\r",
      tpack->fromaddr.zone,tpack->fromaddr.net,tpack->fromaddr.node,tpack->fromaddr.point,
      tmt->tm_year,tmt->tm_mon,tmt->tm_mday,tmt->tm_hour,tmt->tm_min,tmt->tm_sec,version);
*/
      logprintf ("\1Via ParToss %s %u:%u/%u.%u, %s\r", version,
         tpack->fromaddr.zone, tpack->fromaddr.net,
         tpack->fromaddr.node, tpack->fromaddr.point, ftstime);
      mywrite (tpack->handle, logout, __FILE__, __LINE__);
//     }
    }
  else
    {
      if (match && tdn->changes & 8)
  {
    tnsnb.chain = tnsnb.last = NULL;
    tnsnb.numelem = 0;
    addshort (&tnsnb, tpack->fromaddr.net, tpack->fromaddr.node);
    link = newarea->links.chain;
    while (link)
      {
        if (glink->zone == link->zone && link->point == 0)
    {
      tsnb = tnsnb.chain;
      while (tsnb)
        {
          if (tsnb->net == link->net && tsnb->node == link->node)
      break;
          tsnb = tsnb->next;
        }
      if (tsnb == NULL)
        addshort (&tnsnb, link->net, link->node);
    }
        link = link->next;
      }
    sortsnb (&tnsnb);
    writechain (tpack->handle, &tnsnb, 1);
    delshort (&tnsnb);
    addshort (&tnsnb, glink->net, glink->node);
    writechain (tpack->handle, &tnsnb, 2);
    delshort (&tnsnb);
  }
      else
  {
    taddr = bcfg.tinysb.chain;
    tnsnb.chain = tnsnb.last = NULL;
    tnsnb.numelem = 0;
    while (taddr)
      {
        if (cmpaddrw (taddr, tsend) == 0)
    break;
        taddr = taddr->next;
      }
    if (taddr)
      {
        addshort (&tnsnb, newarea->myaka.net, newarea->myaka.node);
        link = newarea->links.chain;
        while (link)
    {
      if (newarea->myaka.zone == link->zone && link->point == 0
          && !link->passive)
        {
          tsnb = tnsnb.chain;
          while (tsnb)
      {
        if (tsnb->net == link->net
            && tsnb->node == link->node)
          break;
        tsnb = tsnb->next;
      }
          if (tsnb == NULL)
      addshort (&tnsnb, link->net, link->node);
        }
      link = link->next;
    }
        sortsnb (&tnsnb);
        writechain (tpack->handle, &tnsnb, 1);
        delshort (&tnsnb);
        addshort (&tnsnb, newarea->myaka.net, newarea->myaka.node);
        writechain (tpack->handle, &tnsnb, 2);
        delshort (&tnsnb);
      }
    else
      {
        if (tsend->zone == newarea->myaka.zone)
    {
      writechain (tpack->handle, (type == 1 ? &psnb : &ssnb), 1);
      writechain (tpack->handle, (type == 1 ? &ppath : &spath),
            2);
    }
        else
    {
      zg = bcfg.zonegate;
      while (zg)
        {
          if (cmpaddr (&(zg->address), tsend) == 0)
      break;
          zg = zg->next;
        }
      if (zg)
        writechain (tpack->handle, &(zg->zseen), 1);
//          else
      if (bcfg.savepath)
        writechain (tpack->handle, (type == 1 ? &ppath : &spath),
        2);
    }
      }
  }
    }
endwork:
  wwrite (tpack->handle, null3, 3, __FILE__, __LINE__);
  flushbuf (tpack->handle);
  if (glpool)
    {
      tpool = glpool;
      mystrncpy (oufn, tpack->name, DirSize);
      temp = strrchr (oufn, '.');
      if (temp)
  (*temp) = 0;
      mystrncat (oufn, (char *)".ouf", 6, DirSize);
      if ((ouf = (short)open (oufn, O_RDWR | O_BINARY)) == -1)
  {
    if ((ouf = (short)open (oufn, O_RDWR | O_BINARY | O_CREAT,
				 S_IREAD | S_IWRITE)) == -1)
      {
        mystrncpy (errname, oufn, DirSize);
        errexit (2, __FILE__, __LINE__);
      }
  }
      lseek (ouf, 0, SEEK_END);
      while (tpool)
  {
    logprintf ("%s\r", tpool->fullname);
    tpool = tpool->next;
  }
      cclose (&ouf, __FILE__, __LINE__);
      tpool = glpool;
      while (tpool)
  {
    ttpool = tpool->next;
    myfree ((void **)&(tpool->fullname), __FILE__, __LINE__);
    myfree ((void **)&(tpool->shortname), __FILE__, __LINE__);
    myfree ((void **)&(tpool->type), __FILE__, __LINE__);
    myfree ((void **)&(tpool), __FILE__, __LINE__);
    tpool = ttpool;
  }
      glpool = NULL;
    }
}

void fakeorigin (short fake, char *buf, long len)
{
  char *temp = NULL, *temp2 = NULL;
  if (fake)
    {
      temp = strstr (buf, " * Origin");
      if (temp)
  {
    while (*temp != '\r' && *temp != '\n' && (temp - buf) < len)
      temp++;
    while (*temp != '.')
      temp--;
    temp++;
    *temp = '0';
    temp++;
    temp2 = temp;
    while (isdigit (*temp2))
      temp2++;
    while (*temp2 != '\r' && *temp2 != '\n' && (temp2 - buf) < len)
      {
        *temp = *temp2;
        temp++;
        temp2++;
      }
    while (temp != temp2)
      {
        *temp = ' ';
        temp++;
      }
  }
    }
}
