// MaxiM: itoa memicmp

#include "partoss.h"
#include "globext.h"

#include "control.h"
#include "arealias.h"
#include "lowlevel.h"
#include "chains.h"
#include "partsqd.h"
#include "morfiles.h"

char *kludges[10] = {
  "AREA:",
  "\1MSGID: ",
  "\1REPLY: ",
  "\1INTL ",
  "\1FMPT ",
  "\1TOPT ",
  "\1FLAGS ",
  "\1AREA:",
  "\1ATTACN:"
};

void writechain (short handle, struct shortchain *chain, short type)
{
  struct shortaddr *tsnb = NULL;
  char curnode[13], cstring[81], temp[8];
  unsigned short net, i = 0;
  mystrncpy (cstring,(char *)( type == 1 ? "SEEN-BY:" : "\1PATH:"), 10);
  tsnb = chain->chain;
  net = 0;
  memset (temp, 0, 8);
  for (i = 0; i < chain->numelem; i++)
    {
      if (!tsnb->hide)
  {
    mystrncpy (curnode, " ", 2);
    if (tsnb->net != net)
      {
        mystrncat (curnode, (char *)itoa (tsnb->net, temp, 10), 8, 12);
        mystrncat (curnode, "/", 2, 12);
      }
    mystrncat (curnode, itoa (tsnb->node, temp, 10), 8, 12);
    if (strlen (cstring) + strlen (curnode) >= 77)
      {
        mystrncat (cstring, "\r", 2, 80);
        mywrite (handle, cstring, __FILE__, __LINE__);
        mystrncpy (cstring,(char *)( type == 1 ? "SEEN-BY:" : "\1PATH:"), 10);
        net = 0, i--;
      }
    else
      {
        net = tsnb->net;
        mystrncat (cstring, curnode, 15, 80);
        tsnb = tsnb->next;
      }
  }
      else
  tsnb = tsnb->next;
    }
  if (net)
    {
      mystrncat (cstring, "\r", 2, 80);
      mywrite (handle, cstring, __FILE__, __LINE__);
    }
}

void readchain (short type, short subtype)
{
  short curnet = 0, curnode = 0, tmp = 0, tmp2 = 0;
  while (1)
    {
      tmp = (short)atoi (point);
      while (isdigit (*point))
  point++;
      if (point && (*point) == '/')
  {
    point++;
    tmp2 = tmp;
    curnet = tmp;
    curnode = (short)atoi (point);
    while (isdigit (*point))
      point++;
  }
      else
  curnode = tmp;
      if ((curnet != bcfg.delseen.net) || (curnode != bcfg.delseen.node))
  addshort (&
      (type ==
       1 ? (subtype == 1 ? psnb : ssnb) : (subtype ==
                   1 ? ppath : spath)),
      curnet, curnode);
      else
  tmp = tmp2;
      while ((*point) && !isspace (*point))
  point++;
      while ((*point) && isspace (*point))
  point++;
      if (point && !(*point))
  break;
      if (point
    &&
    ((type ==
      1 ? strncmp (point, "SEEN-BY", 7) : strncmp (point, "\1PATH",
               5)) == 0))
  {
    while ((*point) && !isspace (*point))
      point++;
    while ((*point) && isspace (*point))
      point++;
  }
      else
  if (point && !isdigit (*point)
      &&
      ((type ==
        1 ? strncmp (point, "SEEN-BY", 7) : strncmp (point, "\1PATH",
                 5)) != 0))
  break;
    }
}

// bolstart: buf itself is at the start of a line (message text), not a
// block read from the middle of one
char *locseenby (char *buf, short bolstart)
{
  char *temp = NULL, *temp2 = NULL;
  temp = strstr (buf, "SEEN-BY: ");
  while (temp)
    {
      temp2 = temp;
      while (temp2 > buf && (temp2[-1] == '\n'))
  temp2--;
      if (temp2 > buf ? (temp2[-1] == '\r') : bolstart)
  return temp;
      temp2 = temp + 1;
      temp = strstr (temp2, "SEEN-BY: ");
    }
  return NULL;
}

char *locpath (char *buf, short bolstart)
{
  char *temp = NULL, *temp2 = NULL;
  temp = strstr (buf, "\1PATH: ");
  while (temp)
    {
      temp2 = temp;
      while (temp2 > buf && (temp2[-1] == '\n'))
  temp2--;
      if (temp2 > buf ? (temp2[-1] == '\r') : bolstart)
  return temp;
      temp2 = temp + 1;
      temp = strstr (temp2, "\1PATH: ");
    }
  return NULL;
}

void parsesnb (char *temp, short type)
{
  struct myaddr tsnd, *link = NULL, *taddr = NULL;
  struct shortaddr *tsnb = NULL;
  ((type == 1) ? psnb.chain : ssnb.chain) = NULL;
  ((type == 1) ? ppath.chain : spath.chain) = NULL;
  ((type == 1) ? psnb.last : ssnb.last) = NULL;
  ((type == 1) ? ppath.last : spath.last) = NULL;
  ((type == 1) ? psnb.numelem : ssnb.numelem) = 0;
  ((type == 1) ? ppath.numelem : spath.numelem) = 0;
  short present = 0, i = 0;
  if (temp)
    {
      point = temp + 9;
      readchain (1, type);
      if (point && point[0] == '\1')
  {
    point += 7;
    readchain (2, type);
  }
    }
  if (type == 1 && !(newarea->myaka.point) && bcfg.lookpath)
    {
      tsnb = ppath.chain;
      for (i = 0; i < ppath.numelem; i++)
  {
    if (tsnb->net == newarea->myaka.net
        && tsnb->node == newarea->myaka.node && tsnb->next)
      {
        isdupe = 2;
        //
        // For Jury Fradkin
        //
        if (bcfg.loglevel > 10)
    {
      logprintf (
         "Path loop detected. Our AKA - %u:%u/%u.%u, found in path - %u/%u",
         newarea->myaka.zone, newarea->myaka.net,
         newarea->myaka.node, newarea->myaka.point,
         tsnb->net, tsnb->node);
      logwrite (1, 11);
    }
        //
        // For Jury Fradkin
        //
        break;
      }
    tsnb = tsnb->next;
  }
    }
  link = newarea->links.chain;
  while (link)
    {
      if (!link->passive)
  {
    if (link->zone == newarea->myaka.zone)
      {
        if (link->point == 0)
    {
      tsnb = (type == 1 ? psnb.chain : ssnb.chain);
      for (i = 0; i < (type == 1 ? psnb.numelem : ssnb.numelem);
           i++)
        {
          if (tsnb->net == link->net && tsnb->node == link->node)
      break;
          tsnb = tsnb->next;
        }
      if (tsnb == NULL)
        present = 1;
      else
        present = 0;
    }
        else
    present = 1;
        if (present)
    {
      tsnb = (type == 1 ? ppath.chain : spath.chain);
      for (i = 0; i < (type == 1 ? ppath.numelem : spath.numelem);
           i++)
        {
          if (tsnb->net == link->net && tsnb->node == link->node
        && ((link->point == 0) || tsnb->next))
      break;
          tsnb = tsnb->next;
        }
      if (tsnb == NULL)
        present = 1;
      else
        present = 0;
    }
      }
    else
      present = 1;
    if (present)
      {
        if (type == 1)
    {
      if (pktaddr.zone == link->zone && pktaddr.net == link->net
          && pktaddr.node == link->node
          && pktaddr.point == link->point)
        present = 0;
    }
        else
    {
      if (bufsqd.fromzone == link->zone
          && bufsqd.fromnet == link->net
          && bufsqd.fromnode == link->node
          && bufsqd.frompoint == link->point)
        present = 0;
    }
      }
    if (present)
      {
        if (!bcfg.selfaka)
    {
      taddr = bcfg.address.chain;
      while (taddr)
        {
          if (taddr->zone == link->zone && taddr->net == link->net
        && taddr->node == link->node
        && taddr->point == link->point)
      present = 0;
          taddr = taddr->next;
        }
    }
      }
    if (present)
      {
        tsnd.zone = link->zone;
        tsnd.net = link->net;
        tsnd.node = link->node;
        tsnd.point = link->point;
        addaddr ((type == 1 ? &ptosend : &stosend), &tsnd);
      }
  }
      link = link->next;
    }
  tsend = (type == 1 ? ptosend.chain : stosend.chain);
  while (tsend)
    {
      if ((tsend->point == 0) && (tsend->zone == newarea->myaka.zone))
  addshort ((type == 1 ? &psnb : &ssnb), tsend->net, tsend->node);
      tsend = tsend->next;
    }
  if (bcfg.numseenby)
    {
      link = bcfg.seenby.chain;
      while (link)
  {
    if (link->zone == newarea->myaka.zone)
      {
        tsnb = (type == 1 ? psnb.chain : ssnb.chain);
        while (tsnb)
    {
      if (tsnb->net == link->net && tsnb->node == link->node)
        break;
      tsnb = tsnb->next;
    }
        if (tsnb == NULL)
    addshort ((type == 1 ? &psnb : &ssnb), link->net, link->node);
      }
    link = link->next;
  }
    }
  if (!newarea->myaka.point)
    {
      tsnb = (type == 1 ? psnb.chain : ssnb.chain);
      while (tsnb)
  {
    if (tsnb->net == newarea->myaka.net
        && tsnb->node == newarea->myaka.node)
      break;
    tsnb = tsnb->next;
  }
      if (tsnb == NULL)
  addshort (&(type == 1 ? psnb : ssnb), newarea->myaka.net,
      newarea->myaka.node);
      tsnb = (type == 1 ? ppath.last : spath.last);
      if ((tsnb == NULL)
    || (tsnb->net != newarea->myaka.net
        || tsnb->node != newarea->myaka.node))
  addshort (&(type == 1 ? ppath : spath), newarea->myaka.net,
      newarea->myaka.node);
    }
  sortsnb (type == 1 ? &psnb : &ssnb);
}

void sortsnb (struct shortchain *chain)
{
  struct shortaddr *tsnb = NULL;
  unsigned long *tmp = NULL;
  short i = 0;
  if (chain->numelem)
    {
      tmp =
  (unsigned long *)myalloc ((chain->numelem * szlong), __FILE__,
          __LINE__);
      tsnb = chain->chain;
      for (i = 0; i < chain->numelem; i++)
  {
    tmp[i] = tsnb->net;
    tmp[i] <<= 16;
    tmp[i] += tsnb->node;
    tsnb = tsnb->next;
  }
      quicksort (tmp, &tmp[chain->numelem - 1]);

      tsnb = chain->chain;
      for (i = 0; i < chain->numelem; i++)
  {
    tsnb->net = (unsigned short)(tmp[i] >> 16);
    tsnb->node = (unsigned short)(tmp[i] & 0xffff);
    tsnb = tsnb->next;
  }
      myfree ((void **)&tmp, __FILE__, __LINE__);
    }
}

void quicksort (unsigned long *array, unsigned long *array2)
{
  unsigned long *mid = NULL, *i = NULL, *last = NULL, tmp = 0;
  mid = array + (unsigned)(array2 - array) / 2;
  tmp = *array;
  *array = *mid;
  *mid = tmp;
  last = array;
  for (i = array + 1; i <= array2; ++i)
    {
      if (*array > *i)
  {
    ++last;
    tmp = *last;
    *last = *i;
    *i = tmp;
  }
    }
  tmp = *array;
  *array = *last;
  *last = tmp;
  if (array < last && array < (last - 1))
    quicksort (array, last - 1);
  if ((last + 1) < array2)
    quicksort (last + 1, array2);
}

void getctrl (char *text, unsigned short len, short type)
{
  struct kludge **ckludge = NULL, *tkludge = NULL;
  unsigned short i = 0, *kludlen = NULL, *kludnum = NULL, klnum = 9, lkludge =
    0, bred = 0, spaces = 0, isarea = 0, isnetmail = 0 /*,isend=0 */ ;
  char term, *temp = NULL, *temp2 = NULL, *temp3 = NULL, *temp4 = NULL;
  struct packmess *tbufmess = NULL;
  struct myaddr faddr;
  struct pool *tpool;
  char att[DirSize + 1], satt[DirSize + 1], tatt[DirSize + 1],
    source[DirSize + 1], attkl[2 * DirSize + 16];
  short attok = 0;
  int n;
  temp = text;
  numlf = 0;
  lkludnum = lkludlen = 0;
  arealen = 0;
  arealenold = 0;
  gheadgarb = 0;
  addrfake = 0;
  if (gheadclen == 0)
    gheadclen = len;
  caddr.zone = caddr.net = caddr.node = caddr.point = 0;
  switch (type)
    {
    case 1:
      term = '\r';
      tbufmess = &bufpkt;
      kludlen = &pkludlen;
      kludnum = &pkludnum;
      ckludge = &pckludge;
      while (*temp == '\n')
  {
    temp++;
    numlf++;
  }
      break;
    case 2:
      term = '\1';
      tbufmess = &bufsqd;
      kludlen = &skludlen;
      kludnum = &skludnum;
      ckludge = &sckludge;
      break;
    case 3:
      term = '\r';
      tbufmess = &bufmess;
      kludlen = &mkludlen;
      kludnum = &mkludnum;
      ckludge = &mckludge;
      break;
    }
  memset (curmsgid, 0, 9);
  memset (curreply, 0, 9);
  *kludlen = *kludnum = 0;
  if (type == 2 && !(mode & (2048 + 256 + 128)))
    {
      i = (short)(strlen (newarea->areaname) + 5);
      *ckludge = (struct kludge *)myalloc (szkludge, __FILE__, __LINE__);
      tkludge = *ckludge;
      tkludge->next = NULL;
      tkludge->str = (char *)myalloc (arealength + 6, __FILE__, __LINE__);
      mystrncpy (tkludge->str, "AREA:", 7);
      mystrncat (tkludge->str, newarea->areaname, arealength, arealength + 5);
//    tkludge->str[i]=0;
      (*kludnum)++;
      (*kludlen) += i;
      if (local && 1)
  {
    if (!bcfg.dnutid)
    {
      tkludge->next =
        (struct kludge *)myalloc (szkludge, __FILE__, __LINE__);
      tkludge = tkludge->next;
      tkludge->next = NULL;
      memset (att, 0, DirSize + 1);
      sprintf (att, "\1TID: ParToss %s", version);
      tkludge->str =
        (char *)myalloc (strlen (att) + 3, __FILE__, __LINE__);
      mystrncpy (tkludge->str, att, (short)(strlen (att) + 2));
      (*kludnum)++;
      (*kludlen) += (unsigned short)(strlen (att) + 1);
    };
  }
    }
  else
    memset (curarea, 0, arealength);
  for (;;)
    {
      spaces = 0;
      lkludge = 0;
      for (i = 0; i < klnum; i++)
  if (strncmp (temp, kludges[i], strlen (kludges[i])) == 0)
    break;
      if (*temp == '\1' || (i < klnum && !((i == 0) && isarea)))
  {
    temp2 = strchr (temp + 1, term);
    if (type == 2)
      {
        if (temp2 == NULL || (temp2 - text > gheadclen))
    temp2 = text + gheadclen - 1;
        else if (temp2 - text > gheadclen)
    {
      temp2 = text + gheadclen - 1;
      gheadgarb = 1;
    }
//          goto garb;
      }
    else
      {
        if (temp2 == NULL || (temp2 - text) > len)
    // temp2=temp+strlen(temp);
    temp2 = text + len;
      }
    if (temp2 <= temp)
      goto garb;
    switch (i)
      {
      case 0:
        if (!isarea)
    memset (curarea, 0, arealength);
        temp3 = temp + 5;
        if ((*temp3 == 0) || (*temp3 == term))
    break;
        while (temp3 < temp2 && isspace (*temp3))
    {
      temp3++;
      spaces++;
    }
        while (temp3 < temp2 && isascii (*temp3) && !isspace (*temp3))
    temp3++;
        if (temp3 > temp2)
    temp3 = temp2;
        if (!isarea)
    {
      bred = (short)(temp2 - temp3);
      arealen = (short)(temp3 - temp /*-spaces*/ );
      if (arealen > arealength + 4)
        arealen = arealength + 4;
      n = arealen - 5 - spaces;
      if (n < 0)
        n = 0;
      if (n > arealength - 1)
        n = arealength - 1;
      memcpy (curarea, temp + 5 + spaces, n);
      //areaaliasmaker
      /*logprintf("Message from %s, %u:%u/%u.%u to %s, %u:%u/%u.%u about \"%s\"",
         bufpkt.fromname, bufpkt.fromzone, bufpkt.fromnet, bufpkt.fromnode,
         bufpkt.frompoint, bufpkt.toname, bufpkt.tozone, bufpkt.tonet,
         bufpkt.tonode, bufpkt.topoint, bufpkt.subj);
         logwrite(1,13);
         if(!quiet)
         ccprintf("%s\r\n",logout); */
      areaaliasmaker ();
      arealenold = arealen;
      arealen = strlen (curarea) + 5;
      //
      if (memicmp (curarea, "NETMAIL", 7) != 0)
        {
          if (type == 1 && both)
      setarea (curarea, 0);
        }
      else
        isnetmail = 1;
      isarea = 1;
    }
        spaces = 0;
        break;
      case 1:
        parseaddr (temp + 8, &faddr, (short)(temp2 - temp - 8));
        if (faddr.zone)
    {
      tbufmess->fromzone = faddr.zone;
      tbufmess->fromnet = faddr.net;
      tbufmess->fromnode = faddr.node;
      tbufmess->frompoint = faddr.point;
    }
        else
    addrfake = 1;
        if (type != 3)
    {
      if (bcfg.defarea.dupes)
        {
          temp4 = temp2 - 1;
          while (temp4 && isspace (*temp4) && (temp4 > text))
//              while(isspace(*temp4))
      temp4--;
          while (temp4 && !isspace (*temp4) && (temp4 > text))
//              while(!isspace(*temp4))
      temp4--;
          temp4++;
          memcpy (curmsgid, temp4,
            (unsigned)(((temp2 - temp4) >
            8) ? 8 : (temp2 - temp4)));
        }
    }
        break;
      case 2:
        if (type != 3)
    {
      parseaddr (temp + 8, &caddr, (short)(temp2 - temp - 8));
      if (tbufmess->tonode == 0 && tbufmess->tonet == 0)
        {
          if (caddr.zone)
      {
        tbufmess->tozone = caddr.zone;
        tbufmess->tonet = caddr.net;
        tbufmess->tonode = caddr.node;
        tbufmess->topoint = caddr.point;
      }
        }
      if (bcfg.defarea.dupes)
        {
          temp4 = temp2 - 1;
          while (temp4 && isspace (*temp4) && (temp4 > text))
//              while(isspace(*temp4))
      temp4--;
          while (temp4 && !isspace (*temp4) && (temp4 > text))
//              while(!isspace(*temp4))
      temp4--;
          temp4++;
          memcpy (curreply, temp4,
            (unsigned)(((temp2 - temp4) >
            8) ? 8 : (temp2 - temp4)));
        }
    }
        break;
      case 3:
        temp3 = strchr (temp + 6, ' ');
        if (temp3 == NULL || temp3 >= temp2)
    break;
        parseaddr (temp + 6, &faddr, (short)(temp3 - temp - 6));
        if (faddr.zone)
    {
      tbufmess->tozone = faddr.zone;
      tbufmess->tonet = faddr.net;
      tbufmess->tonode = faddr.node;
    }
//          tbufmess->topoint=faddr.point;
        temp3++;
        parseaddr (temp3, &faddr, (short)(temp2 - temp3));
        if (faddr.zone)
    {
      tbufmess->fromzone = faddr.zone;
      tbufmess->fromnet = faddr.net;
      tbufmess->fromnode = faddr.node;
    }
//          tbufmess->frompoint=faddr.point;
        break;
      case 4:
        tbufmess->frompoint = (unsigned short)(atoi (temp + 6));
        break;
      case 5:
        tbufmess->topoint = (unsigned short)(atoi (temp + 6));
        break;
      case 6:
        if (type == 3)
    {
      temp3 = strstr (temp, " DIR");
      if ((temp3 != NULL) && (temp3 < temp2))
        mflags |= 0x400;
      temp3 = strstr (temp, " CRA");
      if ((temp3 != NULL) && (temp3 < temp2))
        mflags |= 0x2;
      temp3 = strstr (temp, " FPU");
      if ((temp3 != NULL) && (temp3 < temp2))
        mflags |= 0x402;
      temp3 = strstr (temp, " HLD");
      if ((temp3 != NULL) && (temp3 < temp2))
        mflags |= 0x200;
      temp3 = strstr (temp, " SNT");
      if ((temp3 != NULL) && (temp3 < temp2))
        mflags |= 0x8;
      temp3 = strstr (temp, " RCV");
      if ((temp3 != NULL) && (temp3 < temp2))
        mflags |= 0x4;
      temp3 = strstr (temp, " FRQ");
      if ((temp3 != NULL) && (temp3 < temp2))
        mflags |= 0x800;
      temp3 = strstr (temp, " FIL");
      if ((temp3 != NULL) && (temp3 < temp2))
        mflags |= 0x10;
      temp3 = strstr (temp, " IMM");
      if ((temp3 != NULL) && (temp3 < temp2))
        mflags |= 0x10000l;
    }
        break;
      case 7:
        if (mode & 2048)
    {
      if (!isarea)
        memset (curarea, 0, arealength);
      temp3 = temp + 6;
      if ((*temp3 == 0) || (*temp3 == term))
        break;
      while (temp3 < temp2 && isspace (*temp3))
        {
          temp3++;
          spaces++;
        }
      while (temp3 < temp2 && isascii (*temp3) && !isspace (*temp3))
        temp3++;
      if (temp3 > temp2)
        temp3 = temp2;
      if (!isarea)
        {
          bred = (short)(temp2 - temp3);
          arealen = (short)(temp3 - temp - 1 - spaces);
          if (arealen > arealength + 4)
      arealen = arealength + 4;
          n = arealen - 5 - spaces;
          if (n < 0)
      n = 0;
          if (n > arealength - 1)
      n = arealength - 1;
          memcpy (curarea, temp + 6 + spaces, n);
          areaaliasmaker ();
          arealenold = arealen;
          arealen = strlen (curarea) + 5;
          setarea (curarea, 0);
          isarea = 1;
        }
    }
        spaces = 0;
        break;
      case 8:
        temp3 = temp + 8;
        while (temp3 < temp2 && isspace (*temp3) && (*temp3) != 0
         && (*temp3) != term)
    temp3++;
        temp4 = temp3;
        while (temp4 < temp2 && !isspace (*temp4) && (*temp4) != 0
         && (*temp4) != term)
    temp4++;
        n = (int)(temp4 - temp3);
        if (n > DirSize)
    n = DirSize;
        memset (tatt, 0, DirSize + 1);
        memcpy (tatt, temp3, n);
        // From a packet take a bare file name only, and only into the
        // area's pool: the file is moved from WorkDir to the pool, and
        // rrename() deletes the destination first
        if (type == 1
      && (!tatt[0] || strchr (tatt, '/') || strchr (tatt, '\\')
          || strchr (tatt, ':') || strstr (tatt, "..")
          || !newarea->pooloffs))
    {
      logprintf ("ATTACN kludge ignored (no pool or not a bare file name): %s", tatt);
      logwrite (1, 3);
      lkludge = 1;
      lkludlen += (unsigned short)(temp2 - temp);
      lkludnum++;
      break;
    }
        temp3 = strchr (tatt, DIRSEP[0]);
        if (temp3 == NULL)
    {
      memset (att, 0, DirSize + 1);
      if (newarea->pooloffs)
        {
          n = newarea->poollen + 1;
          if (n > DirSize)
            n = DirSize;
          lseek (areapool, newarea->pooloffs, SEEK_SET);
          rread (areapool, att, (unsigned short)n, __FILE__, __LINE__);
        }
      mystrncat (att, tatt, DirSize, DirSize);
      mystrncpy (satt, tatt, DirSize);
    }
        else
    {
      mystrncpy (att, tatt, DirSize);
      mystrncpy (satt, temp3 + 1, DirSize);
    }
        temp3 = temp4;
        while (temp3 < temp2 && isspace (*temp3) && (*temp3) != 0
         && (*temp3) != term)
    temp3++;
        temp4 = temp3;
        while (temp4 < temp2 && !isspace (*temp4) && (*temp4) != 0
         && (*temp4) != term)
    temp4++;
        n = (int)(temp4 - temp3);
        if (n > DirSize)
    n = DirSize;
        memset (tatt, 0, DirSize + 1);
        memcpy (tatt, temp3, n);

        if (glpool)
    {
      tpool = glpool;
      while (tpool->next)
        tpool = tpool->next;
      tpool->next =
        (struct pool *)myalloc (sizeof (struct pool), __FILE__,
              __LINE__);
      tpool = tpool->next;
    }
        else
    {
      glpool =
        (struct pool *)myalloc (sizeof (struct pool), __FILE__,
              __LINE__);
      tpool = glpool;
    }
        tpool->fullname =
    (char *)myalloc (strlen (att) + 1, __FILE__, __LINE__);
        tpool->shortname =
    (char *)myalloc (strlen (satt) + 1, __FILE__, __LINE__);
        tpool->type =
    (char *)myalloc (strlen (tatt) + 1, __FILE__, __LINE__);
        tpool->next = NULL;
        mystrncpy (tpool->fullname, att, (short)strlen (att));
        mystrncpy (tpool->shortname, satt, (short)strlen (satt));
        mystrncpy (tpool->type, tatt, (short)strlen (tatt));
        if (type == 1)
    {
      mystrncpy (source, bcfg.workdir, DirSize);
      mystrncat (source, satt, DirSize, DirSize);
      rrename (source, att);
    }
        sprintf (attkl, "\1ATTACH: %s %s\r", satt, tatt);
        attok = 1;
        break;

      default:
        lkludge = 1;
        lkludlen += (unsigned short)(temp2 - temp);
        lkludnum++;
        break;
      }
    if (type == 2)
      {
        if (*(temp2 - 1) == 0x0d)
    {
      *(temp2 - 1) = 0;
      if (lkludge)
        lkludlen--;
    }
      }
    if (!(*ckludge))
      {
        *ckludge =
    (struct kludge *)myalloc (szkludge, __FILE__, __LINE__);
        tkludge = *ckludge;
      }
    else
      {
        tkludge = *ckludge;
        while (tkludge->next)
    tkludge = tkludge->next;
        tkludge->next =
    (struct kludge *)myalloc (szkludge, __FILE__, __LINE__);
        tkludge = tkludge->next;
      }
    tkludge->next = NULL;
    if (attok)
      {
        tkludge->str =
    (char *)myalloc (strlen (attkl) + 1, __FILE__, __LINE__);
        strcpy (tkludge->str, attkl);
        attok = 0;
      }
    else if (i != 0)
      {
        tkludge->str =
    (char *)myalloc ((unsigned)(temp2 - temp + 3), __FILE__,
         __LINE__);
        memcpy (tkludge->str, temp, (unsigned)(temp2 - temp));
        tkludge->str[(unsigned)(temp2 - temp)] = 0;
      }
    else
      {
        tkludge->str =
    (char *)myalloc ((strlen (curarea) + 6), __FILE__, __LINE__);
        strcpy (tkludge->str, "AREA:");
        strcat (tkludge->str, curarea);
      }
    tkludge->left = lkludge;
    temp = temp2;
    if (type != 2)
      {
        temp++;
        if (*temp == '\n')
    {
      temp++;
      numlf++;
    }
      }
    (*kludnum)++;
  }
      else
  break;
    }
garb:
  (*kludlen) = (short)(temp - text);
  if (type == 1)
    {
      (*kludlen) += (short)(arealen - arealenold);
    }
  if (bred)
    (*kludlen) -= bred;
//  if(text[(*kludlen)+1]==0)
//   {
//    (*kludlen)--;
//   }
//  if(numlf)
//    (*kludlen)-=numlf;
  if (type == 1)
    {
      if (isnetmail)
  netmail = isnetmail;
      else
  netmail = !curarea[0];
      if (netmail)
  memset (oldarea, 0, arealength);
    }
}

void delctrl (short type)
{
  struct kludge **ckludge = NULL, *tkludge = NULL, *ttkludge = NULL;
  if (type != 3)
    {
      delshort (type == 1 ? &psnb : &ssnb);
      delshort (type == 1 ? &ppath : &spath);
      deladdr (type == 1 ? &ptosend : &stosend);
    }
  switch (type)
    {
    case 1:
      ckludge = &pckludge;
      break;
    case 2:
      ckludge = &sckludge;
      break;
    case 3:
      ckludge = &mckludge;
      break;
    }
  tkludge = *ckludge;
  while (tkludge)
    {
      ttkludge = tkludge->next;
      myfree ((void **)&tkludge->str, __FILE__, __LINE__);
      myfree ((void **)&tkludge, __FILE__, __LINE__);
      tkludge = ttkludge;
    }
  *ckludge = NULL;
}
