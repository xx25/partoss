// MaxiM: strupr stricmp

#include "partoss.h"
#include "globext.h"

#include "linkbase.h"
#include "lowlevel.h"
#include "morfiles.h"
#include "crc32.h"
#include "partsqd.h"
#include "linkareb.h"

long maxmsg;
short linkpos;
struct sqifile *sqi;
struct msglink *msgidn, *replyn;

void linksqds (long aoffset)
{
  short tmustlog, linktype;
  lseek (areaset, aoffset, SEEK_SET);
  rread (areaset, newarea, szarea, __FILE__, __LINE__);
  newarea->links.chain = newarea->links.last = NULL;
  newarea->links.numelem = 0;
  if (newarea->type != 0)
    {
      if (newarea->type != 2 && newarea->type != 3)
  {
    if (!newarea->passthr)
      {
        if (bcfg.fastlink)
    {
      if (newarea->linktype)
        linktype = newarea->linktype;
      else
        linktype = (short)(bcfg.linktype + 1);
      if (linktype == 5)
        return;
      if (!quiet)
        ccprintf ("%-60s\r", newarea->areaname);
/* LMA !!!          linkArea(newarea->areafp,linktype); */
      linkArea (newarea->areafp, linktype);
    }
        else
    {
      tmustlog = mustlog;
      mustlog = 0;
      opensqd (newarea, nindex, 0, 0);
      if (!arealock)
        {
          newarea->links.chain = newarea->links.last = NULL;
          newarea->links.numelem = 0;
          linksqd ();
          closesqd (newarea, 0);
          mustlog = tmustlog;
        }
    }
      }
  }
    }
  else if (bcfg.netlink)
    linknet ();
}

void linksqd (void)
{
  long i, j;
  if (newarea->linktype)
    linktype = newarea->linktype;
  else
    linktype = (short)(bcfg.linktype + 1);
  if (linktype == 5)
    return;
  lseek (newarea->sqd.sqd, 8, SEEK_SET);
  rread (newarea->sqd.sqd, &maxmsg, 4, __FILE__, __LINE__);
  if (maxmsg)
    {
      msgid =
  (unsigned long *)myalloc ((unsigned)(szlong * maxmsg), __FILE__,
          __LINE__);
      if (linktype != 2)
  reply =
    (unsigned long *)myalloc ((unsigned)(szlong * maxmsg), __FILE__,
            __LINE__);
      for (i = 0; i < maxmsg; i++)
  {
    j = readmsg (i, 0);
    if (j < 0)
      goto linkexit;
  }
      if ((linktype & 1) == 1)
  {
    for (i = 0; i < maxmsg; i++)
      {
        if (msgid[(unsigned)i])
    {
      for (j = 0; j < maxmsg; j++)
        {
          if ((reply[(unsigned)j] == msgid[(unsigned)i])
        && (i != j))
      setreply (i + 1, j + 1);
        }
    }
      }
    if (linktype == 1)
      {
        for (i = 0; i < maxmsg - 1; i++)
    {
      if (reply[(unsigned)i])
        {
          for (j = i + 1; j < maxmsg; j++)
      {
        if (reply[(unsigned)j] == reply[(unsigned)i])
          setreply (i + 1, j + 1);
      }
        }
    }
      }
  }
      else
  {
    if (linktype == 2)
      {
        for (i = 0; i < maxmsg; i++)
    {
//          if(msgid[i])
//           {
      for (j = i + 1; j < maxmsg; j++)
        {
          if (msgid[(unsigned)j] == msgid[(unsigned)i])
      {
        setreply (i + 1, j + 1);
        break;
      }
        }
//           }
    }
      }
    else
      {
        for (i = 0; i < maxmsg; i++)
    {
      linkpos = 0;
      if (msgid[(unsigned)i])
        {
          for (j = 0; j < maxmsg && linkpos < 10; j++)
      {
        if ((reply[(unsigned)j] == msgid[(unsigned)i])
            && (i != j))
          {
            setreply (i + 1, j + 1);
            linkpos++;
          }
      }
        }
    }
      }
  }
    linkexit:
      if (linktype != 2)
  myfree ((void **)&reply, __FILE__, __LINE__);
      myfree ((void **)&msgid, __FILE__, __LINE__);
    }
}

void setreply (long from, long to)
{
  long prev, next, i, loop, loop2;
  unsigned j;
  prev = readmsg (to - 1, 1);
  if (linktype == 4)
    {
      next = readmsg (from - 1, 1);
      head.nextreply[linkpos] = prev;
      writemsg (from - 1);
      prev = readmsg (to - 1, 1);
      head.replyto = next;
      writemsg (to - 1);
    }
  else
    {
      if (!(head.replyto))
  {
    next = readmsg (from - 1, 1);
    loop = next;
    while (head.nextreply[0])
      {
        from = head.nextreply[0];
        loop2 = from;
        newarea->curindex = 0;
        lseek (newarea->sqd.sqi, 0, SEEK_SET);
        j =
    rread (newarea->sqd.sqi, nindex,
           (unsigned short)(bufsqi * 12), __FILE__, __LINE__);
        while (j)
    {
      for (i = 0; i < j / 12; i++)
        if (nindex[(unsigned)i].umsgid == from)
          goto ifound;
      newarea->curindex += bufsqi;
      j =
        rread (newarea->sqd.sqi, nindex,
         (unsigned short)(bufsqi * 12), __FILE__, __LINE__);
    }
        goto infound;
      ifound:
        from = newarea->curindex + i + 1;
        if (from == loop2 && linktype == 2)
    {
      logprintf (
         "??? Index/Chain loop in area %s (# %ld), use SQFix",
         newarea->areaname, from);
      logwrite (1, 1);
      goto infound;
    }
        next = readmsg (from - 1, 1);
        if (next == loop && linktype == 2)
    {
      logprintf (
         "??? Index/Chain loop in area %s (# %ld), use SQFix",
         newarea->areaname, from);
      logwrite (1, 1);
      goto infound;
    }
      }
    head.nextreply[0] = prev;
    writemsg (from - 1);
    prev = readmsg (to - 1, 1);
    head.replyto = next;
    writemsg (to - 1);
  infound:
    ;
  }
    }
}

long readmsg (long number, short type)
{
  short i;
  long firstpos, realnum;
  char *temp = NULL, *temp2 = NULL, *tmsgid;
  tmsgid = (char *)myalloc (80, __FILE__, __LINE__);
  if (number >= (newarea->curindex + bufsqi) || number < newarea->curindex)
    {
      newarea->curindex = (number / bufsqi) * bufsqi;
      lseek (newarea->sqd.sqi, newarea->curindex * 12, SEEK_SET);
      rread (newarea->sqd.sqi, nindex, (unsigned short)(bufsqi * 12),
       __FILE__, __LINE__);
    }
  firstpos = nindex[(unsigned)(number - newarea->curindex)].offset;
  realnum = nindex[(unsigned)(number - newarea->curindex)].umsgid;
  lseek (newarea->sqd.sqd, firstpos, SEEK_SET);
  rread (newarea->sqd.sqd, &head, 266, __FILE__, __LINE__);
  if (head.ident != 0xAFAE4453L)
    {
      logprintf (
         "??? Area %s is damaged or index file is corrupted (# %ld)",
         newarea->areaname, number);
      if (logfileok)
  logwrite (1, 1);
      ccprintf ("\r\n%s\r\n", logout);
      badlog (newarea);
      return -1;
    }
  if (type == 0)
    memset (&(head.replyto), 0, 44);
  if (linktype != 2)
    {
      smsglen = head.msglength - 239;
      if (smsglen > 512)
  smsglen = 512;
      if (smsglen < 0)
  smsglen = 0;
      rreadz (newarea->sqd.sqd, sqdbuf, (unsigned short)(smsglen), __FILE__,
       __LINE__);
      temp = strstr (sqdbuf, "\1MSGID: ");
      if (temp && (temp - sqdbuf) < smsglen)
  {
    temp2 = temp + 7;
    while (*temp2
     && !(*temp2 == '\r' || *temp2 == '\n' || *temp2 == '\1'))
      temp2++;
    temp--;
    memset (tmsgid, 0, 80);
    memcpy (tmsgid, temp + 7,
      (unsigned)(((temp2 - temp - 7) >
            79) ? 79 : (temp2 - temp - 7)));
    tmsgid = strupr (tmsgid);
    msgid[(unsigned)number] =
      crc32block (tmsgid, (short)strlen (tmsgid));
  }
      else
  msgid[(unsigned)number] = 0;
      temp = strstr (sqdbuf, "\1REPLY: ");
      if (temp && (temp - sqdbuf) < smsglen)
  {
    temp2 = temp + 7;
    while (*temp2
     && !(*temp2 == '\r' || *temp2 == '\n' || *temp2 == '\1'))
      temp2++;
    temp--;
    memset (tmsgid, 0, 80);
    memcpy (tmsgid, temp + 7,
      (unsigned)(((temp2 - temp - 7) >
            79) ? 79 : (temp2 - temp - 7)));
    tmsgid = strupr (tmsgid);
    reply[(unsigned)number] =
      crc32block (tmsgid, (short)strlen (tmsgid));
  }
      else
  reply[(unsigned)number] = 0;
    }
  else
    {
      temp = head.subj;
      while (isspace (*temp))
  temp++;
      while (memicmp (temp, "Re:", 3) == 0)
  {
    temp += 3;
    while (isspace (*temp))
      temp++;
  }
      i = (short)strlen (temp);
      if (bcfg.linklength)
  i = (short)((i > bcfg.linklength) ? bcfg.linklength : i);
      msgid[(unsigned)number] = crc32block (temp, i);
    }
  if (type == 0)
    {
      lseek (newarea->sqd.sqd, firstpos, SEEK_SET);
      wwrite (newarea->sqd.sqd, &head, 266, __FILE__, __LINE__);
    }
  myfree ((void **)&tmsgid, __FILE__, __LINE__);
  return realnum;
}

void writemsg (long number)
{
  long firstpos;
  if (number >= (newarea->curindex + bufsqi) || number < newarea->curindex)
    {
      newarea->curindex = (number / bufsqi) * bufsqi;
      lseek (newarea->sqd.sqi, newarea->curindex * 12, SEEK_SET);
      rread (newarea->sqd.sqi, nindex, (unsigned short)(bufsqi * 12),
       __FILE__, __LINE__);
    }
  firstpos = nindex[(unsigned)(number - newarea->curindex)].offset;
  lseek (newarea->sqd.sqd, firstpos, SEEK_SET);
  wwrite (newarea->sqd.sqd, &head, 266, __FILE__, __LINE__);
}





void linknet (void)
{
  short i, j, curpos, fgood, mess;
  struct find_t fblk;
  char cfilemsg[DirSize + 1], filemsg[DirSize + 1];
/*
  if(newarea->linktype)
    linktype=newarea->linktype;
  else
    linktype=bcfg.linktype+1;
*/
  linktype = 2;
  mystrncpy (filemsg, newarea->areafp, DirSize);
  mystrncat (filemsg, (char *)"*.msg", 7, DirSize);
  curpos = 0;
  fgood = (short)_dos_findfirst (filemsg, findattr, &fblk);
  if (fgood == 0)
    {
      msgidn =
  (struct msglink *)myalloc ((sizeof (struct msglink) * bcfg.maxnet),
           __FILE__, __LINE__);
/*
    if(linktype!=2)
      replyn=(struct msglink *)myalloc((sizeof(struct msglink)*bcfg.maxnet),__FILE__,__LINE__);
*/
      while (fgood == 0)
  {
    mystrncpy (cfilemsg, newarea->areafp, DirSize);
    mystrncat (cfilemsg, fblk.name, 15, DirSize);
    mess = (short)sopen (cfilemsg, O_RDWR | O_BINARY, SH_DENYWR);
    msgidn[curpos].number = (short)atoi (fblk.name);
/*
      if(linktype!=2)
        replyn[curpos].number=(short)atoi(fblk.name);
*/
    readnet (mess, curpos, 0);
    cclose (&mess, __FILE__, __LINE__);
    curpos++;
    if (curpos >= bcfg.maxnet)
      goto linkit;
    fgood = (short)_dos_findnext (&fblk);
  }
    }
  else
    {
      _dos_findclose (&fblk);
         /***ash***/
      return;
    }
linkit:
  _dos_findclose (&fblk);/***ash***/
/*
  if((linktype&1)==1)
   {
    for(i=0;i<curpos;i++)
     {
      if(msgidn[i].crc)
       {
        for(j=0;j<curpos;j++)
         {
          if(replyn[j].crc==msgidn[i].crc)
            setreplyn(i+1,j+1);
         }
       }
     }
    if(linktype==1)
     {
      for(i=0;i<curpos-1;i++)
       {
        if(replyn[i].crc)
         {
          for(j=i+1;j<curpos;j++)
           {
            if(replyn[j].crc==replyn[i].crc)
              setreplyn(i+1,j+1);
           }
         }
       }
     }
   }
  else
   {
    if(linktype==2)
     {
*/
  for (i = 0; i < curpos; i++)
    {
      for (j = (short)(i + 1); j < curpos; j++)
  {
    if (msgidn[j].crc == msgidn[i].crc)
      {
        setreplyn (i, j);
        break;
      }
  }
    }
/*
  if(linktype!=2)
    myfree((void **)&replyn,__FILE__,__LINE__);
*/
  myfree ((void **)&msgidn, __FILE__, __LINE__);
/*
     }
    else
     {
      for(i=0;i<curpos;i++)
       {
        linkpos=0;
        if(msgidn[i].crc)
         {
          for(j=0;j<curpos && linkpos<10;j++)
           {
            if(replyn[j].crc==msgidn[i].crc)
             {
              setreplyn(i+1,j+1);
              linkpos++;
             }
           }
         }
       }
     }
   }
*/
//  linkexit:
}

void setreplyn (short from, short to)
{
  char temp[8];
  short prev, next;
  char cf1[DirSize + 1], cf2[DirSize + 1];
  mystrncpy (cf1, newarea->areafp, DirSize);
  mystrncat (cf1, itoa (msgidn[from].number, temp, 10), 10, DirSize);
  mystrncat (cf1, ".msg", 10, DirSize);
  mystrncpy (cf2, newarea->areafp, DirSize);
  mystrncat (cf2, itoa (msgidn[to].number, temp, 10), 10, DirSize);
  mystrncat (cf2, ".msg", 10, DirSize);
  prev = mysopen (cf1, 1, __FILE__, __LINE__);
  next = mysopen (cf2, 1, __FILE__, __LINE__);
  lseek (prev, 0xbc, SEEK_SET);
  lseek (next, 0xb8, SEEK_SET);
  wwrite (prev, &(msgidn[to].number), 2, __FILE__, __LINE__);
  wwrite (next, &(msgidn[from].number), 2, __FILE__, __LINE__);
  cclose (&prev, __FILE__, __LINE__);
  cclose (&next, __FILE__, __LINE__);
}

void readnet2 (short pos, short type)
{
  char cfilemsg[DirSize + 1], temp[8];
  short tmess;
  mystrncpy (cfilemsg, newarea->areafp, DirSize);
  mystrncat (cfilemsg, itoa (msgidn[pos].number, temp, 10), 10, DirSize);
  mystrncat (cfilemsg, ".msg", 7, DirSize);
  tmess = (short)sopen (cfilemsg, O_RDWR | O_BINARY, SH_DENYWR);
  readnet (tmess, pos, type);
  cclose (&tmess, __FILE__, __LINE__);
}

void readnet (short file, short pos, short type)
{
  short i;
  char *temp = NULL;
  lseek (file, 0, SEEK_SET);
  rread (file, &bufmsg, (unsigned short)(szmessage - szchar), __FILE__,
   __LINE__);
  smsglen = filelength (file);
  if (smsglen > buflen)
    smsglen = buflen;
  if (type == 0)
    {
      memset (&(bufmsg.replyto), 0, 2);
      memset (&(bufmsg.nextreply), 0, 2);
    }
//  rread(file,sqdbuf,smsglen,__FILE__,__LINE__);
/*
  if(linktype!=2)
   {
    temp=strstr(sqdbuf,"\1MSGID: ");
    if(temp && (temp-sqdbuf)<smsglen)
     {
      temp2=temp+7;
      while(*temp2 && !(*temp2=='\r' || *temp2=='\n' || *temp2=='\1'))
        temp2++;
      temp--;
      msgidn[pos].number=crc32block(temp+7,temp2-temp-7);
     }
    else
      msgidn[pos].number=0;
    temp=strstr(sqdbuf,"\1REPLY: ");
    if(temp && (temp-sqdbuf)<smsglen)
     {
      temp2=temp+7;
      while(*temp2 && !(*temp2=='\r' || *temp2=='\n' || *temp2=='\1'))
        temp2++;
      temp--;
      reply[number]=crc32block(temp+7,temp2-temp-7);
     }
    else
      reply[number]=0;
   }
  else
   {
*/
  temp = bufmsg.subj;
  while (isspace (*temp))
    temp++;
  while (memicmp (temp, "Re:", 3) == 0)
    {
      temp += 3;
      while (isspace (*temp))
  temp++;
    }
  i = (short)strlen (temp);
  if (bcfg.linklength)
    i = (short)((i > bcfg.linklength) ? bcfg.linklength : i);
  msgidn[pos].crc = crc32block (temp, i);
//   }
  if (type == 0)
    {
      lseek (file, 0, SEEK_SET);
      wwrite (file, &bufmsg, (unsigned short)(szmessage - szchar), __FILE__,
        __LINE__);
    }
  return;
}
