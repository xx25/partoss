// MaxiM: find_t Ported, changed.

#include "partoss.h"
#include <stdarg.h>
#include "globext.h"
#include "globfunc.h"

#include "lowlevel.h"
#include "morfiles.h"
#include "errors.h"
#include "environ.h"
#include "times.h"

#ifdef M_I386
#define intx86 int386
#else
#define intx86 int86
#endif

short hex (char hexdigit)
{
  char ch = (char)toupper (hexdigit);
  if (isdigit (ch))
    return ((short)(ch - '0'));
  if (ch >= 'A' && ch <= 'F')
    return ((short)(ch - 'A' + 10));
  return 0;
}

unsigned long asciihex (char *string)
{
  unsigned short i, j;
  unsigned long k = 0;
  for (i = 0; i < 8; i++)
    {
      k <<= 4;
      j = hex (string[i]);
      k += j;
    }
  return k;
}

void readblock (short handle, short level)
{
  short i, bufs;
  long j;
  unsigned bsize;
  bufs = (level > 1) ? 1024 : 4096;
  char *buf = sbuffer[level];
  bsize = rread (handle, buf, bufs, __FILE__, __LINE__);
  curspos[level] = 0;
  j = 0;
  if (bsize < bufs)
    endinput[level] = 1;
  else
    {
      for (i = (short)(bufs - 1);
     i && buf[i] != '\r' && buf[i] != '\n' && buf[i] != 0x1a;
     i--, j++) ;
      lseek (handle, -j, SEEK_CUR);
      bsize = i;
      endinput[level] = 0;
    }
  maxlen[level] = bsize;
}

void getstring (short level)
{
  unsigned i;
  char *buf = sbuffer[level];
  curtpos[level] = 0;
  endstring[level] = 0;
  numcr[level] = 0;
  ::string = buf + curspos[level];
  i = curspos[level];
  while (i < maxlen[level] && buf[i] != '\r' && buf[i] != '\n'
   && buf[i] != 0x1a)
    i++;
  maxstr[level] = (short)(i - curspos[level]);
  while (buf[i] == '\r' || buf[i] == '\n' || buf[i] == 0x1a)
    {
      if (buf[i] == '\r')
  numcr[level]++;
      i++;
    }
  maxstr2[level] = (short)(i - curspos[level]);
  curspos[level] = i;
  if (curspos[level] >= maxlen[level])
    endblock[level] = 1;
}

void gettoken (short level)
{
  unsigned i, j, k, iscomm;
  for (i = curtpos[level]; (i < maxstr[level]) && isspace (::string[i]); i++) ;
  k = 1;
  j = i;
  iscomm = 0;
  while (k)
    {
      if (::string[j] == ';')
  iscomm = 1;
      if (::string[j] == '"' && !iscomm)
  {
    if (i == j)
      i++;
    j++;
    while ((j < maxstr[level]) && ::string[j] != '"')
      j++;
    k = 0;
    if (j == maxstr[level])
      {
        ccprintf
    ("\r\nWARNING! Unclosed parenthesis in %s (line %d)\r\n",
     confile, lineno[level]);
        ccprintf ("Erroneous line is:\r\n");
        ccprintf ("%s\r\n", ::string);
      }
  }
      else if ((j >= maxstr[level]) || isspace (::string[j]))
  k = 0;
      else
  j++;
    }
  token = ::string + i;
  curtpos[level] = j;
  if (::string[curtpos[level]] == '"')
    curtpos[level]++;
  if (curtpos[level] >= maxstr[level] || ::string[j] == '\r'
      || ::string[j] == '\n' || ::string[j] == 0x1a)
    endstring[level] = 1;
  toklen = (short)(j - i);
}

void tokencpy (char *string, short smax)
{
  short slen = (smax > toklen) ? toklen : smax;
  mystrncpy (string, token, slen);
  string[slen] = 0;
}

void makebin (char *string)
{
  short i = 0, j, k;
  while (string[i])
    {
      j = (short)(i / 2);
      k = (short)((hex (string[i++])) << 4);
      k += hex (string[i++]);
      string[j] = (char)k;
    }
  for (k = (short)(j + 1); k < i; k++)
    string[k] = 0;
}

short cmpaddr (struct myaddr *first, struct myaddr *second)
{
  if (first == NULL)
    return -2;
  if (second == NULL)
    return -2;
  if (first->zone < second->zone)
    return -1;
  if (first->zone > second->zone)
    return 1;
  if (first->net < second->net)
    return -1;
  if (first->net > second->net)
    return 1;
  if (first->node < second->node)
    return -1;
  if (first->node > second->node)
    return 1;
  if (first->point < second->point)
    return -1;
  if (first->point > second->point)
    return 1;
  return 0;
}

short cmpaddrw (struct myaddr *first, struct myaddr *second)  // with wildcards
{
  if (first == NULL)
    return -2;
  if (second == NULL)
    return -2;
  if (first->zone != 65535u && second->zone != 65535u)
    {
      if (first->zone < second->zone)
  return -1;
      if (first->zone > second->zone)
  return 1;
      if (first->net != 65535u && second->net != 65535u)
  {
    if (first->net < second->net)
      return -1;
    if (first->net > second->net)
      return 1;
    if (first->node != 65535u && second->node != 65535u)
      {
        if (first->node < second->node)
    return -1;
        if (first->node > second->node)
    return 1;
        if (first->point != 65535u && second->point != 65535u)
    {
      if (first->point < second->point)
        return -1;
      if (first->point > second->point)
        return 1;
    }
      }
  }
    }
  return 0;
}

unsigned long hash (char *string)
{
  unsigned long result = 0, temp;
  char *ttemp = NULL;
  for (ttemp = string; *ttemp; ttemp++)
    {
      result = (result << 4) + tolower (*ttemp);
      if ((temp = (result & 0xf0000000L)) != 0L)
  {
    result |= temp >> 24;
    result |= temp;
  }
    }
  return (result & 0x7fffffffLu);
}

void mywrite (short handle, char *string, char *file, unsigned short line)
{
  wwrite (handle, string, (unsigned short)(strlen (string)), file, line);
}

// sprintf into logout, cut to its size
void logprintf (const char *format, ...)
{
  va_list args;
  va_start (args, format);
  vsnprintf (logout, BufSize + 1, format, args);
  va_end (args);
  logout[BufSize] = 0;
}

void logwrite (short first, short level)
{
  char slev[8], hfile[DirSize + 1];
  if (level > bcfg.loglevel)
    return;
  if (!logfile)
    {
      addhome (hfile, bcfg.logfile);
#if HAVE_SOPEN
      if ((logfile =
     (short)sopen (hfile, O_RDWR | O_BINARY, SH_DENYNO)) == -1)
  if ((logfile =
       (short)sopen (hfile, O_RDWR | O_BINARY | O_CREAT, SH_DENYNO,
         S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
    {
      mystrncpy (errname, hfile, DirSize);
      logfileok = 0;
      errexit (2, __FILE__, __LINE__);
    }
      lseek (logfile, 0, SEEK_END);
#else
      // Perm. mode (S_I*) here must be changed to use value, got from
      // configuration. I.e. it must be possible for user to define his
      // own mode for the logfile.
      if ((logfile =
     open (hfile, O_WRONLY | O_BINARY | O_CREAT | O_APPEND | O_EXLOCK,
     S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1)
  {
    mystrncpy (errname, hfile, DirSize);
    logfileok = 0;
    errexit (2, __FILE__, __LINE__);
  }
#endif
    }
  if (!logfile)
    return;
  logfileok = 1;
  if (first)
    {
      sftime = time (NULL);
      mylocaltime (&sftime, &tmt);
      mystrncpy (tstrtime, asctime (&tmt), 39);
      converttime (tstrtime);
      mywrite (logfile, "\r\n", __FILE__, __LINE__);
      ftstime[19] = ' ';
      wwrite (logfile, ftstime, 20, __FILE__, __LINE__);
      ftstime[19] = 0;
      if (bcfg.logoutl)
  {
    sprintf (slev, "[%2u] ", level);
    mywrite (logfile, slev, __FILE__, __LINE__);
  }
    }
  mywrite (logfile, logout, __FILE__, __LINE__);
  flushbuf (logfile);
  if (!bcfg.dncloselog)
    cclose (&logfile, __FILE__, __LINE__);
}

void badlog (struct area *barea)
{
  char tstr[CSSize + 1], *temp = NULL, *temp2 = NULL;
  long bloglen;
  if (bcfg.badlog[0])
    {
      mystrncpy (tstr, "", 3);
      temp = bcfg.bshablon;
      temp2 = temp;
      while (temp && *temp)
  {
    while (*temp2 && (*temp2 != '@'))
      temp2++;
    mystrncat (tstr, temp, (short)(temp2 - temp + 1), CSSize);
    temp2++;
    switch (toupper (*temp2))
      {
      case 'T':
        mystrncat (tstr, barea->areaname, arealength, CSSize);
        break;
      case 'P':
        mystrncat (tstr, barea->areafp, DirSize, CSSize);
        break;
      case 'A':
        sprintf (logout, "%u:%u/%u.%u", barea->myaka.zone,
           barea->myaka.net, barea->myaka.node,
           barea->myaka.point);
        mystrncat (tstr, logout, (short)(strlen (logout) + 5), CSSize);
        break;
      default:
        temp2--;
        break;
      }
    temp2++;
    temp = temp2;
  }
//    mystrncat(tstr,"\r\n",5,CSSize);
      cclose (&dupreserv, __FILE__, __LINE__);
      if ((blog =
     (short)sopen (bcfg.badlog, O_RDWR | O_BINARY, SH_DENYWR)) == -1)
  {
    if ((blog =
         (short)sopen (bcfg.badlog, O_RDWR | O_BINARY | O_CREAT,
           SH_DENYWR, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
      {
        ccprintf ("\r\nWARNING! Can't create BadLog %s\r\n",
      bcfg.badlog);
        if ((dupreserv = (short)open (NULL_DEV, O_WRONLY)) == -1)
    {
      mystrncpy (errname, NULL_DEV, DirSize);
      errexit (2, __FILE__, __LINE__);
    }
        blog = 0;
        return;
      }
  }
      lseek (blog, 0, SEEK_SET);
      endinput[2] = 0;
      while (!endinput[2])
  {
    readblock (blog, 2);
    endblock[2] = 0;
    do
      {
        getstring (2);
        if ((strnicmp (::string, tstr, maxstr[2]) == 0)
      && (strlen (tstr) == maxstr[2]))
    goto bfound;
      }
    while (!endblock[2]);
  }
      lseek (blog, 0, SEEK_END);
      mywrite (blog, tstr, __FILE__, __LINE__);
      mywrite (blog, "\r\n", __FILE__, __LINE__);
    bfound:
      if (blog)
  {
    bloglen = filelength (blog);
    Close (blog);
    blog = 0;
    if (bloglen == 0)
      unlink (bcfg.badlog);
  }
      if ((dupreserv = (short)open (NULL_DEV, O_WRONLY)) == -1)
  {
    mystrncpy (errname, NULL_DEV, DirSize);
    errexit (2, __FILE__, __LINE__);
  }
      ;
    }
}

/*
void badlog(short type)
 {
  short oldlog;
  if(blog)
   {
    oldlog=logfile;
    logfile=blog;
    sprintf(logout,"Message to area %s put in BadArea:",curarea);
    logwrite(1,1);
    sprintf(logout,"From: %s",buftemp->fromname);
    logwrite(1,1);
    sprintf(logout,"To:   %s",buftemp->toname);
    logwrite(1,1);
    sprintf(logout,"Subj: %s",buftemp->subj);
    logwrite(1,1);
    switch(type)
     {
      case 1:
        sprintf(logout,"Reason: grunded message");
        break;
      case 2:
        sprintf(logout,"Reason: unknown area, AutoCreate disabled");
        break;
      case 3:
        sprintf(logout,"Reason: security violation");
        break;
     }
    logwrite(1,1);
    mywrite(logfile,"\r\n",__FILE__,__LINE__);
    logfile=oldlog;
   }
 }
*/

void parseaddr (char *address, struct myaddr *straddr, short length)
{
  char *temp = NULL, taddr[25];
  straddr->zone = straddr->net = straddr->node = straddr->point = 0;
  if (length <= 0)
    return;
  mystrncpy (taddr, address, (short)((length > 24) ? 24 : length));
  switch (taddr[0])
    {
    case '*':
      straddr->zone = straddr->net = straddr->node = straddr->point = 65535u;
      break;
    case '.':
      straddr->zone = defaddr.zone;
      straddr->net = defaddr.net;
      straddr->node = defaddr.node;
      if (taddr[1] == '*')
  straddr->point = 65535u;
      else
  straddr->point = (unsigned short)(atoi (&taddr[1]));
      break;
    case '/':
      straddr->zone = defaddr.zone;
      straddr->net = defaddr.net;
      if (taddr[1] == '*')
  straddr->node = straddr->point = 65535u;
      else
  {
    straddr->node = (unsigned short)(atoi (&taddr[1]));
    if ((temp = strchr (taddr, '.')) != NULL)
      if (*(temp + 1) == '*')
        straddr->point = 65535u;
      else
        straddr->point = (unsigned short)(atoi (temp + 1));
    else
      straddr->point = 0;
  }
      break;
    case ':':
      straddr->zone = defaddr.zone;
      if (taddr[1] == '*')
  straddr->net = straddr->node = straddr->point = 65535u;
      else
  {
    straddr->net = (unsigned short)(atoi (&taddr[1]));
    temp = strchr (taddr, '/');
    if (temp == NULL || (*(temp + 1) == '*'))
      straddr->node = straddr->point = 65535u;
    else
      {
        straddr->node = (unsigned short)(atoi (temp + 1));
        if ((temp = strchr (taddr, '.')) != NULL)
    if (*(temp + 1) == '*')
      straddr->point = 65535u;
    else
      straddr->point = (unsigned short)(atoi (temp + 1));
        else
    straddr->point = 0;
      }
  }
      break;
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
      if ((temp = strchr (taddr, ':')) != NULL)
  {
    straddr->zone = (unsigned short)(atoi (taddr));
    if (*(temp + 1) == '*')
      straddr->net = straddr->node = straddr->point = 65535u;
    else
      {
        straddr->net = (unsigned short)(atoi (temp + 1));
        temp = strchr (taddr, '/');
        if (temp == NULL || *(temp + 1) == '*')
    straddr->node = straddr->point = 65535u;
        else
    {
      straddr->node = (unsigned short)(atoi (temp + 1));
      if ((temp = strchr (taddr, '.')) != NULL)
        if (*(temp + 1) == '*')
          straddr->point = 65535u;
        else
          straddr->point = (unsigned short)(atoi (temp + 1));
      else
        straddr->point = 0;
    }
      }
  }
      else
  {
    straddr->zone = defaddr.zone;
    if ((temp = strchr (taddr, '/')) != NULL)
      {
        straddr->net = (unsigned short)(atoi (taddr));
        temp = strchr (taddr, '/');
        if (temp == NULL || (*(temp + 1) == '*'))
    straddr->node = straddr->point = 65535u;
        else
    {
      straddr->node = (unsigned short)(atoi (temp + 1));
      if ((temp = strchr (taddr, '.')) != NULL)
        if (*(temp + 1) == '*')
          straddr->point = 65535u;
        else
          straddr->point = (unsigned short)(atoi (temp + 1));
      else
        straddr->point = 0;
    }
      }
    else
      {
        straddr->net = defaddr.net;
        straddr->node = (unsigned short)(atoi (taddr));
        if ((temp = strchr (taddr, '.')) != NULL)
    if (*(temp + 1) == '*')
      straddr->point = 65535u;
    else
      straddr->point = (unsigned short)(atoi (temp + 1));
        else
    straddr->point = 0;
      }
  }
      break;
    }
  straddr->numaka = 0;
  if (straddr->rdonly != 1)
    straddr->rdonly = 0;
  if (straddr->passive != 1)
    straddr->passive = 0;
  straddr->next = NULL;
  defaddr.zone = straddr->zone;
  defaddr.net = straddr->net;
  defaddr.node = straddr->node;
  defaddr.point = straddr->point;
}

void hexascii (unsigned long value, char *string)
{
  char tt, i, j;
  for (i = 0; i < 4; i++)
    {
      tt = (char)(value >> (24 - (i << 3)));
      for (j = 0; j < 2; j++)
  string[(i << 1) + j] = duotrice[(tt >> (4 - (j << 2))) & 0x0f];
    }
}

#ifdef __DOS__
void lpselect (char page)
{
#ifdef __DOS__
  REGS regs;
  regs.h.ah = 5;
  regs.h.al = page;
  intx86 (0x10, &regs, &regs);
#endif
}

void illpselect (char page)
{
#ifdef __DOS__
  short tbx, tdx;
  tdx = 0x3d4;
  tbx = page << 12;
  outp (0x3d4, 12);
  tdx++;
  outp (tdx, tbx >> 8);
  tdx--;
  outp (tdx, 13);
  tdx++;
  outp (tdx, tbx & 0xff);
#endif
}
#endif

void flushbuf (short handle)
{
  if (bcfg.kamikadze)
    return;
#if defined( __DOS__ )
  short duphandle;
  cclose (&dupreserv, __FILE__, __LINE__);
  duphandle = dup (handle);
  if (duphandle != -1)
    cclose (&duphandle, __FILE__, __LINE__);
  else
    {
      mystrncpy (errname, "", DirSize);
      errexit (2, __FILE__, __LINE__);
    }
  if ((dupreserv = open (NULL_DEV, O_WRONLY)) == -1)
    {
      mystrncpy (errname, NULL_DEV, DirSize);
      errexit (2, __FILE__, __LINE__);
    }
#elif defined( __NT__ )
  FlushFileBuffers ((HANDLE) _os_handle (handle));
#elif defined(__linux__) || defined (__FreeBSD__)
  sync ();
#else
  DosBufReset (handle);
#endif
}

void sortfpkt (short what)
{
  struct pktname *tmp = NULL, *fapkt = NULL;
  short i, j, k;
  unsigned long ttime;
  char tname[(DirSize + 1)];
  if (what == 0)
    fapkt = apkt;
  else
    fapkt = fpkt;
  if (fapkt)
    {
      i = 0;
      tmp = fapkt;
      while (tmp->next)
  tmp = tmp->next, i++;
      for (j = 0; j < i; j++)
  {
    tmp = fapkt;
    for (k = 0; k < i - j; k++)
      {
        if (tmp->time > tmp->next->time)
    {
      ttime = tmp->time;
      mystrncpy (tname, tmp->name, DirSize);
      tmp->time = tmp->next->time;
      mystrncpy (tmp->name, tmp->next->name, DirSize);
      tmp->next->time = ttime;
      mystrncpy (tmp->next->name, tname, DirSize);
    }
        tmp = tmp->next;
      }
  }
    }
}

void addpacket (char *path, short where)
{
  struct pktname *cpkt = NULL;
  char packname[(DirSize + 1)], currname[(DirSize + 1)];
  struct find_t fblk;

  mystrncpy (packname, path, DirSize);
  if (packname[0] && packname[strlen (packname) - 1] != DIRSEP[0])
    mystrncat (packname, DIRSEP, 3, DirSize);
  mystrncat (packname, PKT_MASK, 7, DirSize);
  sprintf (logout, "Processing inbound directory %s", packname);
  logwrite (1, 11);
  good = (short)_dos_findfirst (packname, findattr, &fblk);
  while (good == 0)
  {
    if (!(fblk.attrib & 0x1f))
    {
      mystrncpy (currname, path, DirSize);
      if (currname[0] && currname[strlen (currname) - 1] != DIRSEP[0])
        mystrncat (currname, DIRSEP, 3, DirSize);
      mystrncat (currname, fblk.name, DirSize, DirSize);
      sprintf (logout, "--- Adding of %s", currname);
      logwrite (1, 11);
      if (fpkt == NULL)
      {
        fpkt = (struct pktname *)myalloc (szpktname, __FILE__, __LINE__);
        cpkt = fpkt;
      }
      else
      {
        cpkt = fpkt;
        while (cpkt)
        {
          if (stricmp (currname, cpkt->name) == 0)
            break;
          cpkt = cpkt->next;
        }
        if (cpkt == NULL)
        {
          cpkt = fpkt;
          while (cpkt->next)
            cpkt = cpkt->next;
          cpkt->next =
            (struct pktname *)myalloc (szpktname, __FILE__, __LINE__);
          cpkt = cpkt->next;
        }
        else
          goto nextpkt;
      }
      memset (cpkt, 0, szpktname);
      cpkt->next = NULL;
      mystrncpy (cpkt->name, currname, DirSize);
      cpkt->time = fblk.wr_date;
      cpkt->time <<= 16;
      cpkt->time += fblk.wr_time;
      cpkt->where = where;
    }
    nextpkt:
    good = (short)_dos_findnext (&fblk);
  }
  _dos_findclose (&fblk);/***ash***/
}

void addarcs (char *path, struct find_t *fblk, short secure)
{
  struct pktname *cpkt = NULL;
  char currname[(DirSize + 1)];
  mystrncpy (currname, path, DirSize);
  if (currname[0] && currname[strlen (currname) - 1] != DIRSEP[0])
    mystrncat (currname, DIRSEP, 3, DirSize);
  mystrncat (currname, fblk->name, DirSize, DirSize);
  if (apkt == NULL)
    {
      apkt = (struct pktname *)myalloc (szpktname, __FILE__, __LINE__);
      cpkt = apkt;
    }
  else
    {
      cpkt = apkt;
      while (cpkt)
  {
    if (stricmp (currname, cpkt->name) == 0)
      break;
    cpkt = cpkt->next;
  }
      if (cpkt == NULL)
  {
    cpkt = apkt;
    while (cpkt->next)
      cpkt = cpkt->next;
    cpkt->next =
      (struct pktname *)myalloc (szpktname, __FILE__, __LINE__);
    cpkt = cpkt->next;
  }
      else
  return;
    }
  memset (cpkt, 0, szpktname);
  cpkt->next = NULL;
  mystrncpy (cpkt->name, currname, DirSize);
  cpkt->time = fblk->wr_date;
  cpkt->time <<= 16;
  cpkt->time += fblk->wr_time;
  cpkt->where = secure;
}

void *myalloc (unsigned length, char *file, unsigned short line)
{
  void *buf = NULL;
  // ccprintf("* Alloc, source file %s, source line %u\r\n",file,line);
#ifdef XM_USED
  buf = x_malloc (length);
#else
  buf = malloc (length);
#endif
  if (buf == NULL)
    errexit (1, file, line);
  return buf;
}

void *myrealloc (void *buf, unsigned length, char *file, unsigned short line)
{
  if (buf == NULL)
    errexit (1, file, line);
  // ccprintf("* Alloc, source file %s, source line %u\r\n",file,line);
#ifdef XM_USED
  buf = x_realloc (buf, length);
#else
  buf = realloc (buf, length);
#endif
  if (buf == NULL)
    errexit (1, file, line);
  return buf;
}

void myfree (void **buf, char *file, unsigned short line)
{
  // ccprintf("* Free, source file %s, source line %u\r\n",file,line);
  if (*buf == NULL)
    errexit (4, file, line);
/*
  if(logfileok)
   {
    sprintf(logout,"%4x:%4x",FP_SEG(*buf),FP_OFF(*buf));
    logwrite(1);
   }
*/
#ifdef XM_USED
  x_free (*buf);
#else
  free (*buf);
#endif
  *buf = NULL;
}

char *mystrncpy (char *dest, const char *src, unsigned short len)
{
  memset (dest, 0, len + 1);
  return (strncpy (dest, src, len));
}

char *mystrncat (char *dest, const char *src, unsigned short len,
     unsigned short maxsize)
{
  unsigned short size, rest;
  size = (unsigned short)strlen (dest);
  if (size >= maxsize)
    return dest;
  rest = (unsigned short)(maxsize - size);
  if (len > rest)
    len = rest;
  if (len == 0)
    return dest;
  memset (dest + size, 0, len);
  return (strncat (dest, src, len - 1));
}

short rrename (char *from, char *to)
{
  short result, i, len, terr;
  char da, db;
  da = db = ' ';
  len = (short)strlen (from);
  if (len < strlen (to))
    len = (short)strlen (to);
  if (memicmp (from, to, len))
    {
      unlink (to);
      if (from[1] == ':')
  da = from[0];
      if (to[1] == ':')
  db = to[0];
      if (da != db)
  return movefile (from, to);
      for (i = 0; i < 5; i++)
  {
    result = (short)rename (from, to);
    terr = (short)errno;
    if (result == 0)
      break;
    if (lich)
      {
        sprintf (logout, "Waiting for rename %s to %s", from, to);
        logwrite (1, 1);
        sprintf (logout, "Previous try returned %d, errno - %d", result,
           terr);
        logwrite (1, 1);
      }
    mtsleep (1);
  }
      if (result)
  result = movefile (from, to);
      return result;
    }
  else
    return 0;
}

short movefile (char *src, char *dst)
{
  int srch, dsth, res;
  srch = sopen (src, O_RDONLY | O_BINARY, SH_DENYNO);
  if (srch <= 0)
    return -1;
  dsth =
    sopen (dst, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR,
     S_IRWXU | S_IRWXG | S_IRWXO);
  if (dsth <= 0)
    return -2;
  res = rread ((short)srch, sbuffer[0], 4096, __FILE__, __LINE__);
  while (res > 0)
    {
      wwrite ((short)dsth, sbuffer[0], (unsigned short)res, __FILE__,
        __LINE__);
      res = rread ((short)srch, sbuffer[0], 4096, __FILE__, __LINE__);
    }
  Close (dsth);
  Close (srch);
  unlink (src);
  return 0;
}

short wildcard (char *mask, char *string)
{
  while (*mask && *string)
    {
      switch (*mask)
  {
  case '?':
    mask++;
    string++;
    break;
  case '*':
    if (*++mask == '*' || *mask == '?')
      break;
    while (*string && toupper (*string) != toupper (*mask))
      ++string;
    break;
  default:
    if (toupper (*mask++) != toupper (*string++))
      return ((short)(toupper (*--mask) - toupper (*--string)));
  }
    }
  while ((*mask == '*') || (*mask == '?'))
    mask++;
  return ((short)(toupper (*mask) - toupper (*string)));
}

int wildnew (char *mask, char *string)
{
  char curmask[DirSize + 1], curstr[DirSize + 1], ts[DirSize + 1], *temp =
    NULL, *temp2 = NULL, *curstr2 = NULL;
  mystrncpy (curmask, mask, DirSize);
  mystrncpy (curstr, string, DirSize);
  curstr2 = curstr;
  if ((*curmask) == '?')
    {
      if (wildnew (curmask + 1, curstr2) == 0)
  return 0;
      if (wildnew (curmask + 1, curstr2 + 1) == 0)
  return 0;
      return 1;
    }
  if ((*curmask) == '*')
    {
      temp = curmask + 1;
      while ((*temp) != '*' && (*temp) != '?'
       && ((temp - curmask) < strlen (curmask) - 1))
  temp++;
      memcpy (ts, curmask + 1, (unsigned)(temp - curmask - 1));
      ts[(unsigned)(temp - curmask)] = 0;
      while ((temp2 = strstr (curstr2, ts)) != NULL)
  {
    if (wildnew (temp2 + strlen (ts), temp) == 0)
      return 0;
    curstr2 = curstr2 + strlen (ts);
  }
      return 1;
    }
  temp = curmask;
  while ((*temp) != '*' && (*temp) != '?'
   && ((temp - curmask) < strlen (curmask) - 1))
    temp++;
  if (strnicmp (curmask, curstr2, (unsigned)(temp - curmask)) == 0)
    return wildnew (curstr2 + (unsigned)(temp - curmask), temp);
  else
    return 1;
}

void mylocaltime(const time_t *timer, struct tm *localtimer)
{
   memcpy(localtimer, localtime(timer), sizeof(tm));
};
