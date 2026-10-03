// MaxiM: find_t

#include "partoss.h"
#include "globext.h"

#include "buftomsg.h"
#include "lowlevel.h"
#include "morfiles.h"
#include "errors.h"
#include "tossarcs.h"
#include "crc32.h"
#include "buftosqd.h"
#include "times.h"
#include "buftopkt.h"
#include "netfwd.h"

void buftomsg (short type)
{
  struct kludge *tkludge = NULL;
  char temp[8], msgid[9], *temp1 = NULL, *temp2 = NULL, *null1 = "\0";
  char dupbase[DirSize + 1], tareaname[arealength + 1];
  short msg = 0, inout = 0, dupe = 0;
  int finish = 0;
  unsigned short tmsg = 0, fmax2 = 0, tnummsg;
  unsigned short bfromzone = 0, bfrompoint = 0;
  unsigned short btozone = 0, btopoint = 0;
  struct find_t fblk;
  struct myaddr *taddr = NULL;
  struct link *blink = NULL;
  inout = 0;
  taddr = bcfg.address.chain;
  while (taddr)
    {
      if (bufmess.tozone == taddr->zone && bufmess.tonet == taddr->net &&
	  bufmess.tonode == taddr->node && bufmess.topoint == taddr->point)
	{
	  inout = 1;
	  break;
	}
      taddr = taddr->next;
    }
  if (inout)
    {
      mystrncpy (filemsg, inpath, DirSize);
      bufmess.flags &= 0xffdf;
    }
  else
    mystrncpy (filemsg, outpath, DirSize);
  tlist = rlist;
  while (tlist)
    {
      for (carea = 0; carea < tlist->numlists; carea++)
	if (tlist->alist[carea].type == 0)
	  if (stricmp
	      (tlist->alist[carea].areaname,
	       inout ? bcfg.netin : bcfg.netout) == 0)
	    goto nfound;
      tlist = tlist->next;
    }
nfound:
  if (tlist && type == 2 && bcfg.carbnet && !fwdcopy)
    {
      memcpy (tareaname, newarea->areaname, arealength);
      memcpy (newarea->areaname, tlist->alist[carea].areaname, arealength);
      glmove = 0;
      writeboth (0);
      memcpy (newarea->areaname, tareaname, arealength);
      if (glmove)
	return;
    }
  if (type != 1 && type != 4 && !fwdcopy)
    {
      if (bcfg.netdupes && newarea->dupes)
	{
	  isdupe = 0;
	  mystrncpy (dupbase, filemsg, DirSize);
	  mystrncat (dupbase, (char *)"dupcheck", 10, DirSize);
	  if ((dupe =
	       (short)sopen (dupbase, O_RDWR | O_BINARY, SH_DENYWR)) == -1)
	    {
	      if ((dupe =
		   (short)sopen (dupbase, O_RDWR | O_BINARY | O_CREAT,
				 SH_DENYWR,
				 S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
		{
		  mystrncpy (errname, dupbase, DirSize);
		  errexit (2, __FILE__, __LINE__);
		}
	      dupecur = dupemax = 0;
	      chsize (dupe, 0);
	      memset (dupbuf, 0, newarea->dupes * szlong);
	      wwrite (dupe, &dupemax, 2, __FILE__, __LINE__);
	      wwrite (dupe, &dupecur, 2, __FILE__, __LINE__);
	      wwrite (dupe, dupbuf, (newarea->dupes * szlong), __FILE__,
		      __LINE__);
	    }
	  else
	    {
	      rread (dupe, &dupemax, 2, __FILE__, __LINE__);
	      rread (dupe, &dupecur, 2, __FILE__, __LINE__);
	      rread (dupe, dupbuf, (newarea->dupes * szlong), __FILE__,
		     __LINE__);
	    }
	  dupcheck (3);
	  if (!isdupe)
	    {
	      chsize (dupe, 0);
	      lseek (dupe, 0, SEEK_SET);
	      wwrite (dupe, &dupemax, 2, __FILE__, __LINE__);
	      wwrite (dupe, &dupecur, 2, __FILE__, __LINE__);
	      wwrite (dupe, dupbuf, (newarea->dupes * szlong), __FILE__,
		      __LINE__);
	    }
	  cclose ((short *)&dupe, __FILE__, __LINE__);
	  if (isdupe)
	    {
	      if (!bcfg.killdupes)
		buftosqd (dupes, dindex, 1);
	      if (tlist)
		tlist->alist[carea].dupes++;
	      tottoss--;
	      loctoss--;
	      totdupes++;
	      return;
	    }
	}
    }
  if (tlist && !fwdcopy)
    tlist->alist[carea].toss++;
  mystrncat (filemsg, "*.msg", 7, DirSize);
  finish = _dos_findfirst (filemsg, findattr, &fblk);
  while (!finish)
    {
      tnummsg = (short)atoi (fblk.name);
      if (tnummsg > tmsg)
	tmsg = tnummsg;
      finish = _dos_findnext (&fblk);
    }
  _dos_findclose (&fblk);/***ash***/
  tmsg++;
  if (inout)
    mystrncpy (filemsg, inpath, DirSize);
  else
    mystrncpy (filemsg, outpath, DirSize);
  mystrncat (filemsg, itoa (tmsg, temp, 10), 8, DirSize);
  mystrncat (filemsg, ".msg", 6, DirSize);
  if ((msg =
       (short)sopen (filemsg, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR,
		     S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
    {
      mystrncpy (errname, filemsg, DirSize);
      errexit (2, __FILE__, __LINE__);
    }
  memset (&bufmsg, 0, szmessage);
  if (mbigmess && type != 4 /* From Server */ )
    {
      lseek (tempmsg, 0, SEEK_SET);
      rread (tempmsg, bufmess.toname, (unsigned short)(mtolen + 1), __FILE__,
	     __LINE__);
      rread (tempmsg, bufmess.fromname, (unsigned short)(mfromlen + 1),
	     __FILE__, __LINE__);
      rread (tempmsg, bufmess.subj, (unsigned short)(msubjlen + 1), __FILE__,
	     __LINE__);
    }
  mystrncpy (bufmsg.fromname, bufmess.fromname, 35);
  mystrncpy (bufmsg.toname, bufmess.toname, 35);
  mystrncpy (bufmsg.subj, bufmess.subj, 71);
  if (bufmess.datetime[0])
    memcpy (bufmsg.datetime, bufmess.datetime, 20);
  else
    {
      sftime = time (NULL);
      mylocaltime (&sftime, &tmt);
      mystrncpy (tstrtime, asctime (&tmt), 39);
      converttime (tstrtime);
      memcpy (bufmsg.datetime, ftstime, 20);
    }
  bufmsg.timefrom = bufmess.timefrom;
  bufmsg.timeto = bufmess.timeto;
  blink = bcfg.links.chain;
  while (blink)
    {
      if (bufmess.fromzone == blink->address.zone &&
	  bufmess.fromnet == blink->address.net &&
	  bufmess.fromnode == blink->address.node &&
	  bufmess.frompoint == blink->address.point)
	break;
      blink = blink->next;
    }
  if (blink)
    fake = blink->fake;
  else
    fake = 0;
  bufmsg.tonode = bufmess.tonode;
  bufmsg.fromnode = bufmess.fromnode;
  bufmsg.fromnet = bufmess.fromnet;
  bufmsg.tonet = bufmess.tonet;
  btozone = bufmess.tozone;
  bfromzone = bufmess.fromzone;
  btopoint = bufmess.topoint;
  if (!fake)
    bfrompoint = bufmess.frompoint;
  else
    bfrompoint = 0;
  bufmsg.flags = bufmess.flags;
  wwrite (msg, &bufmsg, (unsigned short)(szmessage - szchar), __FILE__,
	  __LINE__);
  if (type == 1 || type == 4)
    {
      sftime = time (NULL);
      times = sftime + nummsg;
      nummsg++;
      hexascii (times, strtimes);
      mystrncpy (msgid, strtimes, 8);
      msgid[8] = 0;
      sprintf (logout, "\1MSGID: %u:%u/%u.%u %s\r", bfromzone,
	       bufmsg.fromnet, bufmsg.fromnode, bfrompoint, msgid);
      mywrite (msg, logout, __FILE__, __LINE__);
      if (bcfg.fintl || (bfromzone != btozone))
	{
	  sprintf (logout, "\1INTL %u:%u/%u %u:%u/%u\r", btozone,
		   bufmsg.tonet, bufmsg.tonode, bfromzone, bufmsg.fromnet,
		   bufmsg.fromnode);
	  mywrite (msg, logout, __FILE__, __LINE__);
	}
      if (bfrompoint)
	{
	  sprintf (logout, "\1FMPT %u\r", bfrompoint);
	  mywrite (msg, logout, __FILE__, __LINE__);
	}
      if (btopoint)
	{
	  sprintf (logout, "\1TOPT %u\r", btopoint);
	  mywrite (msg, logout, __FILE__, __LINE__);
	}
    }
  if (type == 4 && setdir)
    {
      sprintf (logout, "\1FLAGS DIR\r");
      mywrite (msg, logout, __FILE__, __LINE__);
    }
  tkludge = mckludge;
  while (tkludge)
    {
      if (fake)
	{
	  if (strncmp (tkludge->str, "\1MSGID: ", 8) == 0)
	    {
	      temp1 = strchr (tkludge->str, '.');
	      if (temp1)
		{
		  temp1++;
		  *temp1 = '0';
		  temp1++;
		  temp2 = temp1;
		  while (isdigit (*temp2))
		    temp2++;
		  pkludlen -= (unsigned short)(temp2 - temp1);
		  while (*temp2)
		    {
		      *temp1 = *temp2;
		      temp1++;
		      temp2++;
		    }
		  *temp1 = 0;
		}
	    }
	}
      if (!(fake && (strncmp (tkludge->str, "\1FMPT ", 6) == 0)))
	{
	  mywrite (msg, tkludge->str, __FILE__, __LINE__);
	  if (tkludge->str[strlen (tkludge->str) - 1] != '\r')
	    mywrite (msg, "\r", __FILE__, __LINE__);
	}
      tkludge = tkludge->next;
    }
  if (mbigmess)
    {
      while ((fmax2 =
	      (unsigned short)rread (tempmsg, type == 4 ? sqdbuf : pktbuf,
				     buflen, __FILE__, __LINE__)) != 0)
	{
	  fakeorigin (fake, type == 4 ? sqdbuf : pktbuf, fmax2);
	  wwrite (msg, type == 4 ? sqdbuf : pktbuf, fmax2, __FILE__,
		  __LINE__);
	}
    }
  else
    {
      if (mtextlen > 0)
	{
	  fakeorigin (fake, bufmess.text, mtextlen);
	  wwrite (msg, bufmess.text, (unsigned short)(mtextlen), __FILE__,
		  __LINE__);
	}
    }
  if (addorig)
    mywrite (msg, tail, __FILE__, __LINE__);
  wwrite (msg, null1, 1, __FILE__, __LINE__);
  cclose (&msg, __FILE__, __LINE__);
  if (!fwdcopy)
    netstored = 1;
  if (bcfg.netsem[0])
    {
      msg =
	(short)sopen (bcfg.netsem, O_RDWR | O_BINARY | O_CREAT, SH_DENYNO,
		      S_IRWXU | S_IRWXG | S_IRWXO);
      if (msg != -1)
	cclose (&msg, __FILE__, __LINE__);
    }
}
