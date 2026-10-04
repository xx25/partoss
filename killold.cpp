// MaxiM: find_t

#include "partoss.h"
#include "globext.h"

#include "killold.h"
#include "lowlevel.h"
#include "morfiles.h"
#include "errors.h"
#include "times.h"
#include "control.h"
#include "msgtobuf.h"
#include "crc32.h"
#include "attach.h"
#include "buftomsg.h"
#include "template.h"

char shname[16], fname[16], fpname[16];
short zfile;

void killold (void)
{
  struct link *blink = NULL;
  struct myaddr *link = NULL;
  char ext[5], zonext[6], *temp = NULL, ttempl[DirSize + 1];
  char hfile[DirSize + 1];
  short tmpl, waskill;
  unsigned long lpack, subnet, subnode;

  zfile = 0;
  sftime = time (NULL);
  mylocaltime (&sftime, &tmt);
  mystrncpy (tstrtime, asctime (&tmt), 39);
  ext[0] = '.';
  ext[1] = tstrtime[0];
  ext[2] = tstrtime[1];
  ext[4] = 0;
  zonext[0] = '.';
  zonext[4] = 0;
  zonext[5] = 0;
  mystrncpy (hfile, bcfg.workdir, DirSize);
  mystrncat (hfile, "$$temp$$.$$$", DirSize, DirSize);
  if ((zfile =
       (short)sopen (hfile, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR,
		     S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
    {
      mystrncpy (errname, hfile, DirSize);
      errexit (2, __FILE__, __LINE__);
    }
  blink = bcfg.links.chain;
  while (blink)
    {
      if (blink->days)
	{
	  waskill = 0;
	  chsize (zfile, 0);
	  lseek (zfile, 0, SEEK_SET);
	  link = bcfg.address.chain;
	  while (link)
	    {
	      memset (shname, 0, 16);
	      // hexstyle==10
	      memset (logout, 0, BufSize);
	      logprintf ("%u:%u/%u.%u~%u:%u/%u.%u", link->zone,
		       link->net, link->node, link->point,
		       blink->address.zone, blink->address.net,
		       blink->address.node, blink->address.point);
	      lpack = crc32block (logout, (short)strlen (logout), 0);
	      hexascii (lpack, shname);
	      waskill |= killbox (blink);
	      // hexstyle==1
	      subnet = (link->net - blink->address.net) & 0xffff;
	      subnode = (link->node - blink->address.node) & 0xffff;
	      lpack = subnet << 16;
	      lpack |= subnode;
	      hexascii (lpack, shname);
	      waskill |= killbox (blink);

	      subnet = link->node;
	      subnode = link->point;
	      lpack = subnet << 12;
	      lpack |= (subnode & 0xfff);
	      hexascii (lpack, shname);
	      shname[0] = link->point ? 'b' : 'a';
	      waskill |= killbox (blink);
	      subnet = link->node;
	      subnode = link->point;
	      lpack = subnet << 12;
	      lpack |= (subnode & 0xfff);
	      hexascii (lpack, shname);
	      shname[0] = link->point ? 'n' : 'p';
	      waskill |= killbox (blink);
	      subnet = blink->address.node;
	      subnode = blink->address.point;
	      lpack = subnet << 12;
	      lpack |= (subnode & 0xfff);
	      hexascii (lpack, shname);
	      shname[0] = link->point ? 'b' : 'a';
	      waskill |= killbox (blink);
	      subnet = blink->address.node;
	      subnode = blink->address.point;
	      lpack = subnet << 12;
	      lpack |= (subnode & 0xfff);
	      hexascii (lpack, shname);
	      shname[0] = link->point ? 'n' : 'p';
	      waskill |= killbox (blink);
	      link = link->next;
	    }

	  if (waskill && bcfg.killtempl[0] && !blink->nokrep)
	    {
// Find closest matched address
	      if (blink->address.point)
		{
		  link = bcfg.address.chain;
		  while (link)
		    {
		      if ((link->zone == blink->address.zone) &&
			  (link->net == blink->address.net) &&
			  (link->node == blink->address.node) &&
			  (link->point == 0))
			goto lnkfound;
		      link = link->next;
		    }
		}
	      else
		{
		  link = bcfg.address.chain;
		  while (link)
		    {
		      if ((link->zone == blink->address.zone) &&
			  (link->net == blink->address.net) &&
			  (link->point == 0))
			goto lnkfound;
		      link = link->next;
		    }
		  if (link == NULL)
		    {
		      link = bcfg.address.chain;
		      while (link)
			{
			  if ((link->zone == blink->address.zone) &&
			      (link->net == blink->address.net) &&
			      (link->node == blink->address.node))
			    goto lnkfound;
			  link = link->next;
			}
		      if (link == NULL)
			{
			  link = bcfg.address.chain;
			  while (link)
			    {
			      if (link->zone == blink->address.zone
				  && link->point == 0)
				goto lnkfound;
			      link = link->next;
			    }
			}
		    }
		}
	    lnkfound:
	      if (link == NULL)
		link = bcfg.address.chain;
// Find closest matched address
	      bufpkt.toname = (char *)myalloc (36, __FILE__, __LINE__);
	      bufpkt.fromname = (char *)myalloc (36, __FILE__, __LINE__);
	      bufpkt.subj = (char *)myalloc (72, __FILE__, __LINE__);
	      bufpkt.tozone = blink->address.zone;
	      bufpkt.tonet = blink->address.net;
	      bufpkt.tonode = blink->address.node;
	      bufpkt.topoint = blink->address.point;
	      bufpkt.fromzone = link->zone;
	      bufpkt.fromnet = link->net;
	      bufpkt.fromnode = link->node;
	      bufpkt.frompoint = link->point;
	      if (blink->name[0])
		mystrncpy (bufpkt.toname, blink->name, 35);
	      else
		mystrncpy (bufpkt.toname, "SysOp", 35);
	      mystrncpy (bufpkt.fromname, bcfg.manfrom, 35);
	      mystrncpy (bufpkt.subj, "Killed ArcMail report", 71);
	      mtolen = strlen (bufpkt.toname);
	      mfromlen = strlen (bufpkt.fromname);
	      msubjlen = strlen (bufpkt.subj);
	      bufpkt.flags = 0x181;
	      mbigmess = 1;
	      memcpy (&bufmess, &bufpkt, szpackmess);
	      bufmess.toname = bufpkt.toname;
	      bufmess.fromname = bufpkt.fromname;
	      bufmess.subj = bufpkt.subj;
	      if ((bcfg.killtempl[0] != DIRSEP[0])
		  && (bcfg.killtempl[2] != ':'))
		{
		  mystrncpy (ttempl, homedir, DirSize);
		  mystrncat (ttempl, (char *)bcfg.killtempl, DirSize, DirSize);
		}
	      if ((tmpl =
		   (short)sopen (ttempl, O_RDONLY | O_BINARY, SH_DENYWR)) > 0)
		{
		  tempmsg = templat (zfile, tmpl);
		  lseek (tempmsg, 0, SEEK_SET);
		  pmsglen = ptextlen = filelength (tempmsg);
		  pmsglen += pkludlen - 1;
		  mckludge = NULL;
		  needout = 1;
		  buftomsg (4);
		  cclose (&tempmsg, __FILE__, __LINE__);
		  cclose (&tmpl, __FILE__, __LINE__);
		  unlink (pttmpl);
		}
	      myfree ((void **)&bufpkt.subj, __FILE__, __LINE__);
	      myfree ((void **)&bufpkt.fromname, __FILE__, __LINE__);
	      myfree ((void **)&bufpkt.toname, __FILE__, __LINE__);
	    }
	}
      blink = blink->next;
    }
  cclose (&zfile, __FILE__, __LINE__);
  unlink (hfile);
}

short killbox (struct link *blink)
{
  unsigned short i, waskill = 0;
  struct uplname *bladv = NULL;
  char tmpname[DirSize + 1], packets[DirSize + 1], zonext[5];
  shname[8] = 0;
  // boxes==1
  bladv = bcfg.bladv;
  while (bladv)
    {
      if (cmpaddr (&bladv->upaddr, &blink->address) == 0)
	break;
      bladv = bladv->next;
    }
  if (bladv && (bladv->echolist[0]))
    {
      mystrncpy (tmpname, bladv->echolist, DirSize);
      waskill |= kill (tmpname, 1, blink);
    }
  mystrncpy (tmpname, makebox (&blink->address, 0, 0), DirSize);
  waskill |= kill (tmpname, 1, blink);
  mystrncpy (tmpname, makebox (&blink->address, 0, 1), DirSize);
  waskill |= kill (tmpname, 1, blink);
  mystrncpy (tmpname, makebox (&blink->address, 1, 0), DirSize);
  waskill |= kill (tmpname, 1, blink);
  mystrncpy (tmpname, makebox (&blink->address, 1, 1), DirSize);
  waskill |= kill (tmpname, 1, blink);
  mystrncpy (tmpname, makebox (&blink->address, 2, 0), DirSize);
  waskill |= kill (tmpname, 1, blink);
  mystrncpy (tmpname, makebox (&blink->address, 2, 1), DirSize);
  waskill |= kill (tmpname, 1, blink);

  // boxes==4
  for (i = 0; i < 4; i++)
    {
      fname[i] = duotrice[((blink->address.net) >> ((3 - i) << 2)) & 0xf];
      fname[i + 4] =
	duotrice[((blink->address.node) >> ((3 - i) << 2)) & 0xf];
      fpname[i] = '0';
      fpname[i + 4] =
	duotrice[((blink->address.point) >> ((3 - i) << 2)) & 0xf];
    }
  fname[8] = fpname[8] = 0;
  mystrncpy (packets, bcfg.outbound, DirSize);
  if (blink->address.zone != bcfg.address.chain->zone)
    {
      zonext[0] = '.';
      zonext[1] = duotrice[((blink->address.zone) >> 8) & 0xf];
      zonext[2] = duotrice[((blink->address.zone) >> 4) & 0xf];
      zonext[3] = duotrice[(blink->address.zone) & 0xf];
      zonext[4] = 0;
      mystrncat (packets, zonext, 7, DirSize);
    }
  mystrncat (packets, DIRSEP, 3, DirSize);
  if (blink->address.point)
    {
      mystrncat (packets, fname, 10, DirSize);
#if defined (__linux__) || defined (__FreeBSD__)
      mystrncat (packets, ".pnt/", 7, DirSize);
#else
      mystrncat (packets, ".pnt\\", 7, DirSize);
#endif
    }
  mystrncpy (tmpname, packets, DirSize);
  waskill |= kill (tmpname, 4, blink);

  mystrncpy (tmpname, outbound, DirSize);
  waskill |= kill (tmpname, 2, blink);
  memset (shname, 0, 16);
  return waskill;
}

short kill (char *tmpname, short boxes, struct link *blink)
{
  char arcname[(DirSize + 1)], tmpfile[DirSize + 1], tfile[DirSize + 1],
    badname[(DirSize + 1)], *temp = NULL, binkname[(DirSize + 1)],
    tbinkname[(DirSize + 1)];
  short i, found, diff, waskill = 0, nomore, topack, msg, j, ii;
  unsigned short fyear, fmonth, fday;
  unsigned long currtime, filetime;
  struct find_t fblk, tblk;
  mystrncpy (arcname, tmpname, DirSize);
  mystrncat (arcname, shname, 16, DirSize);
  mystrncat (arcname, ".???", 5, DirSize);
  logprintf ("Search %s (%u:%u/%u.%u)", arcname, blink->address.zone,
	   blink->address.net, blink->address.node, blink->address.point);
  logwrite (1, 12);
  for (ii = 0; ii < 7; ii++)
    {
      arcname[strlen (arcname) - 3] = arcsh[ii][2];
      arcname[strlen (arcname) - 2] = arcsh[ii][3];
      found = (short)_dos_findfirst (arcname, findattr, &fblk);
      while (found == 0)
	{
	  if (fblk.size)
	    {
	      mystrncpy (tstrtime, asctime (&tmt), 39);
	      currtime = strtime (tstrtime);
	      filetime = fblk.wr_time;
	      filetime <<= 16;
	      filetime += fblk.wr_date;
	      diff = diffdays (filetime, currtime);
	      if (diff >= blink->days)
		{
		  waskill = 1;
		  mystrncpy (badname, tmpname, DirSize);
		  mystrncat (badname, fblk.name, 16, DirSize);
		  fyear =
		    (unsigned short)((((fblk.wr_date & 0xfe00) >> 9) + 1980));
		  fmonth = (unsigned short)(((fblk.wr_date & 0x1e0) >> 5));
		  fday = (unsigned short)((fblk.wr_date & 0x1f));
		  logprintf ("%s (%u %s %u) - %ld bytes\r\n", fblk.name,
			   fday, months[fmonth - 1], fyear, fblk.size);
		  mywrite (zfile, logout, __FILE__, __LINE__);
		  unlink (badname);
		  if (boxes != 1)
		    {
		      if (boxes < 4)
			{
			  mystrncpy (tmpfile, outpath, DirSize);
			  mystrncat (tmpfile, "*.msg", 7, DirSize);
			  nomore =
			    (short)_dos_findfirst (tmpfile, findattr, &tblk);
			  while (nomore == 0)
			    {
			      if (!(tblk.attrib & 0x1f))
				{
				  mystrncpy (tfile, outpath, DirSize);
				  mystrncat (tfile, tblk.name, 16, DirSize);
				  topack = msgtobuf (tfile);
				  if (bufmsg.flags & 0x10)
				    {
				      temp =
					strstr (strupr (bufmsg.subj),
						strupr (badname));
				      if (temp)
					{
					  while (*temp && !isspace (*temp))
					    {
					      *temp = ' ';
					      temp++;
					    }
					  temp = bufmsg.subj;
					  topack = 0;
					  while (*temp)
					    {
					      if (!isspace (*temp))
						topack = 1;
					      temp++;
					    }
					  if (!topack)
					    unlink (tfile);
					  else
					    {
					      msg =
						mysopen (tfile, 1, __FILE__,
							 __LINE__);
					      lseek (msg, 72, SEEK_SET);
					      wwrite (msg, bufmsg.subj, 72,
						      __FILE__, __LINE__);
					      cclose (&msg, __FILE__,
						      __LINE__);
					    }
					}
				    }
				  delctrl (3);
				}
			      nomore = (short)_dos_findnext (&tblk);
			    }
			  _dos_findclose (&tblk);
			}
		      else
			{
			  mystrncpy (binkname, tmpname, DirSize);
			  mystrncat (binkname,
				     blink->address.point ? fpname : fname,
				     10, DirSize);
			  mystrncat (binkname, ".?lo", 5, DirSize);
			  i =
			    (short)_dos_findfirst (binkname, findattr, &tblk);
			  if (i == 0)
			    {
			      logprintf ("Try to clean %s from %s",
				       badname, binkname);
			      logwrite (1, 10);
			      binkname[strlen (binkname) - 3] =
				tblk.name[strlen (tblk.name) - 3];
			      mystrncpy (tbinkname, binkname, DirSize);
			      tbinkname[strlen (tbinkname) - 3] = '_';
			      i = mysopen (binkname, 0, __FILE__, __LINE__);
			      if ((j =
				   (short)sopen (tbinkname,
						 O_RDWR | O_BINARY | O_CREAT,
						 SH_DENYWR,
						 S_IRWXU | S_IRWXG | S_IRWXO))
				  <= 0)
				{
				  mystrncpy (errname, tbinkname, DirSize);
				  errexit (2, __FILE__, __LINE__);
				}
			      endinput[0] = 0;
			      while (!endinput[0])
				{
				  readblock (i, 0);
				  endblock[0] = 0;
				  do
				    {
				      getstring (0);
				      gettoken (0);
				      tokencpy (logout, BufSize);
				      if ((temp =
					   strstr (strupr (logout),
						   strupr (badname))) == NULL)
					wwrite (j, ::string, maxstr2[0],
						__FILE__, __LINE__);
				    }
				  while (!endblock[0]);
				}
			      close (i);
			      unlink (binkname);
			      if (filelength (j))
				{
				  close (j);
				  rrename (tbinkname, binkname);
				}
			      else
				{
				  close (j);
				  unlink (tbinkname);
				}
			      _dos_findclose (&tblk);
			    }
			}
		    }
		  logprintf ("Killed %s for %u:%u/%u.%u", badname,
			   blink->address.zone, blink->address.net,
			   blink->address.node, blink->address.point);
		  if (logfileok)
		    logwrite (1, 1);
		  ccprintf ("%s\r\n", logout);
		}
	    }
	  found = (short)_dos_findnext (&fblk);
	}
      _dos_findclose (&fblk);
    }
  return waskill;
}
