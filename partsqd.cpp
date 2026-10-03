// MaxiM: memicmp strupr _dos_getftime

#include "partoss.h"
#include "globext.h"

#include "partsqd.h"
#include "lowlevel.h"
#include "morfiles.h"
#include "errors.h"
#include "chains.h"
#include "attach.h"
#include "environ.h"
#include "partserv.h"

short setarea (char *areaname, short pers)
{
  wipearea = 1;
  if (stricmp (areaname, oldarea) == 0)
    {
      if (!pers)
	return arealock;
      else
	return -1;
    }
  tlist = rlist;
  while (tlist)
    {
      for (carea = 0; carea < tlist->numlists; carea++)
	{
	  if (stricmp (tlist->alist[carea].areaname, areaname) == 0)
	    {
	      if (tlist->alist[carea].type < 100)
		goto nfound;
	      else
		{
		  memset (oldarea, 0, arealength);
		  return -2;
		}
	    }
	}
      tlist = tlist->next;
    }
nfound:
  if (tlist && carea < tlist->numlists)
    {
      if (openarea (carea, pers) == -2)
	{
	  memset (oldarea, 0, arealength);
	  return -2;
	}
    }
  else
    {
      if (create || pers)
	{
	  createarea (areaname, pers, &pktaddr);
	  openarea (carea, pers);
	}
      else
	{
	  memset (oldarea, 0, arealength);
	  wipearea = 0;
	  return -1;
	}
    }
  return arealock;
}

void setbadarea (void)
{
  short i, tquiet;
  badmess = (struct area *)myalloc (szarea, __FILE__, __LINE__);
  memset (badmess, 0, szarea);
  bindex = (struct sqifile *)myalloc ((12 * bufsqi), __FILE__, __LINE__);
  tlist = rlist;
  while (tlist)
    {
      for (i = 0; i < tlist->numlists; i++)
	if (tlist->alist[i].type == 2)
	  {
	    lseek (areaset, tlist->alist[i].areaoffs, SEEK_SET);
	    rread (areaset, badmess, szarea, __FILE__, __LINE__);
	    goto nfound2;
	  }
      tlist = tlist->next;
    }
  errexit (8, __FILE__, __LINE__);
nfound2:
  opensqd (badmess, bindex, 0, 1);
  if (arealock)
    badlocked = 1;
  else
    badlocked = 0;
  if (!bcfg.killdupes)
    {
      dupes = (struct area *)myalloc (szarea, __FILE__, __LINE__);
      memset (dupes, 0, szarea);
      dindex = (struct sqifile *)myalloc ((12 * bufsqi), __FILE__, __LINE__);
      tlist = rlist;
      while (tlist)
	{
	  for (i = 0; i < tlist->numlists; i++)
	    if (tlist->alist[i].type == 3)
	      {
		lseek (areaset, tlist->alist[i].areaoffs, SEEK_SET);
		rread (areaset, dupes, szarea, __FILE__, __LINE__);
		goto nfound3;
	      }
	  tlist = tlist->next;
	}
      errexit (9, __FILE__, __LINE__);
    nfound3:
      opensqd (dupes, dindex, 0, 1);
      if (arealock)
	dupelocked = 1;
      else
	dupelocked = 0;
    }
  if (bcfg.myname.numelem && !(mode & 2048))
    {
      tquiet = quiet;
      quiet = 1;
      setarea (bcfg.myname.chain->persarea, 1);
      quiet = tquiet;
    }
}

int openarea (unsigned short i, short pers)
{
  struct area *ttarea1 = NULL;
  struct sqifile *tindex = NULL;
  struct myaddr tsnd;
  ttarea1 = (pers ? persarea : newarea);
  tindex = (pers ? pindex : nindex);
  if (ttarea1->open)
    closesqd (ttarea1, 1);
  lseek (areaset, tlist->alist[i].areaoffs, SEEK_SET);
  rread (areaset, ttarea1, szarea, __FILE__, __LINE__);
  if (ttarea1->delday)
    return -2;
  ttarea1->links.chain = ttarea1->links.last = NULL;
  ttarea1->links.numelem = 0;
  for (i = 0; i < ttarea1->numlinks; i++)
    {
      rread (areaset, &tsnd, szmyaddr, __FILE__, __LINE__);
      addaddr (&(ttarea1->links), &tsnd);
    }
  if (!pers)
    {
//    memset(oldarea,0,arealength);
      mystrncpy (oldarea, curarea, arealength - 1);
    }
  opensqd (ttarea1, tindex, 1, pers);
  return 0;
}

void opensqd (struct area *ttarea, struct sqifile *tindex, short dup,
	      short pers)
{
  char sqdfile[(DirSize + 1)], sqdir[(DirSize + 1)], *temp = NULL;
  short namelen, finish = 0, fplen, shdeny;
  int terrno;
  unsigned short tnummsg, ttnum;
  long tindlen;
  if (bcfg.locked == 1)
    shdeny = SH_DENYNO;
  else
    shdeny = SH_DENYWR;
  arealock = 0;
  if (ttarea->type)
    {
      if ((strcmp (ttarea->areaname, persarea->areaname) == 0)
	  && (persarea->open))
	{
	  ttarea->sqd.sqd = persarea->sqd.sqd;
	  ttarea->sqd.sqi = persarea->sqd.sqi;
	  ttarea->sqd.sqb = persarea->sqd.sqb;
	  memcpy (tindex, pindex, 12 * bufsqi);
	  return;
	}
      namelen = (short)strlen (ttarea->areafp);
      memset (sqdir, 0, (DirSize + 1));
      mystrncpy (sqdfile, ttarea->areafp, DirSize);
      temp = strrchr (ttarea->areafp, DIRSEP[0]);
      if (temp)
	{
	  mystrncpy (sqdir, ttarea->areafp, (short)(temp - ttarea->areafp));
	  createpath (sqdir);
	}
      mystrncat (sqdfile, ".sqd", 6, DirSize);
      ttarea->sqd.sqb = 0;
      ttarea->open = 0;
      while (!finish)
	{
	  ttarea->sqd.sqd = (short)sopen (sqdfile, O_RDWR | O_BINARY, shdeny);
	  if (ttarea->sqd.sqd == -1)
	    {
	      terrno = errno;
	      if ((ttarea->passthr) && ((mode & 3) == 3) && !pers)
		goto passthru;
	      switch (terrno)
		{
		case ENOENT:
		  memset (&sqbuf, 0, szsqdfile);
		  sqbuf.endf = sqbuf.len = (short)256;
		  sqbuf.uid = 1;
		  fplen = (short)strlen (ttarea->areafp);
		  if (fplen < 80)
		    mystrncpy (sqbuf.base, ttarea->areafp, fplen);
		  else
		    {
		      mystrncpy (sqbuf.base, ttarea->areafp, 3);
		      mystrncat (sqbuf.base, "...", 4, 79);
		      mystrncat (sqbuf.base, ttarea->areafp + (fplen - 72),
				 79, 79);
		    }
		  sqbuf.szsqhdr = 28;
		  if ((ttarea->sqd.sqd =
		       (short)sopen (sqdfile, O_RDWR | O_BINARY | O_CREAT,
				     shdeny,
				     S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
		    {
		      mystrncpy (errname, sqdfile, DirSize);
		      errexit (2, __FILE__, __LINE__);
		    }
		  wwrite (ttarea->sqd.sqd, &sqbuf, 256, __FILE__, __LINE__);
		  flushbuf (ttarea->sqd.sqd);
		  sqdfile[namelen + 3] = 'i';
		  if ((ttarea->sqd.sqi =
		       (short)sopen (sqdfile, O_RDWR | O_BINARY | O_CREAT,
				     shdeny,
				     S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
		    {
		      mystrncpy (errname, sqdfile, DirSize);
		      errexit (2, __FILE__, __LINE__);
		    }
		  finish = 1;
		  break;

		case EMFILE:
		  mystrncpy (errname, sqdfile, DirSize);
		  errexit (2, __FILE__, __LINE__);

		case EACCES:
		case -1:
		  if (bcfg.locked == 2 || bcfg.locked == 4)
		    {
		      arealock = 1;
		      return;
		    }
		  else
		    {
		      if (lich)
			{
			  sprintf (logout, "Waiting for open %s", sqdfile);
			  logwrite (1, 1);
			}
		      mtsleep (5);
		    }
		  break;

		default:
		  mystrncpy (errname, sqdfile, DirSize);
		  errexit (2, __FILE__, __LINE__);
		}
	    }
	  else
	    {
	      rread (ttarea->sqd.sqd, &sqbuf, 256, __FILE__, __LINE__);
	      if (sqbuf.highwater >= sqbuf.uid)
		sqbuf.highwater = sqbuf.uid - 1;
	      sqdfile[namelen + 3] = 'i';
	      if ((ttarea->sqd.sqi =
		   (short)sopen (sqdfile, O_RDWR | O_BINARY, shdeny)) == -1)
		if ((ttarea->sqd.sqi =
		     (short)sopen (sqdfile, O_RDWR | O_BINARY | O_CREAT,
				   shdeny,
				   S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
		  {
		    mystrncpy (errname, sqdfile, DirSize);
		    errexit (2, __FILE__, __LINE__);
		  }
	      tindlen = filelength (ttarea->sqd.sqi) / 12;
	      if (tindlen < sqbuf.nummsg)
		sqbuf.nummsg = sqbuf.highmsg = tindlen;
	      ttnum =
		(unsigned
		 short)(((sqbuf.nummsg <
			  bufsqi) ? sqbuf.nummsg : bufsqi) * 12);
	      tnummsg =
		(unsigned short)rread (ttarea->sqd.sqi, tindex, ttnum,
				       __FILE__, __LINE__);
	      if (tnummsg == 65535u)
		return;		/* LMA!!!  use unused variable */
//        if(tnummsg<ttnum)
//          sqbuf.nummsg=sqbuf.highmsg=(tnummsg/12);
	      finish = 1;
	    }
	}
      if (bcfg.nofresh)
	{
	  ttarea->messages = (short)sqbuf.maxmsg;
	  ttarea->skipmsg = (short)sqbuf.skipmsg;
	  ttarea->days = sqbuf.keepdays;
	}
      else
	{
	  sqbuf.maxmsg = ttarea->messages;
	  sqbuf.skipmsg = ttarea->skipmsg;
	  sqbuf.keepdays = ttarea->days;
	}
    passthru:
      if (ttarea->type == 1)
	{
	  if (!quiet)
	    ccprintf ("%-60s\r", ttarea->areaname);
	  if (ttarea->dupes && dup)
	    {
	      sqdfile[namelen + 3] = 'p';
	      if ((ttarea->sqd.sqb =
		   (short)sopen (sqdfile, O_RDWR | O_BINARY, shdeny)) == -1)
		{
		  if ((ttarea->sqd.sqb =
		       (short)sopen (sqdfile, O_RDWR | O_BINARY | O_CREAT,
				     shdeny,
				     S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
		    {
		      mystrncpy (errname, sqdfile, DirSize);
		      errexit (2, __FILE__, __LINE__);
		    }
		  dupecur = dupemax = 0;
		  memset (dupbuf, 0, ttarea->dupes * szlong);
		}
	      else
		{
		  rread (ttarea->sqd.sqb, &dupemax, 2, __FILE__, __LINE__);
		  rread (ttarea->sqd.sqb, &dupecur, 2, __FILE__, __LINE__);
		  if ((dupemax > ttarea->dupes) || (dupecur > dupemax))
		    {
		      sprintf (logout, "!!! File %s.sqp possibly corrupted",
			       ttarea->areafp);
		      logwrite (1, 1);
		    }
		  rread (ttarea->sqd.sqb, dupbuf, (ttarea->dupes * szlong),
			 __FILE__, __LINE__);
		}
	    }
	}
      if (!((ttarea->passthr) && ((mode & 3) == 3) && !pers))
	{
	  if (!bcfg.nofresh)
	    {
	      lseek (ttarea->sqd.sqd, 0, SEEK_SET);
	      wwrite (ttarea->sqd.sqd, &sqbuf, 256, __FILE__, __LINE__);
	      flushbuf (ttarea->sqd.sqd);
	    }
	}
      ttarea->open = 1;
      ttarea->curindex = ttarea->touched = 0;
      ttarea->logged = 0;
    }
}

void closesqd (struct area *ttarea, short dup)
{
  long nummsg;
  char sqdfile[(DirSize + 1)];
  if (ttarea == NULL)
    return;
  if (ttarea->type)
    {
      if (ttarea->open)
	{
	  if (ttarea->sqd.sqd == -1)
	    goto passthru;
	  lseek (ttarea->sqd.sqd, 4, SEEK_SET);
	  rread (ttarea->sqd.sqd, &nummsg, 4, __FILE__, __LINE__);
	  cclose (&ttarea->sqd.sqd, __FILE__, __LINE__);
	  cclose (&ttarea->sqd.sqi, __FILE__, __LINE__);
	  if ((ttarea->passthr || (ttarea->type > 1)) && !nummsg)
	    {
	      mystrncpy (sqdfile, ttarea->areafp, DirSize);
	      mystrncat (sqdfile, ".sqd", 6, DirSize);
	      unlink (sqdfile);
	      sqdfile[strlen (sqdfile) - 1] = 'i';
	      unlink (sqdfile);
	      sqdfile[strlen (sqdfile) - 1] = 'l';
	      unlink (sqdfile);
	    }
	passthru:
	  if (ttarea->sqd.sqb && dup)
	    {
	      if (ttarea->duptouch)
		{
		  chsize (ttarea->sqd.sqb, 0);
		  lseek (ttarea->sqd.sqb, 0, SEEK_SET);
		  wwrite (ttarea->sqd.sqb, &dupemax, 2, __FILE__, __LINE__);
		  wwrite (ttarea->sqd.sqb, &dupecur, 2, __FILE__, __LINE__);
		  wwrite (ttarea->sqd.sqb, dupbuf, (ttarea->dupes * szlong),
			  __FILE__, __LINE__);
		}
	      cclose (&ttarea->sqd.sqb, __FILE__, __LINE__);
	    }
	  ttarea->open = 0;
	}
    }
  deladdr (&(ttarea->links));
}

void createarea (char *areaname, short pers, struct myaddr *pktaddr2)
{
  struct myaddr *taddr = NULL, *link = NULL;
  short i, j;
  short usingshablon = 0;
  unsigned short autonum = 0, tnum, fplen;
#if defined(__BORLANDC__) || (defined(__WATCOMC__) && defined(__386__))
  unsigned date, time;
#else
  unsigned short date, time /*,fyear,fmonth,fday */ ;
#endif
  // unsigned short fhour,fmin,fsec;
  char newname[BufSize + 1], tareaname[arealength + 1], autotemp[5], *temp =
    NULL, *temp2 = NULL;
  struct areaindex *anew = NULL;
  struct area *crarea = NULL, tdefarea, testarea;
  struct link *blink = NULL;
  struct uplname *bladv = NULL;
  mystrncpy (tareaname, areaname, arealength + 1);
  for (i = 0; i < strlen (tareaname); i++)
    {
      if (isspace (tareaname[i]))
	break;
      tareaname[i] = (char)toupper (tareaname[i]);
    }
  crarea = ((pers == 1) ? persarea : newarea);
  if (crarea->open)
    closesqd (crarea, 1);
  mystrncpy (newname, bcfg.areapath, DirSize);
  bladv = bcfg.bladv;
  while (bladv)
    {
      if (cmpaddr (&bladv->upaddr, pktaddr2) == 0)
	break;
      bladv = bladv->next;
    }
  if (bladv)
    {
      sprintf (logout, "Creating area using settings for node %u:%u/%u.%u",
	       pktaddr2->zone, pktaddr2->net, pktaddr2->node, pktaddr2->point);
      logwrite (1, 14);
      if (bladv->persarea[0])
	{
	  tlist = rlist;
	  while (tlist)
	    {
	      for (i = 0; i < tlist->numlists; i++)
		{
		  if (stricmp (tlist->alist[i].areaname, bladv->persarea) == 0
		      && strlen (tlist->alist[i].areaname) ==
		      strlen (bladv->persarea))
		    {
		      lseek (areaset, tlist->alist[i].areaoffs, SEEK_SET);
		      rread (areaset, crarea, szarea, __FILE__, __LINE__);
		      memcpy (&tdefarea, crarea, szarea);
		      mystrncpy (newname, crarea->areafp, DirSize);
#if defined(__linux__) || defined(__FreeBSD__)
		      temp = strrchr (newname, '/');
#else
		      temp = strrchr (newname, '\\');
#endif
		      usingshablon = 1;
		      if (temp)
			temp[1] = 0;
		      sprintf (logout, "Using area %s as template",
			       tlist->alist[i].areaname);
		      logwrite (1, 14);
		      goto founddef;
		    }
		}
	      tlist = tlist->next;
	    }
	}
    }
  else
    {
      sprintf (logout, "Creating area using default settings");
      logwrite (1, 14);
    }
  sprintf (logout, "Using DefaultArea as template");
  logwrite (1, 14);
founddef:
  if (bcfg.longfp)
    {
      for (i = 0; i < strlen (tareaname); i++)
        if (!(isalnum (tareaname[i]) || (tareaname[i] == '.')))
          tareaname[i] = '_';
      mystrncat (newname, tareaname, arealength, DirSize);
      j = 0;
      i = (short)access (newname, 0);
      while (i != -1)
      {
        if (j == 0)
          mystrncat (newname, "_0", 3, DirSize);
        j++;
        newname[strlen (newname) - 1] = duotrice[j & 0xf];
        i = (short)access (newname, 0);
        autonum++;
      }
    }
  else
    {
      if (bcfg.nrenum)
	{
     unsigned char * checkbuf = (unsigned char *)myalloc (8192, __FILE__, __LINE__);
     memset(checkbuf, 0, 8192);
     tlist = rlist;
     while (tlist)
     {
       for (i = 0; i < tlist->numlists; i++)
       {
         lseek (areaset, tlist->alist[i].areaoffs, SEEK_SET);
         rread (areaset, &testarea, szarea, __FILE__, __LINE__);
         fplen = (short)strlen (testarea.areafp);
         if (memicmp (testarea.areafp + fplen - 8, "auto", 4) == 0)
         {
           tnum = (short)((hex (*(testarea.areafp + fplen - 4)) << 12) +
                          (hex (*(testarea.areafp + fplen - 3)) << 8) +
                          (hex (*(testarea.areafp + fplen - 2)) << 4) +
                          (hex (*(testarea.areafp + fplen - 1))));
           checkbuf[tnum/8]|=(1<<(tnum%8));
         }
      }
      tlist = tlist->next;
    }
    i = 0;
    while (i != -1)
    {
      if (!(checkbuf[autonum/8] & (1<<(autonum%8))))
      {
#if defined(__linux__) || defined(__FreeBSD__)
        temp = strrchr (newname, '/');
#else
        temp = strrchr (newname, '\\');
#endif
        if (temp)
          temp[1] = 0;
        else newname[0]=0;
        mystrncat (newname, "auto", 6, DirSize);
        autotemp[0] = duotrice[(autonum >> 12) & 0xf];
        autotemp[1] = duotrice[(autonum >> 8) & 0xf];
        autotemp[2] = duotrice[(autonum >> 4) & 0xf];
        autotemp[3] = duotrice[autonum & 0xf];
        autotemp[4] = 0;
        mystrncat (newname, autotemp, 6, DirSize);
        mystrncat (newname, ".sqd", 6, DirSize);
        i = (short)access (newname, 0);
        if (i == -1)
        {
          newname[strlen (newname) - 1] = 'i';
          i = (short)access (newname, 0);
          if (i == -1)
          {
            newname[strlen (newname) - 1] = 'p';
            i = (short)access (newname, 0);
          }
        }
      }
      if (autonum == 0xFFFF)
      {
        sprintf (logout, "AutoCreate overflow");
        logwrite (1, 14);
        errexit (15, __FILE__, __LINE__);
      }
      autonum++;
    }
    newname[strlen (newname) - 4] = 0;
    myfree ((void **)&checkbuf, __FILE__, __LINE__);
	}
  else
	{
	  tlist = rlist;
	  while (tlist)
	    {
	      for (i = 0; i < tlist->numlists; i++)
		{
		  lseek (areaset, tlist->alist[i].areaoffs, SEEK_SET);
		  rread (areaset, &testarea, szarea, __FILE__, __LINE__);
		  fplen = (short)strlen (testarea.areafp);
		  if (memicmp (testarea.areafp + fplen - 8, "auto", 4) == 0)
		    {
		      tnum =
			(short)((hex (*(testarea.areafp + fplen - 4)) << 12) +
				(hex (*(testarea.areafp + fplen - 3)) << 8) +
				(hex (*(testarea.areafp + fplen - 2)) << 4) +
				(hex (*(testarea.areafp + fplen - 1))));
		      if (tnum >= autonum)
			autonum = (short)(tnum + 1);
		    }
		}
	      tlist = tlist->next;
	    }

      i = 0;
      while (i != -1)
	{
#if defined(__linux__) || defined(__FreeBSD__)
     temp = strrchr (newname, '/');
#else
     temp = strrchr (newname, '\\');
#endif
	  if (temp)
	    temp[1] = 0;
	  else newname[0]=0;
	  mystrncat (newname, "auto", 6, DirSize);
	  autotemp[0] = duotrice[(autonum >> 12) & 0xf];
	  autotemp[1] = duotrice[(autonum >> 8) & 0xf];
	  autotemp[2] = duotrice[(autonum >> 4) & 0xf];
	  autotemp[3] = duotrice[autonum & 0xf];
	  autotemp[4] = 0;
	  mystrncat (newname, autotemp, 6, DirSize);
	  mystrncat (newname, ".sqd", 6, DirSize);
	  i = (short)access (newname, 0);
	  if (i == -1)
	    {
	      newname[strlen (newname) - 1] = 'i';
	      i = (short)access (newname, 0);
	      if (i == -1)
		{
		  newname[strlen (newname) - 1] = 'p';
		  i = (short)access (newname, 0);
		}
	    }
       if (autonum == 0xFFFF)
       {
		  sprintf (logout, "AutoCreate overflow");
		  logwrite (1, 14);
		  errexit (15, __FILE__, __LINE__);
       }
       autonum++;
	}
      newname[strlen (newname) - 4] = 0;
    }
	}
  if (usingshablon == 0)
      memcpy (&tdefarea, &bcfg.defarea, szarea);
  mystrncpy (crarea->areaname, areaname, arealength);
  mystrncpy (crarea->areafp, newname, DirSize);
  crarea->type = 1;
  crarea->days = tdefarea.days;
  crarea->messages = tdefarea.messages;
  crarea->skipmsg = tdefarea.skipmsg;
  crarea->passthr = (short)((pers == 1) ? 0 : tdefarea.passthr);
  if (pers == 3)
    crarea->passthr = 1;
  crarea->dupes = ((pers == 1) ? 0 : tdefarea.dupes);
  crarea->group = tdefarea.group;
  crarea->linktype = tdefarea.linktype;
  crarea->numlinks = 0;
  crarea->links.chain = crarea->links.last = NULL;
  crarea->links.numelem = 0;
  crarea->delday = 0;
  taddr = bcfg.address.chain;
  while (taddr)
    {
      if (taddr->point || ((pers >= 2) ? mfnode.point : pktaddr.point))
	/*
	   {
	   if((taddr->zone==((pers>=2)?mfnode.zone:pktaddr.zone)) &&
	   (taddr->net==((pers>=2)?mfnode.net:pktaddr.net)) &&
	   (taddr->node==((pers>=2)?mfnode.node:pktaddr.node)))
	   break;
	   }
	 */
	{
	  if ((taddr->zone == pktaddr.zone) &&
	      (taddr->net == pktaddr.net) && (taddr->node == pktaddr.node))
	    break;
	}
      else if (taddr->zone == ((pers >= 2) ? mfnode.zone : pktaddr.zone))
	break;
      taddr = taddr->next;
    }
  if (taddr == NULL)
    taddr = bcfg.address.chain;
  memcpy (&(crarea->myaka), taddr, szmyaddr);
  if (pers == 0)
    {
//    if(!(mode&2048))
//     {
      addaddr (&(crarea->links), &pktaddr);
      crarea->numlinks = 1;
//     }
/*
    blink=bcfg.links.chain;
    while(blink)
     {
      if(cmpaddr(&pktaddr,&(blink->address))==0)
        if(bcfg.gric?(strichr(blink->group,crarea->group)==0):(strchr(blink->group,crarea->group)==0))
          crarea->group=blink->group[0];
      blink=blink->next;
     }
*/
      blink = bcfg.links.chain;
      while (blink)
	{
	  if (cmpaddr (&pktaddr, &(blink->address)))
	    {
	      if (blink->autoadd)
		{
		  if (wildcard (blink->crmask, crarea->areaname) == 0)
		    if (bcfg.
			gric ? (strichr (blink->group, crarea->group))
			: (strchr (blink->group, crarea->group)))
		      {
			if (addaddr (&(crarea->links), &(blink->address)))
			  crarea->numlinks++;
		      }
		}
	    }
	  else if (blink->group[0])
	    if (bcfg.
		gric ? (strichr (blink->group, crarea->group) ==
			0) : (strchr (blink->group, crarea->group) == 0))
	      crarea->group = blink->group[0];
	  blink = blink->next;
	}
    }
  if (pers >= 2)
    {
      if (addaddr (&(crarea->links), &ufnode))
	crarea->numlinks++;
      if (addaddr (&(crarea->links), &mfnode))
	crarea->numlinks++;
    }
  link = crarea->links.chain;
  while (link)
    {
      blink = bcfg.links.chain;
      while (blink)
	{
	  if (cmpaddr (link, &(blink->address)) == 0)
	    {
	      if (blink->rog[0])
		if (bcfg.
		    gric ? (strichr (blink->rog, crarea->group))
		    : (strchr (blink->rog, crarea->group)))
		  link->rdonly = 1;
	    }
	  blink = blink->next;
	}
      link = link->next;
    }
  anew = (struct areaindex *)myalloc (szareaindex, __FILE__, __LINE__);
  mystrncpy (anew->areaname, areaname, arealength);
  anew->areaoffs = lseek (areaset, 0, SEEK_END);
  anew->scanned = anew->type = 1;
  anew->toss = anew->sent = anew->dupes = 0;
  anew->descoffs = 0;
  anew->desclen = 0;
  anew->tossed = 0;
  lseek (areandx, 0, SEEK_END);
  wwrite (areandx, anew, szareaindex, __FILE__, __LINE__);
  flushbuf (areandx);
  wwrite (areaset, crarea, szarea, __FILE__, __LINE__);
  if (!(pers == 1))
    {
      link = crarea->links.chain;
      while (link)
	{
	  wwrite (areaset, link, szmyaddr, __FILE__, __LINE__);
	  link = link->next;
	}
    }
  numarea++;
  ndxlen += szareaindex;
  tlist = rlist;
  while (tlist->next)
    tlist = tlist->next;
  if (tlist->numlists == gran)
    {
      tlist->next =
	(struct alists *)myalloc ((sizeof (struct alists) << bcfg.grof),
				  __FILE__, __LINE__);
      tlist = tlist->next;
      tlist->alist =
	(struct areaindex *)myalloc ((szareaindex << bcfg.grof), __FILE__,
				     __LINE__);
      tlist->next = NULL;
      tlist->numlists = 0;
      carea = 0;
    }
  memcpy (&(tlist->alist[tlist->numlists]), anew, szareaindex);
  tlist->numlists++;
  // Участок записи аpии в текстовый файл конфигуpации
  if (pers != 2)
    {
      setf = mysopen (bcfg.creatfile, 1, __FILE__, __LINE__);
      if (setf == -1)
	setf =
	  (short)sopen (bcfg.creatfile, O_RDWR | O_BINARY | O_CREAT,
			SH_DENYWR, S_IRWXU | S_IRWXG | S_IRWXO);
      writearea (setf, crarea, NULL, 1);
#ifdef __DOS__
//    _dos_getftime(setf,&(unsigned short)date,&(unsigned short)time);
      _dos_getftime (setf, &date, &time); // ???
#else
      _dos_getftime (setf, &date, &time); // ???
#endif
/*    fyear=(short)(((date&0xfe00)>>9)+1980);
    fmonth=(short)((date&0x1e0)>>5);
    fday=(short)(date&0x1f);*/
      cclose (&setf, __FILE__, __LINE__);
    }
  else
    writearea (prttemp, crarea, NULL, 1);
  // Участок записи аpии в текстовый файл конфигуpации
  if (bcfg.edlist[0] && (!crarea->passthr || bcfg.showall)
      && (!bcfg.echoonly || (crarea->type == 1)))
    {
      if ((edlist =
	   (short)sopen (bcfg.edlist, O_RDWR | O_BINARY, SH_DENYWR)) == -1)
	{
	  ccprintf ("\r\nWARNING! Can't open AreaList %s\r\n", bcfg.edlist);
	  edlist = 0;
	}
      else
	{
	  lseek (edlist, 0, SEEK_END);
	  temp = bcfg.shablon;
	  temp2 = temp;
	  while (temp && *temp)
	    {
	      while (*temp2 && (*temp2 != '@'))
		temp2++;
	      wwrite (edlist, temp, (unsigned short)(temp2 - temp), __FILE__,
		      __LINE__);
	      temp2++;
	      switch (toupper (*temp2))
		{
		case 'K':
		  switch (crarea->type)
		    {
		    case 0:
		      mywrite (edlist, "NetArea  ", __FILE__, __LINE__);
		      break;
		    case 1:
		      mywrite (edlist, "EchoArea ", __FILE__, __LINE__);
		      break;
		    default:
		      mywrite (edlist, "LocalArea", __FILE__, __LINE__);
		      break;
		    }
		  break;
		case 'T':
		  mywrite (edlist, crarea->areaname, __FILE__, __LINE__);
		  break;
		case 'P':
		  mywrite (edlist, crarea->areafp, __FILE__, __LINE__);
		  break;
		case 'Y':
		  if (crarea->type && crarea->type < 10)
		    mywrite (edlist, "-$", __FILE__, __LINE__);
		  break;
		case 'G':
		  sprintf (logout, "%c", crarea->group);
		  mywrite (edlist, logout, __FILE__, __LINE__);
		  break;
		case 'D':
		  mywrite (edlist, "\"", __FILE__, __LINE__);
		  mywrite (edlist, bcfg.areadesc, __FILE__, __LINE__);
		  mywrite (edlist, "\"", __FILE__, __LINE__);
		  break;
		case 'O':
		  mywrite (edlist, "\"", __FILE__, __LINE__);
		  if (bcfg.areadesc[0])
		    mywrite (edlist, bcfg.areadesc, __FILE__, __LINE__);
		  else
		    mywrite (edlist, crarea->areaname, __FILE__, __LINE__);
		  mywrite (edlist, "\"", __FILE__, __LINE__);
		  break;
		case 'A':
		  sprintf (logout, "%u:%u/%u.%u", crarea->myaka.zone,
			   crarea->myaka.net, crarea->myaka.node,
			   crarea->myaka.point);
		  mywrite (edlist, logout, __FILE__, __LINE__);
		  break;
		default:
		  temp2--;
		  break;
		}
	      temp2++;
	      temp = temp2;
	    }
	  mywrite (edlist, "\r\n", __FILE__, __LINE__);
	  cclose (&edlist, __FILE__, __LINE__);
	}
    }
  switch (pers)
    {
    case 0:
      if (mode & 2048)
	sprintf (logout, "Echo Area %s created from BadArea",
		 crarea->areaname);
      else
	sprintf (logout, "Echo Area %s created by node %u:%u/%u.%u",
		 crarea->areaname, pktaddr.zone, pktaddr.net, pktaddr.node,
		 pktaddr.point);
      break;
    case 1:
      sprintf (logout, "Echo Area %s created as personal area",
	       crarea->areaname);
      break;
    case 2:
    case 3:
      sprintf (logout, "Echo Area %s created by Echo Manager",
	       crarea->areaname);
      break;
    }
  mystrncpy (newname, logout, BufSize);
  if (bcfg.loglevel)
    logwrite (1, 1);
  if (pers != 1)
    {
      if ((crtrep =
	   (short)sopen (crtreprt, O_RDWR | O_BINARY, SH_DENYWR)) == -1)
	if ((crtrep =
	     (short)sopen (crtreprt, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR,
			   S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
	  {
	    mystrncpy (errname, crtreprt, DirSize);
	    errexit (2, __FILE__, __LINE__);
	  }
      lseek (crtrep, 0, SEEK_END);
      mywrite (crtrep, newname, __FILE__, __LINE__);
      mywrite (crtrep, "\r\n", __FILE__, __LINE__);
      cclose (&crtrep, __FILE__, __LINE__);
    }
}

void writearea (short handle, struct area *ttarea, char *descr, short type)	// 1 - create, 2 - change
{
  unsigned short i, j, w1, w2, cr = 0;
  struct myaddr *link = NULL, tsnd;
  char *temp = NULL, crlf;
  for (i = 0; i < strlen (ttarea->areaname); i++)
    if (!isspace (ttarea->areaname[i]))
      goto goodnam2;
  return;
goodnam2:
  if (type == 1)
    {
      lseek (handle, -1L, SEEK_END);
      rread (handle, &crlf, 1, __FILE__, __LINE__);
      while (crlf == 0x1a)
	{
	  lseek (handle, -2L, SEEK_CUR);
	  rread (handle, &crlf, 1, __FILE__, __LINE__);
	}
      if (crlf == '\r' || crlf == '\n')
	cr = 1;
      if (!cr)
	mywrite (handle, "\r\n", __FILE__, __LINE__);
      sprintf (logout, "EchoArea   %s %s -$", strupr (ttarea->areaname),
	       ttarea->areafp);
      mywrite (handle, logout, __FILE__, __LINE__);
    }
  else
    lseek (handle, 0, SEEK_END);
  if (ttarea->days)
    {
      sprintf (logout, " -$d%u", ttarea->days);
      mywrite (handle, logout, __FILE__, __LINE__);
    }
  if (ttarea->messages)
    {
      sprintf (logout, " -$m%u", ttarea->messages);
      mywrite (handle, logout, __FILE__, __LINE__);
    }
  if (ttarea->skipmsg)
    {
      sprintf (logout, " -$s%u", ttarea->skipmsg);
      mywrite (handle, logout, __FILE__, __LINE__);
    }
  if ((ttarea->dupes != bcfg.defarea.dupes) || (ttarea->killd_modified))
    {
      if (ttarea->killd_modified)
      {
	sprintf (logout, " -$b%c%u", (ttarea->killd) == 1 ? 'k' : 'n',
		 ttarea->dupes);
      mywrite (handle, logout, __FILE__, __LINE__);
		}
      else if (ttarea->dupes)
      {
	sprintf (logout, " -$b%u", ttarea->dupes);
      mywrite (handle, logout, __FILE__, __LINE__);
      }
    }
  if (ttarea->passthr)
    {
      sprintf (logout, " -0");
      mywrite (handle, logout, __FILE__, __LINE__);
    }
  if (ttarea->linktype && (ttarea->linktype != (bcfg.linktype + 1)))
    {
      sprintf (logout, " -$l%u", ttarea->linktype);
      mywrite (handle, logout, __FILE__, __LINE__);
    }
  if (ttarea->saveci)
    {
      sprintf (logout, " -$@");
      mywrite (handle, logout, __FILE__, __LINE__);
    }
  sprintf (logout, " -$g%c", ttarea->group);
  mywrite (handle, logout, __FILE__, __LINE__);
  if (descr)
    {
      sprintf (logout, " -$n\"%s\"", descr);
      mywrite (handle, logout, __FILE__, __LINE__);
    }
  sprintf (logout, " -p%u:%u/%u.%u",
	   ttarea->myaka.zone, ttarea->myaka.net, ttarea->myaka.node,
	   ttarea->myaka.point);
  if (!(ttarea->myaka.point))
    {
      temp = strrchr (logout, '.');
      *temp = 0;
    }
  mywrite (handle, logout, __FILE__, __LINE__);
  // сортировка
  memcpy (&defaddr, &(ttarea->myaka), szmyaddr);
  if (ttarea->links.numelem)
    {
      for (i = 0; i < ttarea->links.numelem - 1; i++)
	{
	  link = ttarea->links.chain;
	  for (j = 0; j < ttarea->links.numelem - i - 1; j++)
	    {
	      w1 = getweight (link);
	      w2 = getweight (link->next);
	      if (w2 < w1)
		swapaddr (link, link->next);
	      else if (w2 == w1)
		if (cmpaddr (link, link->next) > 0)
		  swapaddr (link, link->next);
	      link = link->next;
	    }
	}
    }
  link = ttarea->links.chain;
  memcpy (&tsnd, &defaddr, szmyaddr);
  while (link)
    {
      i = 1;
      if (tsnd.zone != link->zone)
	sprintf (logout, " %s%s%s%u:%u/%u.%u",
		 (link->rdonly | link->passive) ? "-" : "",
		 link->rdonly ? "x" : "", link->passive ? "y" : "",
		 link->zone, link->net, link->node, link->point);
      else if (tsnd.net != link->net)
	sprintf (logout, " %s%s%s%u/%u.%u",
		 (link->rdonly | link->passive) ? "-" : "",
		 link->rdonly ? "x" : "", link->passive ? "y" : "", link->net,
		 link->node, link->point);
      else if (tsnd.node != link->node)
	sprintf (logout, " %s%s%s%u.%u",
		 (link->rdonly | link->passive) ? "-" : "",
		 link->rdonly ? "x" : "", link->passive ? "y" : "",
		 link->node, link->point);
      else
	{
	  sprintf (logout, " %s%s%s.%u",
		   (link->rdonly | link->passive) ? "-" : "",
		   link->rdonly ? "x" : "", link->passive ? "y" : "",
		   link->point);
	  i = 0;
	}
      if (link->point == 0 && i)
	{
	  temp = strchr (logout, '.');
	  *temp = 0;
	}
      mywrite (handle, logout, __FILE__, __LINE__);
      memcpy (&tsnd, link, szmyaddr);
      link = link->next;
    }
  if (type == 1)
    mywrite (handle, "\r\n", __FILE__, __LINE__);
  deladdr (&(ttarea->links));
}
