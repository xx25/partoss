// MaxiM: _dos_getftime memicmp

#include "partoss.h"
#include "globext.h"
#include "globfunc.h"

#include "partpost.h"
#include "lowlevel.h"
#include "morfiles.h"
#include "errors.h"
#include "template.h"
#include "times.h"
#include "partsqd.h"
#include "buftosqd.h"
#include "buftomsg.h"
#include "chains.h"
#include "control.h"

short poster (short type)
{
  short i, j, makemess = 0, netmail, numkeys = 9, day, numflags =
    13, tfile, cfile;
  short istear, isorig, oldboth, waspost = 0;
  unsigned short fmax2, fday, fmonth, fyear;
#if defined(__BORLANDC__) || (defined(__WATCOMC__) && defined(__386__))
  unsigned tdate, ttime;
#else
  unsigned short tdate, ttime;
#endif
  // unsigned short fhour,fmin,fsec;
  char msgid[9], tear[81], orig[81], *temp =
    NULL, bfile[DirSize + 1], *tstring = NULL, hfile[DirSize + 1], sa[2];
  struct namechain schain;
  struct addrchain achain;
  struct sysname tname, *pname = NULL;
  struct myaddr tsnd, *taddr = NULL;
  struct kludge *tkl = NULL, *ttkl = NULL;
  if ((type ? (bcfg.post[0]) : (bcfg.reptmpl[0])) == 0)
    return -1;
  addhome (hfile, type ? bcfg.post : bcfg.reptmpl);
  packset = mysopen (hfile, 0, __FILE__, __LINE__);
  sftime = time (NULL);
  mylocaltime (&sftime, &tmt);
  if (type)
    {
      if (!forsed)
	{
#ifdef __DOS__
//      _dos_getftime(packset,&((unsigned)tdate),&((unsigned)ttime));
	  _dos_getftime (packset, &tdate, &ttime);
#else
	  _dos_getftime (packset, &tdate, &ttime);
#endif
	  fyear = (unsigned short)(((tdate & 0xfe00) >> 9) /*+1980 */ );
	  fmonth = (unsigned short)((tdate & 0x1e0) >> 5);
	  fday = (unsigned short)(tdate & 0x1f);
	  if (fyear == (tmt.tm_year - 80) && fmonth == tmt.tm_mon + 1
	      && fday == tmt.tm_mday)
	    {
	      cclose (&packset, __FILE__, __LINE__);
	      return 0;
	    }
	}
      if (alog == 0 && mode & 18)
	{
	  mustlog = -1;
     mystrncpy (echologt, bcfg.workdir, DirSize);
	  mystrncat (echologt, (char *)"echolog.$$$", DirSize, DirSize);
	  if ((alog =
	       (short)sopen (echologt, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR,
			     S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
	    {
	      mystrncpy (errname, echologt, DirSize);
	      errexit (2, __FILE__, __LINE__);
	    }
	  chsize (alog, 0);
	  lseek (alog, 0, SEEK_SET);
	}
    }
  bufpkt.subj = bufpkt.toname = bufpkt.fromname = NULL;
  mystrncpy (confile, type ? bcfg.post : bcfg.reptmpl, DirSize);
  lineno[0] = 1;
  endinput[0] = 0;
  while (!endinput[0])
    {
      readblock (packset, 0);
      endblock[0] = 0;
      do
	{
	  getstring (0);
	  gettoken (0);
	  if (*token != ';')
	    {
	      for (i = 0; i < numkeys; i++)
		if (memicmp (token, keys[i], strlen (keys[i])) == 0)
		  break;
	      switch (i)
		{
		default:
		  tokencpy (logout, BufSize);
		  if (strlen (logout))
		    ccprintf ("Incorrect keyword %s in %s (line %d)\r\n",
			      logout, confile, lineno[0]);
		  break;

		case 0:
		  if (type)
		    {
		      schain.chain = schain.last = NULL;
		      achain.chain = achain.last = NULL;
		      schain.numelem = achain.numelem = 0;
		      gettoken (0);
		      if (strnicmp (token, "Daily", 5) == 0)
			makemess = 1;
		      else
			{
			  if (forsed == 2)
			    {
			      makemess = 0;
			      goto goodday;
			    }
			  if (strnicmp (token, "Monthly", 7) == 0)
			    {
			      while (!endstring[0])
				{
				  gettoken (0);
				  day = (short)atoi (token);
				  if (day == tmt.tm_mday)
				    {
				      makemess = 1;
				      goto goodday;
				    }
				}
			    }
			  else
			    {
			      if (strnicmp (token, "Weekly", 6) == 0)
				{
				  while (!endstring[0])
				    {
				      gettoken (0);
				      if (isdigit (*token))
					day = (short)atoi (token);
				      else
					for (j = 0; j < 7; j++)
					  if (strnicmp (token, days[j], 3) ==
					      0)
					    {
					      day = j;
					      break;
					    }
				      day %= 7;
				      if (day == tmt.tm_wday)
					{
					  makemess = 1;
					  goto goodday;
					}
				    }
				}
			      else
				makemess = 0;
			    }
			}
		    }
		goodday:
		  break;

		case 1:
		  if (type == 0)
		    {
		      schain.chain = schain.last = NULL;
		      achain.chain = achain.last = NULL;
		      schain.numelem = achain.numelem = 0;
		      makemess = 1;
		    }
		  if (makemess)
		    {
		      memset (&bufpkt, 0, szpackmess);
		      memset (oldarea, 0, arealength);
		      bufpkt.flags = 0x100;
		      bufpkt.packtype = 2;
		      mystrncpy (tstrtime, asctime (&tmt), 39);
		      bufpkt.timefrom = bufpkt.timeto = strtime (tstrtime);
		      converttime (tstrtime);
		      mystrncpy (bufpkt.datetime, ftstime, 19);
		      gettoken (0);
		      tokencpy (logout, BufSize);
		      if (setarea (logout, 0))
			makemess = 0;
		      netmail = !(newarea->type);
		      istear = isorig = 0;
		    }
		  break;

		case 2:
		  if (makemess)
		    {
		      gettoken (0);
		      bufpkt.fromname =
			(char *)myalloc (36, __FILE__, __LINE__);
		      tokencpy (bufpkt.fromname, 35);
		      pfromlen = toklen;
		      gettoken (0);
		      tokencpy (logout, BufSize);
		      parseaddr (logout, &node, (short)strlen (logout));
		      if (node.zone)
			{
			  bufpkt.fromzone = node.zone;
			  bufpkt.fromnet = node.net;
			  bufpkt.fromnode = node.node;
			  bufpkt.frompoint = node.point;
			}
		    }
		  break;

		case 3:
		  if (makemess)
		    {
		      gettoken (0);
		      bufpkt.toname =
			(char *)myalloc (36, __FILE__, __LINE__);
		      if (!netmail)
			{
			  tokencpy (bufpkt.toname, 35);
			  ptolen = toklen;
			}
		      else
			{
			  tokencpy (tname.name, 35);
			  addname (&schain, &tname);
			  gettoken (0);
			  tokencpy (logout, BufSize);
			  parseaddr (logout, &tsnd, (short)strlen (logout));
			  if (tsnd.zone)
			    addaddr (&achain, &tsnd);
			}
		    }
		  break;

		case 4:
		  if (makemess)
		    {
		      gettoken (0);
		      bufpkt.subj = (char *)myalloc (72, __FILE__, __LINE__);
		      memset (bufpkt.subj, 0, 72);
		      tokencpy (bufpkt.subj, 71);
		      psubjlen = toklen;
		      trans (bufpkt.subj, 71);
		    }
		  break;

		case 5:
		  if (makemess)
		    {
		      if (netmail)
			{
			  do
			    {
			      gettoken (0);
			      for (j = 0; j < numflags; j++)
				if (strnicmp (token, flags[j], toklen) == 0)
				  break;
			      switch (j)
				{
				case 0:
				  bufpkt.flags |= 1;
				  break;
				case 1:
				  bufpkt.flags |= 2;
				  break;
				case 2:
				  bufpkt.flags |= 0x10;
				  break;
				case 3:
				  bufpkt.flags |= 0x80;
				  break;
				case 4:
				  bufpkt.flags |= 0x200;
				  break;
				case 5:
				  addflags ("DIR");
				  break;
				case 6:
				  bufpkt.flags |= 0x800;
				  break;
				case 7:
				  bufpkt.flags |= 0x1000;
				  break;
				case 8:
				  bufpkt.flags |= 0x4000;
				  break;
				case 9:
				  bufpkt.flags |= 0x8000;
				  break;
				case 10:
				  addflags ("IMM");
				  break;
				case 11:
				  addflags ("KFS");
				  break;
				case 12:
				  addflags ("TFS");
				  break;
				}
			    }
			  while (!endstring[0]);
			}
		    }
		  break;

		case 6:
		  if (makemess)
		    {
		      gettoken (0);
		      tokencpy (tear, 80);
		      trans (tear, 80);
		      istear = 1;
		    }
		  break;

		case 7:
		  if (makemess)
		    {
		      gettoken (0);
		      if (*(token - 1) == '"')
			tokencpy (orig, 80);
		      else
			{
			  mystrncpy (orig, token,
				     (short)(maxstr[0] - (token - ::string)));
			  temp = strchr (orig, '\r');
			  if (temp)
			    *temp = 0;
			  temp = strchr (orig, '\n');
			  if (temp)
			    *temp = 0;
			}
		      trans (orig, 80);
		      isorig = 1;
		    }
		  break;

		case 8:
		  oldboth = both;
		  both = 0;
		  if (makemess)
		    {
		      gettoken (0);
		      tokencpy (logout, BufSize);
		      addhome (hfile, logout);
		      mystrncpy (bfile, hfile, DirSize);
		      tfile =
			(short)sopen (hfile, O_RDONLY | O_BINARY, SH_DENYWR);
		      if (tfile != -1)
			{
			  waspost = 1;
			  logprintf ("Post message to area %s",
				   newarea->areaname);
			  logwrite (1, 4);
			  logprintf ("Message's Subj is \"%s\"",
				   bufpkt.subj);
			  logwrite (1, 6);
			  if (!netmail)
			    {
			      times = sftime + nummsg;
			      nummsg++;
			      hexascii (times, strtimes);
			      mystrncpy (msgid, strtimes, 8);
			      msgid[8] = 0;
			      pckludge =
				(struct kludge *)myalloc (szkludge, __FILE__,
							  __LINE__);
			      logprintf ("\1MSGID: %u:%u/%u.%u %s",
				       bufpkt.fromzone, bufpkt.fromnet,
				       bufpkt.fromnode, bufpkt.frompoint,
				       msgid);
			      pckludge->str =
				(char *)myalloc ((strlen (logout) + 1),
						 __FILE__, __LINE__);
			      mystrncpy (pckludge->str, logout,
					 (short)strlen (logout));
			      pckludge->left = 0;
			      pckludge->next = NULL;
			      pkludnum = 1;
			      pkludlen = (short)(strlen (logout) + 1);
			      lkludlen = lkludnum = 0;
			    }
			  tail =
			    (char *)myalloc (BufSize + 1, __FILE__, __LINE__);
			  if (istear)
			    sprintf (tail, "\r--- %s\r", tear);
			  else
			    sprintf (tail, "\r--- ParToss %s\r", version);
			  if (isorig || !netmail)
			    {
			      if (bufpkt.frompoint)
				logprintf (
					 " * Origin: %s (%u:%u/%u.%u)\r",
					 isorig ? orig : bcfg.origin,
					 bufpkt.fromzone, bufpkt.fromnet,
					 bufpkt.fromnode, bufpkt.frompoint);
			      else
				logprintf (" * Origin: %s (%u:%u/%u)\r",
					 isorig ? orig : bcfg.origin,
					 bufpkt.fromzone, bufpkt.fromnet,
					 bufpkt.fromnode);
			      mystrncat (tail, logout, BufSize, BufSize);
			    }
			  addorig = 1;
			  pbigmess = 1;
			  arealen = 0;
			  tstring = ::string;
			  if (!netmail)
			    {
			      if (type)
				tempsqd = templat (0, tfile);
			      else
				{
				  cfile =
				    (short)sopen (crtreprt,
						  O_RDONLY | O_BINARY,
						  SH_DENYWR);
				  if (cfile != -1)
				    {
				      tempsqd = templat (cfile, tfile);
				      cclose (&cfile, __FILE__, __LINE__);
				    }
				  else
				    tempsqd = templat (0, tfile);
				}
			      pmsglen = ptextlen = filelength (tempsqd);
			      pmsglen += pkludlen;
			      pcmsglen = pmsglen;
			      chsize (temppkt, 0);
			      lseek (temppkt, 0, SEEK_SET);
			      if (!bufpkt.tozone)
				bufpkt.tozone = bufpkt.fromzone;
			      if (!bufpkt.tonet)
				bufpkt.tonet = bufpkt.fromnet;
			      if (!bufpkt.tonode)
				bufpkt.tonode = bufpkt.fromnode;
			      if (!bufpkt.topoint)
				bufpkt.topoint = bufpkt.frompoint;
			      wwrite (temppkt, bufpkt.toname,
				      (unsigned short)(ptolen + 1), __FILE__,
				      __LINE__);
			      wwrite (temppkt, bufpkt.fromname,
				      (unsigned short)(pfromlen + 1),
				      __FILE__, __LINE__);
			      wwrite (temppkt, bufpkt.subj,
				      (unsigned short)(psubjlen + 1),
				      __FILE__, __LINE__);
			      lseek (tempsqd, 0, SEEK_SET);
			      while ((fmax2 =
				      (short)rreadz (tempsqd, sqdbuf, buflen,
						    __FILE__, __LINE__)) != 0)
				wwrite (temppkt, sqdbuf, fmax2, __FILE__,
					__LINE__);
			      cclose (&tempsqd, __FILE__, __LINE__);
			      unlink (pttmpl);
			      lseek (temppkt, 0, SEEK_SET);
			      posting = 1;
			      pcreate = 1;
			      buftosqd (newarea, nindex, 1);
			      pcreate = 0;
			      posting = 0;
			    }
			  else
			    {
			      if (achain.chain)
				{
				  taddr = achain.chain;
				  pname = schain.chain;
				  for (i = 0; i < schain.numelem; i++)
				    {
				      bufpkt.tozone = taddr->zone;
				      bufpkt.tonet = taddr->net;
				      bufpkt.tonode = taddr->node;
				      bufpkt.topoint = taddr->point;
				      mystrncpy (bufpkt.toname, pname->name,
						 35);
				      bufmess = bufpkt;
				      mckludge = pckludge;
				      mkludlen = pkludlen;
				      mbigmess = 1;
				      mtolen = ptolen;
				      mfromlen = pfromlen;
				      msubjlen = psubjlen;
				      mtextlen = ptextlen;
				      if (type)
					tempmsg = templat (0, tfile);
				      else
					{
					  cfile =
					    (short)sopen (crtreprt,
							  O_RDONLY | O_BINARY,
							  SH_DENYWR);
					  if (cfile != -1)
					    {
					      tempmsg =
						templat (cfile, tfile);
					      cclose (&cfile, __FILE__,
						      __LINE__);
					    }
					  else
					    tempmsg = templat (0, tfile);
					}
				      pmsglen = ptextlen =
					filelength (tempmsg);
				      pmsglen += pkludlen - 1;
				      lseek (tempmsg, 0, SEEK_SET);
				      needout = 1;
				      buftomsg (4);
				      mckludge = NULL;
				      taddr = taddr->next;
				      pname = pname->next;
				      cclose (&tempmsg, __FILE__, __LINE__);
				      unlink (pttmpl);
				    }
				  delname (&schain);
				  deladdr (&achain);
				}
			    }
			  ::string = tstring;
			  tstring = NULL;
			  addorig = 0;
			  delctrl (1);
			  myfree ((void **)&tail, __FILE__, __LINE__);
			  cclose (&tfile, __FILE__, __LINE__);
			  if (!endstring[0])
			    {
			      gettoken (0);
			      if (memicmp (token, "Kill", 4) == 0)
				unlink (bfile);
			    }
			}
		      else
			{
			  logprintf ("POST failed: file %s not found",
				   hfile);
			  logwrite (1, 6);
			}
		      closesqd (newarea, 1);
		      makemess = netmail = 0;
		      if (bufpkt.subj)
			myfree ((void **)&bufpkt.subj, __FILE__, __LINE__);
		      if (bufpkt.toname)
			myfree ((void **)&bufpkt.toname, __FILE__, __LINE__);
		      if (bufpkt.fromname)
			myfree ((void **)&bufpkt.fromname, __FILE__,
				__LINE__);
		    }
		  both = oldboth;
		  break;
		}
	    }
	  lineno[0] += numcr[0];
	}
      while (!endblock[0]);
    }
  tkl = pckludge;
  while (tkl)
    {
      ttkl = tkl->next;
      myfree ((void **)&tkl->str, __FILE__, __LINE__);
      myfree ((void **)&tkl, __FILE__, __LINE__);
      tkl = ttkl;
    }
  pckludge = NULL;
  if (type)
    {
/*
    fyear=tmt->tm_year-80;
    fmonth=tmt->tm_mon+1;
    fday=tmt->tm_mday;
    fhour=tmt->tm_hour;
    fmin=tmt->tm_min;
    fsec=tmt->tm_sec/2;
    tdate=fyear<<9;
    tdate|=fmonth<<5;
    tdate|=fday;
    ttime=fhour<<11;
    ttime|=fmin<<5;
    ttime|=fsec;
*/
      cclose (&packset, __FILE__, __LINE__);
      addhome (hfile, type ? bcfg.post : bcfg.reptmpl);
      if ((packset =
	   (short)sopen (hfile, O_RDWR | O_BINARY, SH_DENYWR)) != -1)
	{
	  if (rread (packset, sa, 2, __FILE__, __LINE__))
	    {
	      lseek (packset, 0, SEEK_SET);
	      wwrite (packset, sa, 2, __FILE__, __LINE__);
	    }
//    _dos_setftime(packset,tdate,ttime);
	}
    }
  cclose (&packset, __FILE__, __LINE__);
  return waspost;
}

void addflags (char *flag)
{
  if (pckludge == NULL)
    {
      pckludge = (struct kludge *)myalloc (szkludge, __FILE__, __LINE__);
      pckludge->left = 0;
      pckludge->next = NULL;
      pckludge->str = (char *)myalloc (81, __FILE__, __LINE__);
      mystrncpy (pckludge->str, "\1FLAGS ", 9);
      mystrncat (pckludge->str, flag, 5, 80);
      pkludnum = 1;
      pkludlen = 10;
    }
  else
    {
      mystrncat (pckludge->str, " ", 2, 80);
      mystrncat (pckludge->str, flag, 5, 80);
      pkludlen += 4;
    }
}

void trans (char *string, short length)
{
  short tret;
  long tretl;
  if (strchr (string, '@') != NULL)
    {
//    if((ttempl=sopen("keytempl.$$$",O_RDWR|O_BINARY|O_CREAT,SH_DENYWR,S_IRWXU|S_IRWXG|S_IRWXO))==-1)
//      return;
      // errexit(2,__FILE__,__LINE__);
      chsize (ttempl, 0);
      lseek (ttempl, 0, SEEK_SET);
      mywrite (ttempl, string, __FILE__, __LINE__);
      tret = templat (0, ttempl);
      tretl = filelength (tret);
      if (tretl > (long)length)
	tretl = (long)length;
//    cclose(&ttempl,__FILE__,__LINE__);
//    unlink("keytempl.$$$");
      chsize (ttempl, 0);
      lseek (ttempl, 0, SEEK_SET);
      memset (string, 0, length + 1);
      rread (tret, string, (short)tretl, __FILE__, __LINE__);
      cclose (&tret, __FILE__, __LINE__);
      unlink (pttmpl);
    }
}
