// MaxiM: strlwr

#include "partoss.h"
#include "globext.h"

#include "sqdtobuf.h"
#include "lowlevel.h"
#include "morfiles.h"
#include "control.h"
#include "times.h"
#include "crc32.h"

short sqdtobuf (struct area *ttarea, struct sqifile *tindex, long number)
{
  long firstpos, tpos;
  unsigned short j, k, scanned, fmax2, i, i1, validdt;
  char *temp = NULL, tdt[20];
  sftime = time (NULL);
  mylocaltime (&sftime, &tmt);
  if (number >= (ttarea->curindex + bufsqi) || number < ttarea->curindex)
    {
      ttarea->curindex = (number / bufsqi) * bufsqi;
      lseek (ttarea->sqd.sqi, ttarea->curindex * 12, SEEK_SET);
      rread (ttarea->sqd.sqi, tindex, (unsigned short)(bufsqi * 12), __FILE__,
	     __LINE__);
    }
  firstpos = tindex[(unsigned)(number - ttarea->curindex)].offset;
  curhash = tindex[(unsigned)(number - ttarea->curindex)].hash;
  if (firstpos == 0)
    return -2;
  if (mode & 128)
    rehwm = (short)(tindex[(unsigned)(number - ttarea->curindex)].umsgid);
  lseek (ttarea->sqd.sqd, firstpos, SEEK_SET);
  rread (ttarea->sqd.sqd, &head, 266, __FILE__, __LINE__);
  if (head.ident != 0xAFAE4453L)
    {
      logprintf (
	       "??? Area %s is damaged or index file is corrupted (# %u)",
	       ttarea->areaname, number);
      if (logfileok)
	logwrite (1, 1);
      ccprintf ("\r\n%s\r\n", logout);
      badlog (ttarea);
      return -1;
    }
  scanned = (short)(head.flags2 & 1);
  local = (short)(head.flags & 0x100);
  if ((((ttarea->numlinks > 1) || local) && (!scanned || rescan))
      || mode & 6272)
    {
      memset (&bufsqd, 0, szpackmess);
      bufsqd.flags = head.flags;
      if (!(mode & 128))
	bufsqd.flags &= 0x7493;
      flags2 = head.flags2;
      memcpy (bufsqd.datetime, head.datetime, 20);
      memcpy (tdt, head.datetime, 20);

      validdt = 0;
      if (bufsqd.datetime[0])
	{
	  for (i = 0; i < 19; i++)
	    {
	      if (bufsqd.datetime[i] == 0)
		goto gooddt;
	      if (!isspace (bufsqd.datetime[i]))
		{
		  validdt = 1;
		  goto gooddt;
		}
	    }
	}
    gooddt:
      if (validdt)
	bufsqd.timefrom = strtime (bufsqd.datetime);
      else
	{
	  mystrncpy (tstrtime, asctime (&tmt), 39);
	  bufsqd.timefrom = strtime (tstrtime);
	  converttime (tstrtime);
	  memcpy (bufsqd.datetime, ftstime, 20);
	}
      mystrncpy (tstrtime, asctime (&tmt), 39);
      bufsqd.timeto = strtime (tstrtime);

      i1 = (short)strlen (bufsqd.datetime);
      if (i1 < 19)
	{
	  for (i = i1; i < 19; i++)
	    bufsqd.datetime[i] = ' ';
	  bufsqd.datetime[19] = 0;
	}
      bufsqd.timefrom = head.timefrom;
      bufsqd.timeto = head.timeto;
      if (bufsqd.timeto == 0)
	{
	  sftime = time (NULL);
	  mylocaltime (&sftime, &tmt);
	  mystrncpy (tstrtime, asctime (&tmt), 39);
	  bufsqd.timeto = strtime (tstrtime);
	}
      if (nowpurge)
	{
	  pfrom.zone = head.fromzone;
	  pfrom.net = head.fromnet;
	  pfrom.node = head.fromnode;
	  pfrom.point = head.frompoint;
	  pto.zone = head.tozone;
	  pto.net = head.tonet;
	  pto.node = head.tonode;
	  pto.point = head.topoint;
	}
      bufsqd.fromzone = head.fromzone;
      bufsqd.fromnet = head.fromnet;
      bufsqd.fromnode = head.fromnode;
      bufsqd.frompoint = head.frompoint;
      if (!pktaddr.zone)
	pktaddr.zone = head.fromzone;
      if (!pktaddr.net)
	pktaddr.net = head.fromnet;
      if (!pktaddr.node)
	pktaddr.node = head.fromnode;
      if (!pktaddr.point)
	pktaddr.point = head.frompoint;
      bufsqd.tozone = ttarea->myaka.zone;
      bufsqd.tonet = ttarea->myaka.net;
      bufsqd.tonode = ttarea->myaka.node;
      bufsqd.fromname = head.fromname;
      sfromlen = strlen (bufsqd.fromname);
      bufsqd.toname = head.toname;
      stolen = strlen (bufsqd.toname);
      bufsqd.subj = head.subj;
      ssubjlen = strlen (bufsqd.subj);
      smsglen = head.msglength - 239;
      if (smsglen < 0)
	smsglen = 0;
/********************************************************************
      if(!validdt)
        smsglen+=20;
********************************************************************/
      gheadclen = (short)(head.clen);
      if (smsglen < buflen)
	{
	  fmax2 =
	    (unsigned short)rreadz (ttarea->sqd.sqd, sqdbuf,
				   (unsigned short)(smsglen + 1), __FILE__,
				   __LINE__);
	  if (gheadclen && (strlen (sqdbuf) < (gheadclen - 1)))
	    gheadclen = (short)(strlen (sqdbuf) + 1);
	  getctrl (sqdbuf, (short)smsglen, 2);
	  if (gheadgarb)
	    {
	      bufsqd.text = sqdbuf + skludlen;
	      stextlen = smsglen - skludlen + 1;
	    }
	  else
	    {
	      bufsqd.text = sqdbuf + skludlen + 1;
	      stextlen = smsglen - skludlen;
	    }
	  sbigmess = 0;
	  temp = locseenby (bufsqd.text);
	  if (temp)
	    scmsglen = temp - bufsqd.text + skludlen + (skludlen ? 1 : 0);
	  else
	    scmsglen = smsglen;
//      if(!(mode&2176))
	  parsesnb (temp, 2);
	}
      else
	{
	  sbigmess = 1;
	  soffset = firstpos + 266;
	  lseek (ttarea->sqd.sqd, soffset, SEEK_SET);
	  endmsg = 0;
	  chsize (tempsqd, 0);
	  lseek (tempsqd, 0, SEEK_SET);
	  wwrite (tempsqd, bufsqd.toname, (unsigned short)(stolen + 1),
		  __FILE__, __LINE__);
	  wwrite (tempsqd, bufsqd.fromname, (unsigned short)(sfromlen + 1),
		  __FILE__, __LINE__);
	  wwrite (tempsqd, bufsqd.subj, (unsigned short)(ssubjlen + 1),
		  __FILE__, __LINE__);
	  fmax2 =
	    (unsigned short)rreadz (ttarea->sqd.sqd, sqdbuf, buflen, __FILE__,
				   __LINE__);
	  if (gheadclen && (strlen (sqdbuf) < (gheadclen - 1)))
	    gheadclen = (short)(strlen (sqdbuf) + 1);
	  getctrl (sqdbuf, fmax2, 2);
//      getctrl(sqdbuf,(fmax2<head.clen)?(fmax2-1):head.clen,2);
	  smsglen = fmax2;
	  if (gheadgarb)
	    wwrite (tempsqd, sqdbuf + skludlen,
		    (unsigned short)(fmax2 - skludlen), __FILE__, __LINE__);
	  else
	    wwrite (tempsqd, sqdbuf + skludlen + 1,
		    (unsigned short)(fmax2 - skludlen - 1), __FILE__,
		    __LINE__);
	  soffset += fmax2;
	  while (!endmsg)
	    {
	      lseek (ttarea->sqd.sqd, soffset, SEEK_SET);
	      fmax2 =
		(unsigned short)rreadz (ttarea->sqd.sqd, sqdbuf, buflen,
				       __FILE__, __LINE__);
	      if (fmax2)
		{
		  temp = (char *)memchr (sqdbuf, '\0', fmax2);
		  if (temp || fmax2 < buflen)
		    {
		      endmsg = 1;
		      // short read without a NUL: take all of it
		      j = (short)(temp ? (temp - sqdbuf) : fmax2);
		    }
		  else
		    {
		      for (k = fmax2;
			   k > 0 && (sqdbuf[k] != '\r')
			   && (sqdbuf[k] != '\n'); k--) ;
		      if (k > 0)
			j = k;
		      else
			j = fmax2;
		    }
		  smsglen += j;
		  wwrite (tempsqd, sqdbuf, j, __FILE__, __LINE__);
		  soffset += j;
		}
	      else
		endmsg = 1;
	    }
	  tpos = smsglen - skludlen - 1;
	  flushbuf (tempsqd);
	  if (tpos > buflen)
	    tpos = buflen;
	  lseek (tempsqd, -tpos, SEEK_END);
	  rreadz (tempsqd, sqdbuf, buflen, __FILE__, __LINE__);
	  temp = locseenby (sqdbuf, (short)(tpos < buflen));
	  if (temp)
	    scmsglen = smsglen - (buflen - (temp - sqdbuf));	// +skludlen;
	  else
	    scmsglen = smsglen;
//      if(!(mode&2176))
	  parsesnb (temp, 2);
	  stextlen = smsglen - skludlen - 1;
	  scurpos = fmax2;
	}
      if (!(rescan || (mode & 128)))
	{
	  if ((local || (mode & 2048)) && bcfg.maxdupes)
	    {
	      // smsgcrc32=crc32block(tdt,20);
	      // smsgcrc32=crc32block(bufsqd.fromname,(short)sfromlen,smsgcrc32);
	      smsgcrc32 = crc32block (bufsqd.fromname, (short)sfromlen);
	      smsgcrc32 =
		crc32block (bufsqd.toname, (short)stolen, smsgcrc32);
	      smsgcrc32 =
		crc32block (bufsqd.subj, (short)ssubjlen, smsgcrc32);
	      if (curmsgid[0])
		smsgcrc32 = crc32block (strlwr (curmsgid), 8, smsgcrc32);
	      if (curreply[0])
		smsgcrc32 = crc32block (strlwr (curreply), 8, smsgcrc32);
	      if ((!curmsgid[0]) && (!curreply[0]))
		smsgcrc32 = crc32block (tdt, 20, smsgcrc32);
	    }
	}
      if (!(mode & 128))
	{
	  if (head.flags & 0x100)
	    head.flags |= 8;
	  flags2 = head.flags2 = 1;
	  lseek (ttarea->sqd.sqd, firstpos, SEEK_SET);
	  wwrite (ttarea->sqd.sqd, &head, 266, __FILE__, __LINE__);
	  flushbuf (ttarea->sqd.sqd);
	}
    }
  buftemps = &bufsqd;
  return scanned;
}

short sqhtobuf (long number)
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
  if (firstpos == 0)
    return -2;
  if (mode & 128)
    rehwm = (short)(nindex[(unsigned)(number - newarea->curindex)].umsgid);
  lseek (newarea->sqd.sqd, firstpos, SEEK_SET);
  rread (newarea->sqd.sqd, &head, 266, __FILE__, __LINE__);
  if (head.ident != 0xAFAE4453L)
    {
      logprintf (
	       "??? Area %s is damaged or index file is corrupted (# %u)",
	       newarea->areaname, number);
      if (logfileok)
	logwrite (1, 1);
      ccprintf ("\r\n%s\r\n", logout);
      badlog (newarea);
      return -1;
    }
  if (head.timeto == 0)
    {
      sftime = time (NULL);
      mylocaltime (&sftime, &tmt);
      mystrncpy (tstrtime, asctime (&tmt), 39);
      head.timeto = strtime (tstrtime);
    }
  return 0;
}
