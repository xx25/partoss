// MaxiM: strlwr

#include "partoss.h"
#include "globext.h"

#include "pkttobuf.h"
#include "lowlevel.h"
#include "morfiles.h"
#include "times.h"
#include "control.h"
#include "crc32.h"

// Returns 1 if the message header runs past the data read (damaged packet)
short pkttobuf (void)
{
  unsigned short i, j, fmax2, validdt, dtlen;
  long tpos;
  char *temp = NULL, tdt[22];
  sftime = time (NULL);
  mylocaltime (&sftime, &tmt);
  memset (&bufpkt, 0, szpackmess);
  memcpy (&bufpkt, pktbuf + pcurpos, 34);
  bufpkt.flags &= 0xfeff;
  if (bcfg.strip2fts)
    bufpkt.flags &= 0x7413;
  if (bcfg.stripattr)
    bufpkt.flags &= 0xfdfd;
  if (bcfg.stripext)
    bufpkt.flags &= 0xf8ff;
  if (bcfg.killadd)
    bufpkt.flags |= 0x80;
  mflags = bufpkt.flags;
  validdt = 0;
  memcpy (tdt, bufpkt.datetime, 21);
  dtlen = (short)strlen (bufpkt.datetime);
  if (dtlen == 20)		// "dd mon 1xx  hh:mm:ss:" bug in packet
    for (i = 8; i <= 20; i++)
      bufpkt.datetime[i - 1] = bufpkt.datetime[i];
  if (bufpkt.datetime[0])
    {
      for (i = 0; i < 19; i++)
	if (bufpkt.datetime[i] == 0)
	  goto gooddt;
      if (!isspace (bufpkt.datetime[i]))
	{
	  validdt = 1;
	  goto gooddt;
	}
    }
gooddt:
  if (validdt)
    bufpkt.timefrom = strtime (bufpkt.datetime);
  else
    {
      mystrncpy (tstrtime, asctime (&tmt), 39);
      bufpkt.timefrom = strtime (tstrtime);
      if (converttime (bufpkt.datetime) == 0)
	converttime (tstrtime);
      memcpy (bufpkt.datetime, ftstime, 20);
    }
  mystrncpy (tstrtime, asctime (&tmt), 39);
  bufpkt.timeto = strtime (tstrtime);
//  pcurpos+=34;
  // the header starts at pcurpos (after any garbage tosspkt skipped)
  pcurpos = (unsigned short)(pcurpos + 15 + dtlen);
  j = (short)strlen (bufpkt.datetime);
  if (j < 19)
    {
      for (i = j; i < 19; i++)
	bufpkt.datetime[i] = ' ';
      bufpkt.datetime[19] = 0;
      pcurpos -= (unsigned short)(19 - j);
      while (pcurpos < fmax && *(pktbuf + pcurpos) == 0)
	pcurpos++;
    }
  // pktbuf ends with two NULs after fmax (rreadz), so each strlen stops
  // there at the latest; a name running into them means the header is cut
  if (pcurpos >= fmax)
    return 1;
  bufpkt.toname = pktbuf + pcurpos;
  ptolen = strlen (bufpkt.toname);
  pcurpos += (unsigned short)ptolen;
  pcurpos++;
  if (pcurpos >= fmax)
    return 1;
  bufpkt.fromname = pktbuf + pcurpos;
  pfromlen = strlen (bufpkt.fromname);
  pcurpos += (unsigned short)pfromlen;
  pcurpos++;
  if (pcurpos >= fmax)
    return 1;
  bufpkt.subj = pktbuf + pcurpos;
  psubjlen = strlen (bufpkt.subj);
  pcurpos += (unsigned short)psubjlen;
  pcurpos++;
  if (pcurpos > fmax)
    return 1;
  mystrncpy (gltoname, bufpkt.toname, 35);
  mystrncpy (glfromname, bufpkt.fromname, 35);
  mystrncpy (glsubj, bufpkt.subj, 71);
  temp = (char *)memchr (pktbuf + pcurpos, '\0', fmax - pcurpos);
  if (temp)
    {
      j = (short)(temp - pktbuf - pcurpos);
      getctrl (pktbuf + pcurpos, j, 1);
      if (bcfg.maxdupes)
	{
	  msgcrc32 = crc32block (bufpkt.fromname, (short)pfromlen);
	  msgcrc32 = crc32block (bufpkt.toname, (short)ptolen, msgcrc32);
	  msgcrc32 = crc32block (bufpkt.subj, (short)psubjlen, msgcrc32);
	  if (curmsgid[0])
	    msgcrc32 = crc32block (strlwr (curmsgid), 8, msgcrc32);
	  if (curreply[0])
	    msgcrc32 = crc32block (strlwr (curreply), 8, msgcrc32);
	  if ((!curmsgid[0]) && (!curreply[0]))
	    msgcrc32 = crc32block (tdt, 20, msgcrc32);
	}
      bufpkt.text = pktbuf + pcurpos + pkludlen - arealen + arealenold;
      if (!netmail)
	{
	  temp = locseenby (bufpkt.text);
	  if (temp)
	    pcmsglen = temp - bufpkt.text + pkludlen;
	  else
	    pcmsglen = j;
	  if ((mode & 2 || rescan || bcfg.lookpath)
	      && (newarea->numlinks > 1))
	    parsesnb (temp, 1);
	}
      else
	{
	  pcmsglen = j;
	  logprintf (
		   "Netmail message from %s, %u:%u/%u.%u to %s, %u:%u/%u.%u about \"%s\"",
		   bufpkt.fromname, bufpkt.fromzone, bufpkt.fromnet,
		   bufpkt.fromnode, bufpkt.frompoint, bufpkt.toname,
		   bufpkt.tozone, bufpkt.tonet, bufpkt.tonode, bufpkt.topoint,
		   bufpkt.subj);
	  logwrite (1, 3);
	  if (!quiet)
	    ccprintf ("%s\r\n", logout);
	}
      pbigmess = 0;
      pmsglen = j + arealen - arealenold;
      ptextlen = pmsglen - pkludlen;
      pcurpos += j;
      pcurpos++;
    }
  else
    {
      pbigmess = 1;
      endmsg = 0;
      chsize (temppkt, 0);
      lseek (temppkt, 0, SEEK_SET);
      wwrite (temppkt, bufpkt.toname, (unsigned short)(ptolen + 1), __FILE__,
	      __LINE__);
      wwrite (temppkt, bufpkt.fromname, (unsigned short)(pfromlen + 1),
	      __FILE__, __LINE__);
      wwrite (temppkt, bufpkt.subj, (unsigned short)(psubjlen + 1), __FILE__,
	      __LINE__);
      getctrl (pktbuf + pcurpos, (short)(fmax - pcurpos), 1);
      if (bcfg.maxdupes)
	{
	  msgcrc32 = crc32block (bufpkt.fromname, (short)pfromlen);
	  msgcrc32 = crc32block (bufpkt.toname, (short)ptolen, msgcrc32);
	  msgcrc32 = crc32block (bufpkt.subj, (short)psubjlen, msgcrc32);
	  if (curmsgid[0])
	    msgcrc32 = crc32block (strlwr (curmsgid), 8, msgcrc32);
	  if (curreply[0])
	    msgcrc32 = crc32block (strlwr (curreply), 8, msgcrc32);
	  if ((!curmsgid[0]) && (!curreply[0]))
	    msgcrc32 = crc32block (tdt, 20, msgcrc32);
	}
      pmsglen = fmax - pcurpos;
      if (pkludlen > pmsglen)
	pkludlen = (unsigned short)pmsglen;
      wwrite (temppkt, pktbuf + pcurpos + pkludlen,
	      (unsigned short)(fmax - pcurpos - pkludlen), __FILE__,
	      __LINE__);
      while (!endmsg)
	{
	  fmax2 =
	    (unsigned short)rreadz (pkt, pktbuf, buflen, __FILE__, __LINE__);
	  temp = (char *)memchr (pktbuf, '\0', fmax2);
	  if (temp || fmax2 < buflen)
	    {
	      endmsg = 1;
	      if (temp)
		j = (short)(temp - pktbuf);
	      else
		j = fmax2;
	    }
	  else
	    j = fmax2;
	  pmsglen += j;
	  wwrite (temppkt, pktbuf, j, __FILE__, __LINE__);
	  poffset += j;
	}
      tpos = pmsglen - pkludlen - 1;
      poffset++;
      lseek (pkt, poffset, SEEK_SET);
      flushbuf (temppkt);
      if (!netmail)
	{
	  if (tpos > buflen)
	    tpos = buflen;
	  if (tpos < 0)
	    tpos = 0;
	  lseek (temppkt, -tpos, SEEK_END);
	  rreadz (temppkt, pktbuf, (unsigned short)(tpos), __FILE__, __LINE__);
	  temp = locseenby (pktbuf);
	  if (temp && ((temp - pktbuf) < tpos))
	    pcmsglen = pmsglen - (tpos - (temp - pktbuf));
	  else
	    pcmsglen = pmsglen;
	  if ((mode & 2 || rescan || bcfg.lookpath)
	      && (newarea->numlinks > 1))
	    parsesnb (temp, 1);
//  if(mode&2 || rescan)
//    if(newarea->numlinks!=1)
//      parsesnb(temp,1);
	}
      else
	pcmsglen = pmsglen;
      ptextlen = pmsglen - pkludlen - 1;
//    pcurpos=fmax-2;
      pcurpos = fmax;
    }
  poffset += pcurpos;
  if (bufpkt.fromzone == 0)
    bufpkt.fromzone = bcfg.address.chain->zone;
  if (bufpkt.tozone == 0)
    bufpkt.tozone = bufpkt.fromzone;
  node.zone = bufpkt.tozone;
  node.net = bufpkt.tonet;
  node.node = bufpkt.tonode;
  node.point = bufpkt.topoint;
  pkludlen -= numlf;
  pmsglen -= numlf;
  pcmsglen -= numlf;
  return 0;
}
