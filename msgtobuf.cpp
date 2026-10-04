// MaxiM: Ported. Not changed.

#include "partoss.h"
#include "globext.h"

#include "msgtobuf.h"
#include "lowlevel.h"
#include "morfiles.h"
#include "control.h"

short msgtobuf (char *fname)
{
  short msg, noempty = 0, i, j;
  unsigned fmax1, fmax2;
  char *temp = NULL;
  struct myaddr *taddr;
  msg = mysopen (fname, 0, __FILE__, __LINE__);
  memset (&bufmess, 0, szpackmess);
  fmax1 =
    rread (msg, &bufmsg, (unsigned short)(szmessage - szchar), __FILE__,
	   __LINE__);
  bufmess.fromname = bufmsg.fromname;
  mfromlen = strlen (bufmess.fromname);
  bufmess.toname = bufmsg.toname;
  mtolen = strlen (bufmess.toname);
  bufmess.subj = bufmsg.subj;
  msubjlen = strlen (bufmess.subj);
  memcpy (bufmess.datetime, bufmsg.datetime, 20);
  j = (short)strlen (bufmess.datetime);
  if (j < 19)
    {
      for (i = j; i < 19; i++)
	bufmess.datetime[i] = ' ';
      bufmess.datetime[19] = 0;
    }
  bufmess.fromnode = bufmsg.fromnode;
  bufmess.fromnet = bufmsg.fromnet;
  bufmess.tonode = bufmsg.tonode;
  bufmess.tonet = bufmsg.tonet;
  bufmess.flags = bufmsg.flags;
  mflags = bufmess.flags;
  fmax1 = rreadz (msg, sqdbuf, buflen, __FILE__, __LINE__);
  if (fmax1 < buflen)
    {
      sqdbuf[fmax1] = 0;
      getctrl (sqdbuf, (short)fmax1, 3);
      bufmess.text = sqdbuf + mkludlen;
      temp = bufmess.text;
      while (*temp && isspace (*temp))
	temp++;
      if (*temp)
	noempty = 1;
      mbigmess = 0;
      rmbigmess = 0;
      mmsglen = fmax1;
    }
  else
    {
      noempty = 1;
      mbigmess = 1;
      rmbigmess = 1;
      endmsg = 0;
      chsize (temppkt, 0);
      lseek (temppkt, 0, SEEK_SET);
//    wwrite(temppkt,&bufmess,34,__FILE__,__LINE__);
      wwrite (temppkt, bufmess.toname, (unsigned short)(mtolen + 1), __FILE__,
	      __LINE__);
      wwrite (temppkt, bufmess.fromname, (unsigned short)(mfromlen + 1),
	      __FILE__, __LINE__);
      wwrite (temppkt, bufmess.subj, (unsigned short)(msubjlen + 1), __FILE__,
	      __LINE__);
      getctrl (sqdbuf, (short)fmax1, 3);
      mmsglen = fmax1;
      wwrite (temppkt, sqdbuf + mkludlen, (unsigned short)(fmax1 - mkludlen),
	      __FILE__, __LINE__);
      while (!endmsg)
	{
	  fmax2 = rreadz (msg, sqdbuf, buflen, __FILE__, __LINE__);
	  if (fmax2 < buflen)
	    endmsg = 1;
	  mmsglen += fmax2;
	  wwrite (temppkt, sqdbuf, fmax2, __FILE__, __LINE__);
	}
      flushbuf (temppkt);
    }
  mtextlen = mmsglen - mkludlen - 1;
  if (mtextlen < 0)
    mtextlen = 0;
  if (bufmess.fromzone == 0)
    bufmess.fromzone = bcfg.address.chain->zone;
  if (bufmess.tozone == 0)
    bufmess.tozone = bufmess.fromzone;
  node.zone = bufmess.tozone;
  node.net = bufmess.tonet;
  node.node = bufmess.tonode;
  node.point = bufmess.topoint;
  mfnode.zone = bufmess.fromzone;
  mfnode.net = bufmess.fromnet;
  mfnode.node = bufmess.fromnode;
  mfnode.point = bufmess.frompoint;
  cclose (&msg, __FILE__, __LINE__);
  taddr = bcfg.address.chain;
  while (taddr)
    {
      if (cmpaddr (taddr, &node) == 0)
	return 0;
      taddr = taddr->next;
    }
  if (!noempty)
    return 0;
  if (mflags & 0x18e5el)
    return 0;
  else if (mflags & 0x80)
    return 2;
  else
    return 1;
}
