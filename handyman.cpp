// MaxiM: ported, not changed

#include "partoss.h"
#include "globext.h"

#include "handyman.h"
#include "lowlevel.h"
#include "partserv.h"

void handyman (short argc, char **argv)
{
  short i = 0, j = 0;
  struct myaddr *taddr = NULL, tnode;
  struct link *blink = NULL;
  if (argv[1][4] == 'N' || argv[1][4] == 'n')
    noreport = 1;
  else
    noreport = 0;
  memcpy (&defaddr, bcfg.address.chain, szmyaddr);
  if (argc < 3)
    return;
  parseaddr (argv[2], &tnode, (short)(strlen (argv[2])));
  memset (&bufmess, 0, szpackmess);
  bufmess.fromname = (char *)myalloc (36, __FILE__, __LINE__);
  bufmess.toname = (char *)myalloc (36, __FILE__, __LINE__);
  bufmess.subj = (char *)myalloc (72, __FILE__, __LINE__);
  chsize (temppkt, 0);
  lseek (temppkt, 0, SEEK_SET);
  for (i = 3; i < argc; i++)
    {
      logprintf ("%s%s", (i == 3) ? "" : " ", argv[i]);
      for (j = 0; j < strlen (logout); j++)
	if (logout[j] == bcfg.guard)
	  logout[j] = '%';
      mywrite (temppkt, logout, __FILE__, __LINE__);
    }
  mywrite (temppkt, "\r\n", __FILE__, __LINE__);
  blink = bcfg.links.chain;
  while (blink)
    {
      if (cmpaddr (&tnode, &(blink->address)) == 0)
	{
	  if (blink->name[0])
	    mystrncpy (bufmess.fromname, blink->name, 35);
	  else
	    mystrncpy (bufmess.fromname, "SysOp", 35);
	  mfromlen = strlen (bufmess.fromname);
	  mystrncpy (bufmess.toname, "Parma Tosser", 35);
	  mtolen = strlen (bufmess.toname);
	  mystrncpy (bufmess.subj, "Dummy password", 71);
	  msubjlen = strlen (bufmess.subj);
	  memcpy (&mfnode, &(blink->address), szmyaddr);
	  bufmess.fromzone = mfnode.zone;
	  bufmess.fromnet = mfnode.net;
	  bufmess.fromnode = mfnode.node;
	  bufmess.frompoint = mfnode.point;
	  taddr = bcfg.address.chain;
	  while (taddr)
	    {
	      if (taddr->point || mfnode.point)
		{
		  if ((taddr->zone == mfnode.zone)
		      && (taddr->net == mfnode.net)
		      && (taddr->node == mfnode.node))
		    break;
		}
	      else if (taddr->zone == mfnode.zone)
		break;
	      taddr = taddr->next;
	    }
	  if (taddr == NULL)
	    taddr = bcfg.address.chain;
	  memcpy (&node, taddr, szmyaddr);
	  bufmess.tozone = taddr->zone;
	  bufmess.tonet = taddr->net;
	  bufmess.tonode = taddr->node;
	  bufmess.topoint = taddr->point;
	  doserv ();
	  goto goodwork;
	}
      blink = blink->next;
    }
  logprintf ("!!! Link %u:%u/%u.%u not found !!!", tnode.zone,
	   tnode.net, tnode.node, tnode.point);
  logwrite (1, 2);
  if (!quiet)
    ccprintf ("\r\n%s\r\n", logout);
goodwork:
  myfree ((void **)&bufmess.subj, __FILE__, __LINE__);
  myfree ((void **)&bufmess.toname, __FILE__, __LINE__);
  myfree ((void **)&bufmess.fromname, __FILE__, __LINE__);
}
