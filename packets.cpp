// MaxiM: find_t

#include "partoss.h"
#include "globext.h"

#include "packets.h"
#include "lowlevel.h"
#include "morfiles.h"
#include "errors.h"
#include "headers.h"

void createpkts (void)
{
  if (pkts == NULL)
    {
      logprintf ("Processing outbound directory %s", bcfg.workout);
      logwrite (1, 11);
      searchpkts (bcfg.workout, OUT_MASK);
      searchpkts (bcfg.workout, PKT_MASK);
      logprintf ("Processing outbound directory %s", bcfg.outbound);
      logwrite (1, 11);
      searchpkts (outbound, OUT_MASK);
      searchpkts (outbound, PKT_MASK);
    }
}

void killpkts (void)
{
  int mgood;
  char tmpname[(DirSize + 1)];
  struct find_t fblk;
#if defined (__linux__) || defined (__FreeBSD__)
// memset(tmpname,0,DirSize+1);
#endif
  mystrncpy (tmpname, bcfg.workout, DirSize);
  mystrncat (tmpname, (char *)OUT_MASK, 7, DirSize);
  mgood = _dos_findfirst (tmpname, findattr, &fblk);
  while (mgood == 0)
    {
      mystrncpy (tmpname, bcfg.workout, DirSize);
      mystrncat (tmpname, fblk.name, 16, DirSize);
      if (fblk.size == 0)
	unlink (tmpname);
      mgood = _dos_findnext (&fblk);
    }
  _dos_findclose (&fblk);/***ash***/
}

void delpkts (void)
{
  struct packet *ttpack = NULL;
  tpack = pkts;
  while (tpack)
    {
      if (tpack->opened)
	{
	  cclose (&tpack->handle, __FILE__, __LINE__);
	  tpack->opened = 0;
	}
      ttpack = tpack->next;
      myfree ((void **)&tpack->name, __FILE__, __LINE__);
      myfree ((void **)&tpack, __FILE__, __LINE__);
      tpack = ttpack;
    }
  pkts = NULL;
}

void newtpack (void)
{
  if (pkts == NULL)
    {
      pkts = (struct packet *)myalloc (szpacket, __FILE__, __LINE__);
      tpack = pkts;
    }
  else
    {
      tpack = pkts;
      while (tpack->next)
	tpack = tpack->next;
      tpack->next = (struct packet *)myalloc (szpacket, __FILE__, __LINE__);
      tpack = tpack->next;
    }
  memset (tpack->password, 0, 8);
  tpack->next = NULL;
}

void addtpack (struct myaddr *glink)
{
  char ttname[DirSize + 1];
  struct myaddr *taddr = NULL;
  struct link *blink = NULL;
  struct packet *ttpack = NULL /*,*tttpack=NULL */ ;
  short exist;
  newtpack ();
  tpack->name = (char *)myalloc ((DirSize + 1), __FILE__, __LINE__);
  tpack->touched = tpack->opened = tpack->filled = tpack->sent = tpack->file =
    0;
  numpack++;
  memcpy (&(tpack->outaddr), &node, szmyaddr);
  blink = bcfg.links.chain;
  while (blink)
    {
      if (cmpaddr (&blink->address, &tpack->outaddr) == 0)
	break;
      blink = blink->next;
    }
  if (blink)
    if ((blink->mask) & (1L << 20))
      memcpy (tpack->password, blink->password, 8);
  if (newarea->type)
    memcpy (&(tpack->fromaddr), glink, szmyaddr);
  else
    {
      if (tpack->outaddr.point)
	{
	  taddr = bcfg.address.chain;
	  while (taddr)
	    {
	      if (taddr->zone == tpack->outaddr.zone &&
		  taddr->net == tpack->outaddr.net &&
		  taddr->node == tpack->outaddr.node && taddr->point == 0)
		goto lnkfound;
	      taddr = taddr->next;
	    }
	}
      else
	{
	  taddr = bcfg.address.chain;
	  while (taddr)
	    {
	      if (taddr->zone == tpack->outaddr.zone &&
		  taddr->net == tpack->outaddr.net && taddr->point == 0)
		goto lnkfound;
	      taddr = taddr->next;
	    }
	  if (taddr == NULL)
	    {
	      taddr = bcfg.address.chain;
	      while (taddr)
		{
		  if (taddr->zone == tpack->outaddr.zone &&
		      taddr->net == tpack->outaddr.net &&
		      taddr->node == tpack->outaddr.node && taddr->point)
		    goto lnkfound;
		  taddr = taddr->next;
		}
	      if (taddr == NULL)
		{
		  taddr = bcfg.address.chain;
		  while (taddr)
		    {
		      if (taddr->zone == tpack->outaddr.zone
			  && taddr->point == 0)
			goto lnkfound;
		      taddr = taddr->next;
		    }
		}
	    }
	}
    lnkfound:
      if (taddr == NULL)
	taddr = bcfg.address.chain;
      memcpy (&(tpack->fromaddr), taddr, szmyaddr);
    }
  exist = 1;
  while (exist)
    {
      sftime = time (NULL);
      times = sftime + numpack;
      numpack++;
      hexascii (times, strtimes);
      mystrncpy (ttname, bcfg.workout, DirSize);
      mystrncat (ttname, strtimes, 10, DirSize);
      mystrncat (ttname, ".out", 7, DirSize);
      ttpack = pkts;
      while (ttpack)
	{
	  if (strnicmp (ttname, ttpack->name, strlen (ttname) - 4) == 0)
	    break;
	  ttpack = ttpack->next;
	}
      if (!ttpack)
	exist = 0;
    }
  mystrncpy (tpack->name, ttname, DirSize);
}

void searchpkts (char *path, char *ext)
{
  struct myaddr from, to, *taddr = NULL;
  short handle, i;
  int mgood;
  long pktsize;
  struct link *blink = NULL;
  char tmpname[(DirSize + 1)], currname[(DirSize + 1)];
  struct find_t fblk;
  struct packet *tmpkt = NULL;
  mystrncpy (tmpname, path, DirSize);
  mystrncat (tmpname, ext, 7, DirSize);
  mgood = _dos_findfirst (tmpname, findattr, &fblk);
  while (mgood == 0)
    {
      mystrncpy (tmpname, path, DirSize);
      mystrncat (tmpname, fblk.name, 16, DirSize);
      tmpkt = pkts;
      while (tmpkt)
	{
	  if (strncmp (tmpkt->name, tmpname, strlen (tmpname) - 4) == 0)
	    {
	      _dos_findclose (&fblk);
	      return;
	    }
	  tmpkt = tmpkt->next;
	}
      if (fblk.size)
	{
	  if ((handle =
	       (short)sopen (tmpname, O_RDONLY | O_BINARY, SH_DENYWR)) == -1)
	    {
	      mystrncpy (errname, tmpname, DirSize);
	      errexit (2, __FILE__, __LINE__);
	    }
	  mystrncpy (currname, path, DirSize);
	  if (currname[0] && currname[strlen (currname) - 1] != DIRSEP[0])
	    mystrncat (currname, DIRSEP, 3, DirSize);
	  mystrncat (currname, fblk.name, DirSize, DirSize);
	  logprintf ("--- Adding of %s", currname);
	  logwrite (1, 11);
	  readhead (handle, &from, &to);
/*
      short netmail;
      char *temp;
      rread(handle,buffer,1024,__FILE__,__LINE__);
      temp=memstr(buffer,"AREA:",1024);
      if(temp)
        netmail=0;
      else
        netmail=1;
*/
	  cclose (&handle, __FILE__, __LINE__);
	  taddr = bcfg.address.chain;
	  for (i = 0; i < bcfg.numaddr; i++)
	    {
	      if (cmpaddr (taddr, &from) == 0)
		break;
	      taddr = taddr->next;
	    }
	  if (i < bcfg.numaddr)
	    {
	      newtpack ();
	      numpack++;
	      memset (tpack, 0, szpacket);
	      tpack->name =
		(char *)myalloc ((DirSize + 1), __FILE__, __LINE__);
	      memcpy (&tpack->fromaddr, &from, szmyaddr);
	      memcpy (&tpack->outaddr, &to, szmyaddr);
	      tpack->touched = 1;
//      tpack->netmail=netmail;
	      mystrncpy (tpack->name, tmpname, DirSize);
	      pktsize = bcfg.pktsize;
	      blink = bcfg.links.chain;
	      while (blink)
		{
		  if (cmpaddr (&(blink->address), &to) == 0)
		    break;
		  blink = blink->next;
		}
	      if (blink && blink->pktsize)
		pktsize = blink->pktsize;
	      if (pktsize && (fblk.size >= pktsize))
		tpack->filled = 1;
	    }
	}
      else
	unlink (tmpname);
      mgood = _dos_findnext (&fblk);
    }
  _dos_findclose (&fblk);/***ash***/
}
