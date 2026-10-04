// MaxiM: Ported.

#include "partoss.h"
#include "globext.h"

#include "rebuild.h"
#include "lowlevel.h"
#include "morfiles.h"
#include "errors.h"
#include "partsqd.h"
#include "buftosqd.h"
#include "sqdtobuf.h"
#include "times.h"
#include "control.h"
#include "tossarcs.h"
#include "attach.h"
#include "crc32.h"

void rebuild (long aoffset, short type)
{
  lseek (areaset, aoffset, SEEK_SET);
  rread (areaset, newarea, szarea, __FILE__, __LINE__);
  newarea->links.chain = newarea->links.last = NULL;
  newarea->links.numelem = 0;
  if (newarea->type && (!newarea->passthr || bcfg.passpurge))
    {
      opensqd (newarea, nindex, 0, 0);
      if (!arealock)
  {
    newarea->links.chain = newarea->links.last = NULL;
    newarea->links.numelem = 0;
    if (newarea->sqd.sqd)
      {
        switch (type)
    {
    case 1:
      purgesqd ();
      break;
    case 2:
      fixsqd ();
      break;
    case 3:
      untoss ();
      break;
    }
      }
  }
    }
}

void purgesqd (void)
{
  char fulname[(DirSize + 1)], pname[(DirSize + 1)], iname[(DirSize + 1)],
    *bitmap = NULL;
  long maxmsg, i, newmess = 0, oldsize, newsize, sumdel = 0;
  /**/
   long firstmsg,lastread=1000000000L,lastread2;
   short sql;
  /**/
  unsigned long currtime;
  short needcopy, needwork, balloc;
  unsigned short diff;
  struct sqdfile tsqbuf;
  struct pointers firstf;
  posting = 1;
  balloc = 0;
  nowpurge = 1;
  mystrncpy (pname, newarea->areafp, DirSize);
  mystrncat (pname, "._qd", 5, DirSize);
  unlink (pname);
  mystrncpy (iname, newarea->areafp, DirSize);
  mystrncat (iname, "._qi", 5, DirSize);
  unlink (iname);
  oldsize = filelength (newarea->sqd.sqd) + filelength (newarea->sqd.sqi);
  lseek (newarea->sqd.sqd, 8, SEEK_SET);
  rread (newarea->sqd.sqd, &maxmsg, 4, __FILE__, __LINE__);
  /**/
   if(bcfg.purgelr)
   {
      lastread = maxmsg;
      mystrncpy(iname,newarea->areafp,DirSize);
      mystrncat(iname,".sql",5,DirSize);
      if((sql=(short)sopen(iname,O_RDWR|O_BINARY,SH_DENYWR,S_IRWXU|S_IRWXG|S_IRWXO))==-1)
         firstmsg=0;
      else
      {
         while(rread(sql, &lastread2, 4, __FILE__, __LINE__)==4)
         {
            if(lastread < lastread2)
            {
               lseek (sql, -4, SEEK_CUR);
               if (wwrite(sql, &lastread, 4, __FILE__, __LINE__) != 4)
                  lseek (sql, 4, SEEK_CUR);
            };
         };
         cclose(&sql,__FILE__,__LINE__);
      };
   };
  /**/
  if (oldsize > 256)
    needwork = 1;
  else
    needwork = 0;
  if (needwork)
    {
      needwork = 0;
      lseek (newarea->sqd.sqd, 112, SEEK_SET);
      rread (newarea->sqd.sqd, &firstf, 28, __FILE__, __LINE__);
      if (firstf.next)
  {
    needwork = 1;
    if (bcfg.analyse < 2)
      goto dowork;
    if (bcfg.analyse == 3)
      {
        while (firstf.next)
    {
      sumdel++;
      lseek (newarea->sqd.sqd, firstf.next, SEEK_SET);
      rread (newarea->sqd.sqd, &firstf, 28, __FILE__, __LINE__);
    }
      }
  }
      if (newarea->days)
  {
    if (bcfg.analyse)
      {
        if (bcfg.analyse > 1)
    {
      bitmap =
        (char *)myalloc ((unsigned)((maxmsg >> 3) + 1), __FILE__,
             __LINE__);
      balloc = 1;
    }
        for (i = 0; i < maxmsg; i++)
    {
      if (sqhtobuf (i) == -2)
        goto mnext;
      sftime = time (NULL);
      mylocaltime (&sftime, &tmt);
      mystrncpy (tstrtime, asctime (&tmt), 39);
      currtime = strtime (tstrtime);
      diff = diffdays (head.timeto, currtime);
      if (diff >= newarea->days)
        {
          needwork = 1;
          if (bcfg.analyse == 1)
      goto dowork;
          else
      {
        bitmap[(unsigned)(i >> 3)] &=
          (char)((0xfe << (i & 7)) & 0xff);
        if (bcfg.analyse == 3)
          sumdel++;
      }
        }
      else if (bcfg.analyse > 1)
        bitmap[(unsigned)(i >> 3)] |=
          (char)((1 << (i & 7)) & 0xff);
    mnext:
      ;
    }
      }
    else
      needwork = 1;
  }
    }
dowork:
  if (needwork && (bcfg.analyse == 3))
    //if(((sumdel*100)/maxmsg)<bcfg.delproc)
    if ((sumdel * 100) < (maxmsg * bcfg.delproc))
      needwork = 0;
  if (needwork)
    {
      memcpy (persarea, newarea, szarea);
      if ((persarea->sqd.sqd =
     (short)sopen (pname, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR,
       S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
  {
    mystrncpy (errname, pname, DirSize);
    errexit (2, __FILE__, __LINE__);
  }
      if ((persarea->sqd.sqi =
     (short)sopen (iname, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR,
       S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
  {
    mystrncpy (errname, iname, DirSize);
    errexit (2, __FILE__, __LINE__);
  }
      persarea->open = 1;
      lseek (newarea->sqd.sqd, 0, SEEK_SET);
      rread (newarea->sqd.sqd, &tsqbuf, 256, __FILE__, __LINE__);
      tsqbuf.nummsg = tsqbuf.highmsg = tsqbuf.first = tsqbuf.last =
  tsqbuf.firstf = tsqbuf.lastf = 0;
      tsqbuf.endf = 256;
      wwrite (persarea->sqd.sqd, &tsqbuf, 256, __FILE__, __LINE__);
      for (i = 0; i < maxmsg; i++)
  {
//      if((newarea->days==0) || (bcfg.analyse<2) || ((bitmap[i>>3])&(1<<(i<<7))))
    if ((newarea->days == 0) || (bcfg.analyse < 2)
        || ((bitmap[(unsigned)(i >> 3)]) & (1 << (i & 7))))
      {
        if (sqdtobuf (newarea, nindex, i) == -2)
    goto mnext2;
        if (newarea->days == 0)
    needcopy = 1;
        else
    {
      if (bcfg.analyse < 2)
        {
          sftime = time (NULL);
          mylocaltime (&sftime, &tmt);
          mystrncpy (tstrtime, asctime (&tmt), 39);
          currtime = strtime (tstrtime);
          diff = diffdays (bufsqd.timeto, currtime);
          if (diff < newarea->days)
      needcopy = 1;
          else
      needcopy = 0;
        }
      else
        needcopy = 1;
    }
        if (needcopy)
    {
      buftosqd (persarea, pindex, 2);
      newmess++;
    }
        delctrl (2);
      mnext2:
        ;
      }
  }
      if (balloc)
  myfree ((void **)&bitmap, __FILE__, __LINE__);
      closesqd (newarea, 0);
      newsize =
  filelength (persarea->sqd.sqd) + filelength (persarea->sqd.sqi);
      cclose (&persarea->sqd.sqd, __FILE__, __LINE__);
      cclose (&persarea->sqd.sqi, __FILE__, __LINE__);
      persarea->open = 0;
      if (newsize == 256)
  {
    mystrncpy (iname, newarea->areafp, DirSize);
    mystrncat (iname, ".sqd", 5, DirSize);
    unlink (iname);
    iname[strlen (iname) - 1] = 'i';
    unlink (iname);
    iname[strlen (iname) - 1] = 'l';
    unlink (iname);
    iname[strlen (iname) - 3] = '_';
    iname[strlen (iname) - 1] = 'd';
    unlink (iname);
    iname[strlen (iname) - 1] = 'i';
    unlink (iname);
  }
      else
  {
    mystrncpy (fulname, newarea->areafp, DirSize);
    mystrncat (fulname, ".sqd", 5, DirSize);
    if (rrename (pname, fulname))
      {
        mystrncpy (errname, pname, DirSize);
        errexit (13, __FILE__, __LINE__);
      }
    fulname[strlen (fulname) - 1] = 'i';
    if (rrename (iname, fulname))
      {
        mystrncpy (errname, iname, DirSize);
        errexit (13, __FILE__, __LINE__);
      }
  }
      if (maxmsg > newmess || oldsize > newsize)
  {
    globold += oldsize;
    globnew += newsize;
    if (oldsize < 1024)
      logprintf ("Purge %s: %ld -> %ld (%ldb -> %ldb, %d%%)",
         newarea->areaname, maxmsg, newmess, oldsize, newsize,
         (newsize * 100) / oldsize);
    else
      logprintf ("Purge %s: %ld -> %ld (%ldK -> %ldK, %d%%)",
         newarea->areaname, maxmsg, newmess, oldsize >> 10,
         newsize >> 10,
         /*(newsize*100)/oldsize */ newsize / (oldsize / 100));
    if (bcfg.loglevel)
      logwrite (1, 1);
    ccprintf ("%s\r\n", logout);
  }
    }
  else
    closesqd (newarea, 0);
  posting = 0;
  nowpurge = 0;
}

void fixsqd (void)
{
  /*
     struct myaddr *ttaddr=NULL,*taddr=NULL;
     struct link *blink=NULL;
     char *temp=NULL;
     soffset=256;
     memcpy(persarea,newarea,szarea);
     if((persarea->sqd.sqd=sopen(pname,O_RDWR|O_BINARY|O_CREAT,SH_DENYWR,S_IRWXU|S_IRWXG|S_IRWXO))==-1)
     {
     mystrncpy(errname,pname,DirSize);
     errexit(2,__FILE__,__LINE__);
     }
     if((persarea->sqd.sqi=sopen(iname,O_RDWR|O_BINARY|O_CREAT,SH_DENYWR,S_IRWXU|S_IRWXG|S_IRWXO))==-1)
     {
     mystrncpy(errname,iname,DirSize);
     errexit(2,__FILE__,__LINE__);
     }
     lseek(newarea->sqd.sqd,0,SEEK_SET);
     rread(newarea->sqd.sqd,&tsqbuf,256,__FILE__,__LINE__);
     tsqbuf.nummsg=tsqbuf.highmsg=tsqbuf.highwater=tsqbuf.first=tsqbuf.last=
     tsqbuf.firstf=tsqbuf.lastf=0;
     tsqbuf.endf=256;
     tsqbuf.uid=1;
     wwrite(persarea->sqd.sqd,&tsqbuf,256,__FILE__,__LINE__);
     while((fmax=rread(newarea->sqd.sqd,sqdbuf,buflen,__FILE__,__LINE__))>0)
     {
     if(fmax<szsqdhead)
     break;
     for(i=fmax-szsqdhead;*(pktbuf+i)!='S' || (*(pktbuf+i+1)!='D' ||
     (*(pktbuf+i+2)!='®') || (*(pktbuf+i+3)!='¯');i--);
     if(i)
     fmax=i;
     soffset+=fmax;
     lseek(newarea->sqd.sqd,soffset,SEEK_SET);
     scurpos=0;
     while((scurpos+szsqdhead)<fmax)
     {
     badfr=pctrlpos=0;
     sqdtobuf2();
     buftosqd(persarea,pindex,1);
     delctrl(1);
     }
     }
     closesqd(newarea,0);
     newsize=filelength(persarea->sqd.sqd)+filelength(persarea->sqd.sqi);
     cclose(&persarea->sqd.sqd,__FILE__,__LINE__);
     cclose(&persarea->sqd.sqi,__FILE__,__LINE__);
     mystrncpy(fulname,newarea->areafp,DirSize);
     mystrncat(fulname,".sqd",5,DirSize);
     if(rrename(pname,fulname))
     {
     mystrncpy(errname,pname,DirSize);
     errexit(13,__FILE__,__LINE__);
     }
     fulname[strlen(fulname)-1]='i';
     if(rrename(iname,fulname))
     {
     mystrncpy(errname,iname,DirSize);
     errexit(13,__FILE__,__LINE__);
     }
     }

     void sqdtobuf2(void)
     {
     unsigned short i,j,fmax2;
     long tpos;
     char *temp=NULL;
     sftime=time(NULL);
     memset(&bufsqd,0,szpackmess);
     memcpy(&bufsqd,sqdbuf+scurpos,szsqdhead);
     pcurpos+=szsqdhead;
     bufsqd.toname=sqdbuf+scurpos;
     stolen=strlen(bufsqd.toname);
     scurpos+=36;
     bufsqd.fromname=sqdbuf+scurpos;
     sfromlen=strlen(bufsqd.fromname);
     scurpos+=36;
     bufsqd.subj=sqdbuf+scurpos;
     ssubjlen=strlen(bufsqd.subj);
     pcurpos+=72;
     getctrl(sqdbuf+scurpos,buflen-scurpos,2);
     bufsqd.text=sqdbuf+scurpos+skludlen;
     temp=memchr(bufsqd.text,'\0',buflen-scurpos-skludlen);
     if(temp)
     {
     sbigmess=0;
     smsglen=j;
     stextlen=smsglen-skludlen;
     scurpos+=j;
     scurpos++;
     }
     else
     {
     sbigmess=1;
     endmsg=0;
     chsize(tempsqd,0);
     lseek(tempsqd,0,SEEK_SET);
     pmsglen=fmax-pcurpos;
     wwrite(temppkt,pktbuf+pcurpos+pkludlen,fmax-pcurpos-pkludlen,__FILE__,__LINE__);
     while(!endmsg)
     {
     fmax2=rread(pkt,pktbuf,buflen,__FILE__,__LINE__);
     temp=(char *)memchr(pktbuf,'\0',fmax2);
     if(temp || fmax2<buflen)
     {
     endmsg=1;
     if(temp)
     j=temp-pktbuf;
     else
     j=fmax2;
     }
     else
     j=fmax2;
     pmsglen+=j;
     wwrite(temppkt,pktbuf,j,__FILE__,__LINE__);
     poffset+=j;
     }
     tpos=pmsglen-pkludlen-1;
     poffset++;
     ptextlen=pmsglen-pkludlen-1;
     pcurpos=fmax-2;
     }
   */
}

void tossbad (void)
{
  long maxmsg, i /*,null=0 */ ;
  char tempsqdn[DirSize + 1], badd[DirSize + 1], badi[DirSize + 1];
/*  struct myaddr *ttaddr=NULL;*/
  mystrncpy (logout, "Toss from Bad Area", 20);
  logwrite (1, 4);
  setbadarea ();
  if (badlocked)
    {
      logprintf ("??? Tossing from Bad Area is impossible");
      logwrite (1, 4);
      return;
    }
  lseek (badmess->sqd.sqd, 8, SEEK_SET);
  rread (badmess->sqd.sqd, &maxmsg, 4, __FILE__, __LINE__);
  if (!maxmsg)
    {
      closesqd (badmess, 0);
      if (!bcfg.killdupes)
  closesqd (dupes, 0);
      mystrncpy (logout, "Bad Area is empty", 20);
      logwrite (1, 4);
      return;
    }
  wipearea = 0;
  nowpurge = 1;
  if (bcfg.createbad)
    create = bcfg.create = 1;
  chsize (temppkt, 0);
  lseek (temppkt, 0, SEEK_SET);
  mystrncpy (tempsqdn, bcfg.workdir, DirSize);
  mystrncat (tempsqdn, "tempsqd.$$$", 16, DirSize);
  if ((tempsqd =
       (short)sopen (tempsqdn, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR,
         S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
    {
      mystrncpy (errname, tempsqdn, DirSize);
      errexit (2, __FILE__, __LINE__);
    }
  memcpy (persarea, badmess, szarea - szlong);
  persarea->areaname[0]++;
  mystrncpy (badd, badmess->areafp, DirSize);
  mystrncat (badd, ".sqd", 7, DirSize);
  mystrncpy (badi, badd, DirSize);
  badi[strlen (badi) - 3] = '_';
  closesqd (badmess, 0);
  if (!bcfg.killdupes)
    closesqd (dupes, 0);
  if (rrename (badd, badi))
    {
      mystrncpy (errname, badd, DirSize);
      errexit (13, __FILE__, __LINE__);
    }
  badd[strlen (badd) - 1] = 'i';
  badi[strlen (badi) - 1] = 'i';
  if (rrename (badd, badi))
    {
      mystrncpy (errname, badd, DirSize);
      errexit (13, __FILE__, __LINE__);
    }
  badd[strlen (badd) - 1] = 'd';
  badd[strlen (badd) - 3] = '_';
  if ((persarea->sqd.sqd =
       (short)sopen (badd, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR,
         S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
    {
      mystrncpy (errname, badd, DirSize);
      errexit (2, __FILE__, __LINE__);
    }
  if ((persarea->sqd.sqi =
       (short)sopen (badi, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR,
         S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
    {
      mystrncpy (errname, badi, DirSize);
      errexit (2, __FILE__, __LINE__);
    }
  persarea->open = 1;
  setbadarea ();

  lseek (persarea->sqd.sqd, 8, SEEK_SET);
  rread (persarea->sqd.sqd, &maxmsg, 4, __FILE__, __LINE__);
  rread (persarea->sqd.sqi, pindex,
   (unsigned short)(((maxmsg < bufsqi) ? maxmsg : bufsqi) * 12),
   __FILE__, __LINE__);
  for (i = 0; i < maxmsg; i++)
    {
      isdupe = 0;
      pktaddr.zone = pktaddr.net = pktaddr.node = pktaddr.point = 0;
      if (sqdtobuf (persarea, pindex, i) == -2)
  goto mnext3;
      badarea = setarea (curarea, 0);
      if (badarea)
  {
    wipearea = 0;
    totbad++;
    if (badarea > 0 && (bcfg.locked == 4))
      {
        logprintf ("BackUp: Area %s is locked");
        logwrite (1, 3);
        backup (1);
      }
    else
      {
        if (badarea < 0)
    badtype = 2;
        else
    badtype = 5;
        if (badlocked)
    {
      logprintf ("BackUp: BadArea is locked");
      logwrite (1, 3);
      backup (1);
    }
        else
    buftosqd (badmess, bindex, 2);
      }
    wipearea = 1;
  }
      else
  {
    if (!isdupe)
      dupcheck (2);
    if (newarea->dupes && isdupe)
      {
        if (!bcfg.killdupes)
    {
      wipearea = 0;
      if (dupelocked)
        {
          logprintf ("BackUp: DupeArea is locked");
          logwrite (1, 3);
          backup (1);
        }
      else
        buftosqd (dupes, dindex, 2);
      wipearea = 1;
    }
      }
    else
      buftosqd (newarea, nindex, 2);
  }
/*
     {
      ttaddr=newarea->links.chain;
      while(ttaddr)
       {
        if(cmpaddr(ttaddr,&pktaddr)==0)
         {
          if(ttaddr->rdonly)
           {
            wipearea=0;
            totbad++;
            badtype=3;
            if(badlocked)
             {
              logprintf("BackUp: BadArea is locked");
              logwrite(1,3);
              backup(1);
             }
            else
              buftosqd(badmess,bindex,2);
            wipearea=1;
           }
          else
           {
            if(!isdupe)
              dupcheck(2);
            if(newarea->dupes && isdupe)
             {
              if(tlist)
                tlist->alist[carea].dupes++;
              totdupes++;
              if(!bcfg.killdupes)
               {
                wipearea=0;
                if(dupelocked)
                 {
                  logprintf("BackUp: DupeArea is locked");
                  logwrite(1,3);
                  backup(1);
                 }
                else
                  buftosqd(dupes,dindex,2);
                wipearea=1;
               }
             }
            else
              buftosqd(newarea,nindex,2);
           }
          break;
         }
        ttaddr=ttaddr->next;
       }
      if(ttaddr==NULL)
       {
        if(cmpaddr(&(newarea->myaka),&pktaddr)==0)
         {
          if(!isdupe)
            dupcheck(2);
          if(newarea->dupes && isdupe)
           {
            if(tlist)
              tlist->alist[carea].dupes++;
            totdupes++;
            if(!bcfg.killdupes)
             {
              wipearea=0;
              if(dupelocked)
               {
                logprintf("BackUp: DupeArea is locked");
                logwrite(1,3);
                backup(1);
               }
              else
                buftosqd(dupes,dindex,2);
              wipearea=1;
             }
           }
          else
            buftosqd(newarea,nindex,2);
         }
        else
         {
          if(!bcfg.secure)
           {
            if(!isdupe)
              dupcheck(2);
            if(newarea->dupes && isdupe)
             {
              if(tlist)
                tlist->alist[carea].dupes++;
              totdupes++;
              if(!bcfg.killdupes)
               {
                wipearea=0;
                if(dupelocked)
                 {
                  logprintf("BackUp: DupeArea is locked");
                  logwrite(1,3);
                  backup(1);
                 }
                else
                  buftosqd(dupes,dindex,2);
                wipearea=1;
               }
             }
            else
              buftosqd(newarea,nindex,2);
           }
          else
           {
            wipearea=0;
            totbad++;
            badtype=4;
            if(badlocked)
             {
              logprintf("BackUp: BadArea is locked");
              logwrite(1,3);
              backup(1);
             }
            else
              buftosqd(badmess,bindex,2);
            wipearea=1;
           }
         }
       }
     }
*/
      delctrl (2);
    mnext3:
      ;
    }
  closesqd (newarea, 1);
  closesqd (persarea, 1);
  unlink (badd);
  unlink (badi);
  closesqd (badmess, 0);
  if (!bcfg.killdupes)
    closesqd (dupes, 0);
  cclose (&tempsqd, __FILE__, __LINE__);
  unlink (tempsqdn);
  nowpurge = 0;
}

void untoss (void)
{
  char fulname[(DirSize + 1)], pname[(DirSize + 1)], fname[18], *temp = NULL;
  long maxmsg, i, j, newmess = 0, a /*,null=0 */ ;
  unsigned short ayear, amonth, aday, acurr, fmax2;
  short bcurr;
  struct sqdfile tsqbuf;
  lseek (newarea->sqd.sqd, 8, SEEK_SET);
  rread (newarea->sqd.sqd, &maxmsg, 4, __FILE__, __LINE__);
  if (maxmsg)
    mystrncpy (pname, bcfg.unname, DirSize);
  for (i = 0; i < maxmsg; i++)
    {
      if (sqdtobuf (newarea, nindex, i) == -2)
  goto mnext4;
      a = bufsqd.timefrom;
      ayear = (short)((a >> 9) & 0x7f);
      ayear += 1980;
      amonth = (short)((a >> 5) & 0x0f);
      aday = (short)(a & 0x1f);
#if defined(__linux__) || defined(__FreeBSD__)
      sprintf (fname, "%04u%02u%02u/", ayear, amonth, aday, acurr);
#else
      sprintf (fname, "%04u%02u%02u\\", ayear, amonth, aday);
#endif
      mystrncpy (fulname, pname, DirSize);
      mystrncat (fulname, fname, 18, DirSize);
      createpath (fulname);
      memcpy (fname, bufsqd.fromname, 8);
      for (j = 0; j < 8; j++)
  if (!isalnum (fname[(unsigned)j]))
    fname[(unsigned)j] = '_';
      fname[8] = 0;
      mystrncat (fulname, fname, 18, DirSize);
      mystrncat (fulname, ".000", 6, DirSize);
      acurr = 1;
      while (access (fulname, 0) != -1)
  {
    bcurr = acurr;
    fulname[strlen (fulname) - 3] = (char)(bcurr / 100 + '0');
    bcurr = (short)(bcurr % 100);
    fulname[strlen (fulname) - 2] = (char)(bcurr / 10 + '0');
    bcurr = (short)(bcurr % 10);
    fulname[strlen (fulname) - 1] = (char)(bcurr + '0');
    fulname[strlen (fulname)] = 0;
    acurr++;
  }
      bcurr =
  (short)sopen (fulname, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR,
          S_IRWXU | S_IRWXG | S_IRWXO);
      if (sbigmess)
  {
    lseek (tempsqd, 0, SEEK_SET);
    rreadz (tempsqd, sqdbuf, (unsigned short)(stolen + 1), __FILE__,
     __LINE__);
    mywrite (bcurr, "To: ", __FILE__, __LINE__);
    mywrite (bcurr, sqdbuf, __FILE__, __LINE__);
    mywrite (bcurr, "\r", __FILE__, __LINE__);
    rreadz (tempsqd, sqdbuf, (unsigned short)(sfromlen + 1), __FILE__,
     __LINE__);
    mywrite (bcurr, "From: ", __FILE__, __LINE__);
    mywrite (bcurr, sqdbuf, __FILE__, __LINE__);
    mywrite (bcurr, "\r", __FILE__, __LINE__);
    rreadz (tempsqd, sqdbuf, (unsigned short)(ssubjlen + 1), __FILE__,
     __LINE__);
    mywrite (bcurr, "Subj: ", __FILE__, __LINE__);
    mywrite (bcurr, sqdbuf, __FILE__, __LINE__);
    mywrite (bcurr, "\r\r", __FILE__, __LINE__);
    while ((fmax2 =
      (unsigned short)rreadz (tempsqd, sqdbuf, buflen, __FILE__,
           __LINE__)) != 0)
      {
        temp = strstr (sqdbuf, "\rSEEN-BY: ");
        if (temp && ((temp - sqdbuf) < fmax2))
    {
      wwrite (bcurr, sqdbuf, (unsigned short)(temp - sqdbuf + 1),
        __FILE__, __LINE__);
      break;
    }
        else
    wwrite (bcurr, sqdbuf, fmax2, __FILE__, __LINE__);
      }
  }
      else
  {
    mywrite (bcurr, "To: ", __FILE__, __LINE__);
    mywrite (bcurr, bufsqd.toname, __FILE__, __LINE__);
    mywrite (bcurr, "\r", __FILE__, __LINE__);
    mywrite (bcurr, "From: ", __FILE__, __LINE__);
    mywrite (bcurr, bufsqd.fromname, __FILE__, __LINE__);
    mywrite (bcurr, "\r", __FILE__, __LINE__);
    mywrite (bcurr, "Subj: ", __FILE__, __LINE__);
    mywrite (bcurr, bufsqd.subj, __FILE__, __LINE__);
    mywrite (bcurr, "\r\r", __FILE__, __LINE__);
    temp = strstr (bufsqd.text, "\rSEEN-BY: ");
    if (temp && ((temp - bufsqd.text) < stextlen))
      wwrite (bcurr, bufsqd.text,
        (unsigned short)(temp - bufsqd.text + 1), __FILE__,
        __LINE__);
    else
      wwrite (bcurr, bufsqd.text, (unsigned short)(stextlen), __FILE__,
        __LINE__);
  }
      cclose (&bcurr, __FILE__, __LINE__);
      newmess++;
      delctrl (2);
    mnext4:
      ;
    }
  if (bcfg.untkill)
    {
      lseek (newarea->sqd.sqd, 0, SEEK_SET);
      rread (newarea->sqd.sqd, &tsqbuf, 256, __FILE__, __LINE__);
      tsqbuf.nummsg = tsqbuf.highmsg = tsqbuf.first = tsqbuf.last =
  tsqbuf.firstf = tsqbuf.lastf = 0;
      tsqbuf.endf = 256;
      lseek (newarea->sqd.sqd, 0, SEEK_SET);
      wwrite (newarea->sqd.sqd, &tsqbuf, 256, __FILE__, __LINE__);
      chsize (newarea->sqd.sqd, 256);
      chsize (newarea->sqd.sqi, 0);
    }
  closesqd (newarea, 0);
}
