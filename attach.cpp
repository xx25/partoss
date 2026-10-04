// MaxiM: needed find_t _dos_findfirst/next/close

#include "partoss.h"
#include "globext.h"

#include "attach.h"
#include "archives.h"
#include "lowlevel.h"
#include "morfiles.h"
#include "errors.h"
#include "crc32.h"
#include "chains.h"
#include "times.h"
#include "environ.h"
#include "buftomsg.h"

short make, exist;
unsigned short addarc;
long arcsize;

void makeattach (short type)
{
  struct link *blink = NULL, tblink;
  struct uplname *tupl = NULL, *bladv = NULL;
  char ext[5], shname[16], arcname[(DirSize + 1)], tmpname[(DirSize + 1)],
    badname[(DirSize + 1)], fname[16], fpname[16], packets[(DirSize + 1)],
    binkname[(DirSize + 1)], zonext[6], *temp = NULL, boxname[(DirSize + 1)],
    straddr[25], flname[16], empb[4], deflo, tboxname[(DirSize + 1)],
    ssystem[DirSize + 1], errbuf[10];
  unsigned short boxes = 0, hold = 0, hexstyle = 0, bstyle = 0;
  short flags = 0, i = 0, k = 0, flo = 0, waswork = 0, arcnlen = 0, diff;
  int olds = 0, olds2 = 0, packerr = 0, tbsy = 0, islo, finish = 0, busy;
  unsigned long lpack = 0, subnet = 0, subnode = 0;
  unsigned long currtime, filetime;
  struct find_t fblk, ablk, fblo;
  sftime = time (NULL);
  mylocaltime (&sftime, &tmt);
  mystrncpy (tstrtime, asctime (&tmt), 39);
  ext[0] = '.';
#if defined (__linux__) || defined (__FreeBSD__)
  ext[1] = (char)tolower (tstrtime[0]);
  ext[2] = (char)tolower (tstrtime[1]);
#else
  ext[1] = (char)toupper (tstrtime[0]);
  ext[2] = (char)toupper (tstrtime[1]);
#endif
  ext[4] = 0;
  fname[8] = fpname[8] = 0;
  zonext[0] = '.';
  zonext[4] = 0;
  zonext[5] = 0;
  if (pkts)
    {
      for (i = 0; i < 7; i++)
  {
    if ((toupper (arcsh[i][2]) != toupper (ext[1])) ||
        (toupper (arcsh[i][3]) != toupper (ext[2])))
      {
        mystrncpy (badname, outbound, DirSize);
        mystrncat (badname, (char *)arcsh[i], 16, DirSize);
        olds = _dos_findfirst (badname, findattr, &fblk);
        while (olds == 0)
    {
      if (fblk.size == 0)
        {
          mystrncpy (tmpname, outbound, DirSize);
          mystrncat (tmpname, fblk.name, 16, DirSize);
          unlink (tmpname);
        }
      olds = _dos_findnext (&fblk);
    }
        _dos_findclose (&fblk);
             /***ash***/
      }
  }
    }
  if (bcfg.loglevel > 10)
    {
      tpack = pkts;
      while (tpack)
  {
    logprintf ("Packet %s - ", tpack->name);
    if ((!tpack->sent) && (type == 0 || tpack->filled)
        && (tpack->touched))
      mystrncat (logout, "must be sent", 15, DirSize);
    else
      mystrncat (logout, "must not be sent", 19, DirSize);
    logwrite (1, 11);
    tpack = tpack->next;
  }
    }
  tpack = pkts;
  while (tpack)
    {
      if (!tpack->sent)
  {
    if (type == 0 || tpack->filled)
      {
        if (tpack->touched)
    {
      busy = 0;
      memset (shname, 0, 16);
      memset (bsyname, 0, DirSize + 1);
      memset (bsynamef, 0, DirSize + 1);
      packerr = hold = hexstyle = bstyle = 0;
      bstyle = bcfg.boxstyle;
      boxes = bcfg.method;
      addarc = bcfg.addarc;
      arcsize = bcfg.arcsize;
      mystrncpy (defarc, bcfg.defarc, 9);
      flags = 0x191;
      ext[3] = '0';
      blink = bcfg.links.chain;
      while (blink)
        {
          if (cmpaddr (&blink->address, &tpack->outaddr) == 0)
      break;
          blink = blink->next;
        }
      if (blink)
        {
          if (blink->boxes)
      boxes = blink->boxes;
          if (addarc)
      addarc = (!(blink->addarc == 65535u));
          else
      addarc = (blink->addarc == 1);
          hold = (blink->hold == 1);
          hexstyle = blink->style;
          bstyle = blink->boxstyle;
          mystrncpy (defarc, blink->packer, 9);
          if (blink->arcsize)
      arcsize = blink->arcsize;
        }
      if (boxes < 4)
        if (hold)
          flags |= 0x200;

// Проверка наличия бизи-флагов обоих типов
// .Bsy flags for Bink
      for (i = 0; i < 4; i++)
        {
          fname[i] =
      duotrice[((tpack->outaddr.
           net) >> ((3 - i) << 2)) & 0xf];
          fname[i + 4] =
      duotrice[((tpack->outaddr.
           node) >> ((3 - i) << 2)) & 0xf];
          fpname[i] = '0';
          fpname[i + 4] =
      duotrice[((tpack->outaddr.
           point) >> ((3 - i) << 2)) & 0xf];
        }
      mystrncpy (packets, bcfg.outbound, DirSize);
      if (tpack->outaddr.zone != bcfg.address.chain->zone)
        {
          zonext[1] =
      duotrice[((tpack->outaddr.zone) >> 8) & 0xf];
          zonext[2] =
      duotrice[((tpack->outaddr.zone) >> 4) & 0xf];
          zonext[3] = duotrice[(tpack->outaddr.zone) & 0xf];
          mystrncat (packets, zonext, 7, DirSize);
        }
      mystrncat (packets, DIRSEP, 3, DirSize);
      if (tpack->outaddr.point)
        {
          mystrncat (packets, fname, 10, DirSize);
#if defined (__linux__) || defined (__FreeBSD__)
          mystrncat (packets, ".pnt/", 7, DirSize);
#else
          mystrncat (packets, ".pnt\\", 7, DirSize);
#endif
        }
      mystrncpy (binkname, packets, DirSize);
      mystrncat (binkname, tpack->outaddr.point ? fpname : fname,
           10, DirSize);
      mystrncat (binkname, ".bsy", 6, DirSize);
      if (!bcfg.dncbsy)
        {
          mystrncat (packets, "$", 2, DirSize);
          createpath (packets);
          packets[strlen (packets) - 1] = 0;
          if (access (binkname, 0) == 0)
      {
        mystrncat (packets, "$", 2, DirSize);
        rmdir (packets);
        packets[strlen (packets) - 1] = 0;
        addarc = 0;
        busy = 1;
        if (bcfg.loglevel > 10)
          {
            logprintf (
               "Bink busy flag %s for %u:%u/%u.%u detected",
               binkname, tpack->outaddr.zone,
               tpack->outaddr.net,
               tpack->outaddr.node,
               tpack->outaddr.point);
            logwrite (1, 3);
          }
        goto noaddarc1;
      }
          if (!bcfg.dnccsy)
      {
        binkname[strlen (binkname) - 3] = 'c';
        if (access (binkname, 0) == 0)
          {
            mystrncat (packets, "$", 2, DirSize);
            rmdir (packets);
            packets[strlen (packets) - 1] = 0;
            addarc = 0;
            busy = 1;
            if (bcfg.loglevel > 10)
        {
          logprintf (
             "Bink busy flag %s for %u:%u/%u.%u detected",
             binkname, tpack->outaddr.zone,
             tpack->outaddr.net,
             tpack->outaddr.node,
             tpack->outaddr.point);
          logwrite (1, 3);
        }
            goto noaddarc1;
          }
      }
        }
// FrontDoor-like Busy flags
        if (!bcfg.dncfd)
        if (bcfg.busy[0])
        {
          if (tpack->outaddr.point)
      sprintf (straddr, "%u:%u/%u.%u", tpack->outaddr.zone,
         tpack->outaddr.net, tpack->outaddr.node,
         tpack->outaddr.point);
          else
      sprintf (straddr, "%u:%u/%u", tpack->outaddr.zone,
         tpack->outaddr.net, tpack->outaddr.node);
          addrcrc =
      crc32block (straddr, (short)strlen (straddr),
            0xffffffffL);
          hexascii (addrcrc, flname);
          flname[8] = 0;
          strupr (flname);
          mystrncpy (logout, bcfg.busy, DirSize);
          mystrncat (logout, flname, 16, DirSize);
          mystrncat (logout, ".`*", 6, DirSize);
          if ((olds =
         _dos_findfirst (logout, findattr, &fblk)) == 0)
      {
        addarc = 0;
        busy = 1;
        _dos_findclose (&fblk);
        if (bcfg.loglevel > 10)
          {
            logprintf (
               "FD busy flag %s\\%s for %u:%u/%u.%u detected",
               bcfg.busy, flname, tpack->outaddr.zone,
               tpack->outaddr.net,
               tpack->outaddr.node,
               tpack->outaddr.point);
            logwrite (1, 3);
          }
        goto noaddarc1;
      }
        }
// Создание бизи-флагов
      if (!bcfg.dncbsy)
        {
          binkname[strlen (binkname) - 3] = 'b';
          mystrncpy (bsyname, binkname, DirSize);
          tbsy =
      open (bsyname, O_RDWR | O_BINARY | O_CREAT,
            S_IREAD | S_IWRITE);
          if (tbsy <= 0)
      {
        mystrncat (packets, "$", 2, DirSize);
        rmdir (packets);
        packets[strlen (packets) - 1] = 0;
        addarc = 0;
        busy = 1;
        if (bcfg.loglevel > 10)
          {
            logprintf (
               "Bink busy flag %s for %u:%u/%u.%u create failed",
               bsyname, tpack->outaddr.zone,
               tpack->outaddr.net,
               tpack->outaddr.node,
               tpack->outaddr.point);
            logwrite (1, 11);
          }
        goto noaddarc1;
      }
          else
      {
        mystrncat (packets, "$", 2, DirSize);
        rmdir (packets);
        packets[strlen (packets) - 1] = 0;
        mywrite ((short)tbsy, "ParToss busy flag", __FILE__,
           __LINE__);
        cclose ((short *)&tbsy, __FILE__, __LINE__);
      }
        }
        if (!bcfg.dncfd)
      if (bcfg.busy[0])
        {
          mystrncpy (bsynamef, bcfg.busy, DirSize);
          mystrncat (bsynamef, flname, 16, DirSize);
          mystrncat (bsynamef, ".`ff", 6, DirSize);
          tbsy =
      open (bsynamef, O_RDWR | O_BINARY | O_CREAT,
            S_IREAD | S_IWRITE);
          if (tbsy <= 0)
      {
        addarc = 0;
        busy = 1;
        if (bcfg.loglevel > 10)
          {
            logprintf (
               "FD busy flag %s for %u:%u/%u.%u create failed",
               bsynamef, tpack->outaddr.zone,
               tpack->outaddr.net,
               tpack->outaddr.node,
               tpack->outaddr.point);
            logwrite (1, 11);
          }
        goto noaddarc1;
      }
          else
      {
        mywrite ((short)tbsy, "ParToss busy flag", __FILE__,
           __LINE__);
        cclose ((short *)&tbsy, __FILE__, __LINE__);
      }
        }
    noaddarc1:
      ;
// Проверка наличия бизи-флагов обоих типов
      if (!tpack->file)
        {
          if (hexstyle == 10)
      {
        memset (logout, 0, BufSize);
        logprintf ("%u:%u/%u.%u~%u:%u/%u.%u",
           tpack->fromaddr.zone, tpack->fromaddr.net,
           tpack->fromaddr.node,
           tpack->fromaddr.point, tpack->outaddr.zone,
           tpack->outaddr.net, tpack->outaddr.node,
           tpack->outaddr.point);
        lpack =
          crc32block (logout, (short)strlen (logout), 0);
        hexascii (lpack, shname);
      }
          else
      {
        if (tpack->fromaddr.point == 0
            && tpack->outaddr.point == 0)
          hexstyle = 1;
        if (hexstyle == 1)
          {
            subnet =
        (tpack->fromaddr.net -
         tpack->outaddr.net) & 0xffff;
            subnode =
        (tpack->fromaddr.node -
         tpack->outaddr.node) & 0xffff;
            lpack = subnet << 16;
            lpack |= subnode;
            hexascii (lpack, shname);
          }
        else
          {
            if (tpack->fromaddr.point)
        {
          subnet = tpack->fromaddr.node;
          subnode = tpack->fromaddr.point;
        }
            else
        {
          subnet = tpack->outaddr.node;
          subnode = tpack->outaddr.point;
        }
            lpack = subnet << 12;
            lpack |= (subnode & 0xfff);
            hexascii (lpack, shname);
            if (hexstyle == 2)
        shname[0] = tpack->fromaddr.point ? 'b' : 'a';
            else
        shname[0] = tpack->fromaddr.point ? 'n' : 'p';
          }
      }
          shname[8] = 0;
          mystrncpy (arcname, outbound, DirSize);
          mystrncat (arcname, shname, 11, DirSize);
          mystrncat (arcname, ext, 6, DirSize);
        }
      else
        mystrncpy (arcname, tpack->name, DirSize);
      exist = 0;
      if (!tpack->file)
        adjustname (arcname);
      if (!tpack->opened)
        {
          tpack->handle =
      (short)sopen (tpack->name, O_RDWR | O_BINARY,
              SH_DENYWR);
          tpack->opened = 1;
        }
      arclen = filelength (tpack->handle);
      if (!blink)
        {
          memset (&tblink, 0, szlink);
          memcpy (&tblink.address, &tpack->outaddr, szmyaddr);
          tblink.boxes = bcfg.method;
          tblink.addarc = bcfg.addarc;
          tblink.pktsize = bcfg.pktsize;
          tblink.arcsize = bcfg.arcsize;
          mystrncpy (tblink.packer, bcfg.defarc, 9);
          addlink (&(bcfg.links), &tblink);
          bcfg.numlink++;
          blink = bcfg.links.chain;
          while (blink)
      {
        if (cmpaddr (&blink->address, &tpack->outaddr) == 0)
          break;
        blink = blink->next;
      }
        }
      blink->sent += arclen;
      cclose (&tpack->handle, __FILE__, __LINE__);
      tpack->opened = 0;
      if (arclen == 0)
        {
          unlink (tpack->name);
          tpack->name[strlen (tpack->name) - 1] = 'F';
          unlink (tpack->name);
          goto nextpack;
        }
/*
          if(!tpack->netmail || bcfg.pack)
           {
*/
      if (!tpack->file)
        {
          mystrncpy (tmpname, tpack->name, DirSize);
          if (tmpname[strlen (tmpname) - 3] != 'p'
        && tmpname[strlen (tmpname) - 2] != 'k')
      {
        tpack->name[strlen (tpack->name) - 3] = 'p';
        tpack->name[strlen (tpack->name) - 2] = 'k';
        rrename (tmpname, tpack->name);
        mystrncpy (tmpname, tpack->name, DirSize);
      }
        }
      if (boxes == 1)
        {
          bladv = bcfg.bladv;
          while (bladv)
      {
        if (cmpaddr (&bladv->upaddr, &tpack->outaddr) == 0)
          break;
        bladv = bladv->next;
      }
          if (bladv && (bladv->echolist[0]))
      {
        mystrncpy (boxname, bladv->echolist, DirSize);
      }
          else
      {
        if (bstyle == 2)
          memcpy (tpack->outaddr.domain,
            blink->address.domain, 8);
        mystrncpy (boxname,
             makebox (&tpack->outaddr, bstyle, hold),
             DirSize);
      }
          mystrncat (boxname, "$", 2, DirSize);
          mystrncpy (tboxname, boxname, DirSize);
          createpath (boxname);
          boxname[strlen (boxname) - 1] = 0;
          if (!tpack->file)
      {
        arcnlen = (short)(strlen (arcname) - 1);
        if (addarc)
          {
            if (arcname[arcnlen] != 0x30)
        {
          arcname[arcnlen]--;
          if (arcname[arcnlen] == 0x40)
            arcname[arcnlen] = '9';
          if (arcname[arcnlen] == 0x60)
            arcname[arcnlen] = '9';
        }
          }
        temp = strrchr (arcname, DIRSEP[0]);
        if (temp)
          mystrncat (boxname, temp + 1, 16, DirSize);
        else
          mystrncat (boxname, arcname, DirSize, DirSize);
      reread1:
        olds = _dos_findfirst (boxname, findattr, &fblk);
        olds2 = _dos_findfirst (arcname, findattr, &ablk);
        if (olds2 == 0 || olds == 0)
          {
            mystrncpy (tstrtime, asctime (&tmt), 39);
            currtime = strtime (tstrtime);
            filetime = fblk.wr_time;
            filetime <<= 16;
            filetime += fblk.wr_date;
            diff = diffdays (filetime, currtime);
            if ((olds != 0)
          || (!addarc
              || (arcsize && (fblk.size > arcsize)))
          || diff)
        {
          arcname[arcnlen]++;
          if (arcname[arcnlen] == 0x3A)
            arcname[arcnlen] = 'a';
          if (arcname[arcnlen] > 'z')
            {
              if (busy)
          {
            mystrncpy (tmpname, tpack->name,
                 DirSize);
            if (tmpname[strlen (tmpname) - 3] !=
                'o'
                && tmpname[strlen (tmpname) -
               2] != 'u')
              {
                tpack->
            name[strlen (tpack->name) -
                 3] = 'o';
                tpack->
            name[strlen (tpack->name) -
                 2] = 'u';
                rrename (tmpname, tpack->name);
                mystrncpy (tmpname, tpack->name,
               DirSize);
              }
            blink->sent -= arclen;
            rmdir (tboxname);
            goto nextpack;
          }
              arcname[arcnlen] = 'z';
            }
          boxname[strlen (boxname) - 1] =
            arcname[arcnlen];
/***ash           while((olds=_dos_findnext(&fblk))==0) ; ***/
/***ash***/ _dos_findclose (&fblk);
/***ash***/ _dos_findclose (&ablk);
          if (arcname[arcnlen] != 'z')
            goto reread1;
          else
            {
              olds =
          _dos_findfirst (boxname, findattr,
              &fblk);
              _dos_findclose (&fblk);
              if (busy && olds == 0)
          {
            mystrncpy (tmpname, tpack->name,
                 DirSize);
            if (tmpname[strlen (tmpname) - 3] !=
                'o'
                && tmpname[strlen (tmpname) -
               2] != 'u')
              {
                tpack->
            name[strlen (tpack->name) -
                 3] = 'o';
                tpack->
            name[strlen (tpack->name) -
                 2] = 'u';
                rrename (tmpname, tpack->name);
                mystrncpy (tmpname, tpack->name,
               DirSize);
              }
            blink->sent -= arclen;
            goto nextpack;
          }
            }
        }
          }
        if (olds == 0)
/***ash         while((olds=_dos_findnext(&fblk))==0) ; ***/
/***ash***/ _dos_findclose (&fblk);
        if (olds2 == 0)
/***ash***/ _dos_findclose (&ablk);
        if (bcfg.sbp[0])
          {
            mystrncpy (ssystem, bcfg.sbp, DirSize);
            mystrncat (ssystem, "  ", 5, DirSize);
            mystrncat (ssystem, tmpname, DirSize, DirSize);
#ifdef __NT__
            GetConsoleTitle(logout, BufSize);
#endif
            system (ssystem);
#ifdef __NT__
            SetConsoleTitle(logout);
#endif
          }
        logprintf ("Pack %s to %s", tmpname, boxname);
        logwrite (1, 9);
        packerr = archiver (boxname, tmpname, 2);
        if (bcfg.sap[0])
          {
            mystrncpy (ssystem, bcfg.sap, DirSize);
            mystrncat (ssystem, "  ", 5, DirSize);
            mystrncat (ssystem, itoa (packerr, errbuf, 10), DirSize, DirSize);
#ifdef __NT__
            GetConsoleTitle(logout, BufSize);
#endif
            system (ssystem);
#ifdef __NT__
            SetConsoleTitle(logout);
#endif
          }
        if (!packerr)
          {
            k =
        (short)sopen (arcname,
                O_RDWR | O_BINARY | O_CREAT,
                SH_DENYWR,
                S_IRWXU | S_IRWXG | S_IRWXO);
            cclose (&k, __FILE__, __LINE__);
          }
      }
          else
      {
        temp = strrchr (tpack->name, DIRSEP[0]);
        if (temp)
          mystrncat (boxname, temp + 1, 16, DirSize);
        else
          mystrncat (boxname, tpack->name, DirSize,
               DirSize);
        if (rrename (tpack->name, boxname))
          movefile (tpack->name, boxname);
      }
          temp = strrchr (boxname, DIRSEP[0]);
          if (temp)
      {
        *(temp + 1) = '$';
        *(temp + 2) = 0;
        rmdir (boxname);
        *(temp + 1) = 0;
      }
        }
      else
        {
          if (boxes < 4)
      {
        if (!tpack->file)
          {
            if (bcfg.sbp[0])
        {
          mystrncpy (ssystem, bcfg.sbp, DirSize);
          mystrncat (ssystem, "  ", 5, DirSize);
          mystrncat (ssystem, tmpname, DirSize, DirSize);
#ifdef __NT__
          GetConsoleTitle(logout, BufSize);
#endif
          system (ssystem);
#ifdef __NT__
          SetConsoleTitle(logout);
#endif
        }
            logprintf ("Pack %s to %s", tmpname, arcname);
            logwrite (1, 9);
            packerr = archiver (arcname, tmpname, 2);
            if (bcfg.sap[0])
        {
          mystrncpy (ssystem, bcfg.sap, DirSize);
          mystrncat (ssystem, "  ", 5, DirSize);
          mystrncat (ssystem, itoa (packerr, errbuf, 10), DirSize, DirSize);
#ifdef __NT__
          GetConsoleTitle(logout, BufSize);
#endif
          system (ssystem);
#ifdef __NT__
          SetConsoleTitle(logout);
#endif
        }
          }
        else
          mystrncpy (arcname, tpack->name, DirSize);
      }
          else
      {
        if (busy)
          {
            mystrncpy (tmpname, tpack->name, DirSize);
            if (tmpname[strlen (tmpname) - 3] != 'o'
          && tmpname[strlen (tmpname) - 2] != 'u')
        {
          tpack->name[strlen (tpack->name) - 3] = 'o';
          tpack->name[strlen (tpack->name) - 2] = 'u';
          rrename (tmpname, tpack->name);
          mystrncpy (tmpname, tpack->name, DirSize);
        }
            blink->sent -= arclen;
            goto nextpack;
          }
        mystrncpy (binkname, packets, DirSize);
        mystrncat (binkname, shname, 11, DirSize);
        if (!tpack->file)
          {
            arcnlen = (short)(strlen (arcname) - 1);
            if (addarc && exist)
        {
          if (arcname[arcnlen] > '0')
            {
              arcname[arcnlen]--;
              if (arcname[arcnlen] == 0x40)
          arcname[arcnlen] = '9';
              if (arcname[arcnlen] == 0x60)
          arcname[arcnlen] = '9';
            }
        }
            temp = strrchr (arcname, '.');
            if (temp)
        mystrncat (binkname, temp, 7, DirSize);
            else
        mystrncat (binkname, arcname, DirSize, DirSize);
          reread2:
            olds =
        _dos_findfirst (binkname, findattr, &fblk);
            if (olds == 0)
        {
          exist = 0;
          mystrncpy (tstrtime, asctime (&tmt), 39);
          currtime = strtime (tstrtime);
          filetime = fblk.wr_time;
          filetime <<= 16;
          filetime += fblk.wr_date;
          diff = diffdays (filetime, currtime);
          if (!addarc
              || (arcsize && (fblk.size > arcsize))
              || (fblk.size == 0) || diff)
            {
              arcname[arcnlen]++;
              if (arcname[arcnlen] == 0x3A)
          arcname[arcnlen] = 'a';
              if (arcname[arcnlen] > 'z')
          arcname[arcnlen] = 'z';
              binkname[strlen (binkname) - 1] =
          arcname[arcnlen];
/***ash             while((olds=_dos_findnext(&fblk))==0) ; ***/
/***ash***/ _dos_findclose (&fblk);
              if (arcname[arcnlen] != 'Z')
          goto reread2;
            }
        }
            else
        {
          if (!bcfg.trunc && addarc && exist)
            {
              arcname[arcnlen]++;
              if (arcname[arcnlen] == 0x3A)
          arcname[arcnlen] = 'a';
              if (arcname[arcnlen] > 'z')
          arcname[arcnlen] = 'z';
              binkname[strlen (binkname) - 1] =
          arcname[arcnlen];
            }
        }
            if (olds == 0)
/***ash           while((olds=_dos_findnext(&fblk))==0) ; ***/
/***ash***/ _dos_findclose (&fblk);
            if (bcfg.sbp[0])
        {
          mystrncpy (ssystem, bcfg.sbp, DirSize);
          mystrncat (ssystem, "  ", 5, DirSize);
          mystrncat (ssystem, tmpname, DirSize, DirSize);
#ifdef __NT__
          GetConsoleTitle(logout, BufSize);
#endif
          system (ssystem);
#ifdef __NT__
          SetConsoleTitle(logout);
#endif
        }
            logprintf ("Pack %s to %s", tmpname, binkname);
            logwrite (1, 9);
            packerr = archiver (binkname, tmpname, 2);
            if (bcfg.sap[0])
        {
          mystrncpy (ssystem, bcfg.sap, DirSize);
          mystrncat (ssystem, "  ", 5, DirSize);
          mystrncat (ssystem, itoa (packerr, errbuf, 10), DirSize, DirSize);
#ifdef __NT__
          GetConsoleTitle(logout, BufSize);
#endif
          system (ssystem);
#ifdef __NT__
          SetConsoleTitle(logout);
#endif
        }
          }
        else
          {
            temp = strrchr (arcname, DIRSEP[0]);
            if (temp)
        mystrncat (binkname, temp + 1, 15, DirSize);
            else
        mystrncat (binkname, arcname, DirSize,
             DirSize);
            if (rrename (tpack->name, binkname))
        movefile (tpack->name, binkname);
          }
        mystrncat (packets, "$", 2, DirSize);
        rmdir (packets);
        packets[strlen (packets) - 1] = 0;
      }
        }
/*
            else
              packerr=0;
           }
*/
      if (!packerr)
        {
          if (boxes == 4)
      {
/*
              if(!bcfg.pack)
                mystrncpy(arcname,tpack->name,DirSize);
              if(tpack->netmail&2)
                arcname[strlen(arcname)-3]='C';
              else
                if(tpack->netmail&3)
                  arcname[strlen(arcname)-3]='D';
*/
        if (!tpack->file)
          {
            if ((i =
           (short)sopen (arcname,
             O_RDWR | O_BINARY | O_CREAT,
             SH_DENYWR,
             S_IRWXU | S_IRWXG | S_IRWXO))
          <= 0)
        {
          mystrncpy (errname, arcname, DirSize);
          errexit (2, __FILE__, __LINE__);
        }
            cclose (&i, __FILE__, __LINE__);
          }
        mystrncpy (arcname, binkname, DirSize);
        mystrncpy (binkname, packets, DirSize);
        mystrncat (binkname,
             tpack->outaddr.point ? fpname : fname,
             10, DirSize);
        mystrncat (binkname, ".?lo", 6, DirSize);
        // If this won't work, change it to ".*" and inside cycle
        // check if file name ends to "lo"
        i = (short)strlen (binkname);
        if (hold)
          deflo = 'h';
        else if (bcfg.binkdlo)
          deflo = 'd';
        else
          deflo = 'f';
/*
              if(tpack->netmail&2)
                binkname[strlen(binkname)-3]='c';
              else
                if(tpack->netmail&3)
                  binkname[strlen(binkname)-3]='d';
*/
        if (!bcfg.trunc)
          mystrncpy (logout, "^", 2);
        else
          mystrncpy (logout, "#", 2);
        if (!tpack->file)
          {
            mystrncat (logout, packets, DirSize, BufSize);
            temp = strrchr (arcname, DIRSEP[0]);
            if (temp)
        mystrncat (logout, temp + 1, DirSize,
             BufSize);
            else
        mystrncat (logout, arcname, DirSize, BufSize);
          }
        else
          mystrncat (logout, arcname, DirSize, BufSize);

        islo = _dos_findfirst (binkname, findattr, &fblo);
        while (islo == 0)
          {
            mystrncpy (badname, binkname, DirSize);
            temp = strrchr (fblo.name, '.');
            badname[strlen (badname) - 3] = temp[1];
            finish = 0;
            while (!finish)
        {
          flo =
            (short)sopen (badname, O_RDWR | O_BINARY,
              SH_DENYWR);
          if (flo == -1)
            {
              if (errno == EACCES)
          {
            if (lich)
              {
                logprintf (
                   "Waiting for open %s",
                   badname);
                logwrite (1, 1);
              }
            mtsleep (5);
          }
              else
          goto newslo;
            }
          else
            finish = 1;
        }
            finish = strlen (logout);
            lseek (flo, 0, SEEK_SET);
            endinput[2] = 0;
            while (!endinput[2])
        {
          readblock (flo, 2);
          endblock[2] = 0;
          do
            {
              getstring (2);
              if ((finish == maxstr[2])
            &&
            (strnicmp
             (logout, ::string, maxstr[2]) == 0))
          goto sfound;
            }
          while (!endblock[2]);
        }
            cclose (&flo, __FILE__, __LINE__);
          newslo:
            islo = _dos_findnext (&fblo);
          }
        _dos_findclose (&fblo);

        binkname[i - 3] = deflo;
        finish = 0;
        while (!finish)
          {
            flo =
        (short)sopen (binkname, O_RDWR | O_BINARY,
                SH_DENYWR);
            if (flo <= 0)
        switch (errno)
          {
          case ENOENT:
            if ((flo =
           (short)sopen (binkname,
                   O_RDWR | O_BINARY |
                   O_CREAT, SH_DENYWR,
                   S_IRWXU | S_IRWXG |
                   S_IRWXO)) == -1)
              {
          mystrncpy (errname, binkname,
               DirSize);
          errexit (2, __FILE__, __LINE__);
              }
            finish = 1;
            break;

          case EMFILE:
            mystrncpy (errname, binkname, DirSize);
            errexit (2, __FILE__, __LINE__);

          case EACCES:
            if (lich)
              {
          logprintf (
             "Waiting for open/create %s",
             binkname);
          logwrite (1, 1);
              }
            mtsleep (5);
            break;

          case -1:
            if ((flo =
           (short)sopen (binkname,
                   O_RDWR | O_BINARY,
                   SH_DENYNO)) == -1)
              {
          mystrncpy (errname, binkname,
               DirSize);
          errexit (2, __FILE__, __LINE__);
              }
            finish = 1;
            break;

          default:
            mystrncpy (errname, binkname, DirSize);
            errexit (2, __FILE__, __LINE__);
          }
            else
        finish = 1;
          }
        lseek (flo, 0, SEEK_END);
        mystrncat (logout, "\r\n", 5, BufSize);
        mywrite (flo, logout, __FILE__, __LINE__);
        goto sfoundd;
      sfound:
        lseek (flo, 0, SEEK_SET);
        rread (flo, empb, 2, __FILE__, __LINE__);
        lseek (flo, 0, SEEK_SET);
        wwrite (flo, empb, 2, __FILE__, __LINE__);
      sfoundd:
        cclose (&flo, __FILE__, __LINE__);
      }
          else
      {
        if (boxes == 2)
          {
            if (!tpack->file)
        {
          if (make)
            msgwrite (&tpack->fromaddr,
                &tpack->outaddr, "ArcMail",
                "SysOp", arcname, flags,
                "\1FLAGS TFS\r", NULL);
        }
            else
        msgwrite (&tpack->fromaddr, &tpack->outaddr,
            "ArcMail", "SysOp", arcname, flags,
            "\1FLAGS KFS\r", NULL);
          }
      }
/*
            if(!tpack->netmail || bcfg.pack)
*/
          unlink (tmpname);
        }
      tpack->sent = 1;
      waswork = 1;
    }
        else
    {
      if (tpack->opened)
        {
          cclose (&tpack->handle, __FILE__, __LINE__);
          tpack->opened = 0;
        }
      unlink (tpack->name);
      tpack->name[strlen (tpack->name) - 1] = 'f';
      unlink (tpack->name);
    }
      }
  }
    nextpack:
      if (bsyname[0])
  unlink (bsyname);
      if (bsynamef[0])
  unlink (bsynamef);
      tpack = tpack->next;
    }
  if (waswork)
    {
      tupl = bcfg.semaphore;
      while (tupl)
  {
    i =
      (short)sopen (tupl->echolist, O_RDWR | O_BINARY | O_CREAT,
        SH_DENYNO, S_IRWXU | S_IRWXG | S_IRWXO);
    if (i != -1)
      cclose (&i, __FILE__, __LINE__);
    tupl = tupl->next;
  }
    }
}

void msgwrite (struct myaddr *from, struct myaddr *to, char *fromname,
         char *toname, char *subj, unsigned short flags, char *klflags,
         char *text)
{
  bufmess.fromname = fromname;
  bufmess.toname = toname;
  bufmess.subj = subj;
  bufmess.flags = flags;
  bufmess.text = text;
  if (text)
    mtextlen = strlen (text);
  else
    mtextlen = 0;
  mbigmess = 0;
  bufmess.tozone = to->zone;
  bufmess.tonet = to->net;
  bufmess.tonode = to->node;
  bufmess.topoint = to->point;
  bufmess.fromzone = from->zone;
  bufmess.fromnet = from->net;
  bufmess.fromnode = from->node;
  bufmess.frompoint = from->point;
  if (klflags)
    {
      mckludge = (struct kludge *)myalloc (szkludge, __FILE__, __LINE__);
      mckludge->str = (char *)myalloc (81, __FILE__, __LINE__);
      mystrncpy (mckludge->str, klflags, 80);
      mckludge->left = 0;
      mckludge->next = NULL;
      mkludlen = (short)strlen (klflags);
      mkludnum = 1;
    }
  else
    {
      mckludge = NULL;
      mkludlen = mkludnum = 0;
    }
  buftomsg (1);
  if (klflags)
    {
      myfree ((void **)&mckludge->str, __FILE__, __LINE__);
      myfree ((void **)&mckludge, __FILE__, __LINE__);
    }
  return;
}

void createpath (char *path)
{
  char curpath[(DirSize + 1)], curpd[5], curpath2[(DirSize + 1)],
    tpath[(DirSize + 1)], temppath[(DirSize + 1)], *temp = NULL, *temp2 =
    NULL;
  short curdisk, needdisk, realdisk;
  unsigned int total;
  if (path[0])
    {
      mystrncpy (tpath, path, DirSize);
      if (tpath[strlen (tpath) - 1] != DIRSEP[0])
  {
    tpath[strlen (tpath)] = DIRSEP[0];
    tpath[strlen (tpath) + 1] = 0;
  }
      _dos_getdrive ((unsigned int *)(&curdisk));
      curpd[0] = (char)(curdisk + '@');
      curpd[1] = ':';
      curpd[2] = DIRSEP[0];
      curpd[3] = 0;
      getcwd (curpath, DirSize);
//    memset(temppath,0,(DirSize+1));
      if (path[1] == ':')
  {
    needdisk = (char)(toupper (tpath[0]) - '@');
    _dos_setdrive (needdisk, &total);
    _dos_getdrive ((unsigned int *)(&realdisk));
    if (realdisk != needdisk)
      {
        ccprintf
    ("!!! Can't change drive to %c: while trying to create %s\r\n",
     tpath[0], path);
        return;
      }
    getcwd (curpath2, DirSize);
    mystrncpy (temppath, tpath, 2);
    temppath[2] = 0;
    mystrncat (temppath, DIRSEP, 3, DirSize);
    chdir (temppath);
  }
      temp2 = tpath;
      if (temp2[0] == DIRSEP[0])
  {
    chdir (DIRSEP);
    temp2 = temp2 + 1;
  }
      temp = strchr (temp2, DIRSEP[0]);
      while (temp)
  {
    mystrncpy (temppath, temp2, DirSize);
    temppath[(unsigned)(temp - temp2)] = 0;
    if (chdir (temppath) == -1)
      {
        mkdir (temppath);
        chdir (temppath);
      }
    temp2 = temp + 1;
    temp = strchr (temp2, DIRSEP[0]);
  }
//    memset(temppath,0,(DirSize+1));
      mystrncpy (temppath, tpath, 2);
      temppath[2] = 0;
      mystrncat (temppath, DIRSEP, 3, DirSize);
      chdir (temppath);
      chdir (curpath2);
      _dos_setdrive (curdisk, &total);
      chdir (curpd);
      chdir (curpath);
    }
}

void adjustname (char *name)
{
  int olds;
  struct find_t fblk;
  make = 1;
  olds = _dos_findfirst (name, findattr, &fblk);
  while (olds == 0)
    {
      exist = 1;
      if ((fblk.attrib & 0x1f) || fblk.size == 0 || !addarc ||
    (arcsize && (fblk.size > arcsize)))
  {
    name[strlen (name) - 1]++;
    if (name[strlen (name) - 1] == 0x3a)
      name[strlen (name) - 1] = 'a';
    if (toupper (name[strlen (name) - 1]) == 'Z')
      {
        _dos_findclose (&fblk);
        olds = _dos_findfirst (name, findattr, &fblk);
        if (olds == 0)
    {
      if (fblk.size == 0)
        name[strlen (name) - 1] = '0';
      else
        make = 0;
    }
        else
    _dos_findclose (&fblk);
        break;
      }
  }
      else
  {
    make = 0;
    break;
  }
/*  while(_dos_findnext(&fblk)==0) ; ***ash***/
      _dos_findclose (&fblk);
         /***ash***/
      olds = _dos_findfirst (name, findattr, &fblk);
    }
  if (olds == 0)
/* while(_dos_findnext(&fblk)==0) ; ***ash***/
    _dos_findclose (&fblk);
       /***ash***/
}

char *makebox (struct myaddr *toaddr, int type, int hold)
{
  static char ret[DirSize + 1];
  char box32[16], boxlong[DirSize + 1], tdomain[9];
  unsigned int i;
  mystrncpy (ret, bcfg.boxes, DirSize);
  switch (type)
    {
    case 0:
      i = toaddr->zone;
      box32[0] = duotrice[(i >> 5) & 0x1f];
      box32[1] = duotrice[i & 0x1f];
      i = toaddr->net;
      box32[2] = duotrice[(i >> 10) & 0x1f];
      box32[3] = duotrice[(i >> 5) & 0x1f];
      box32[4] = duotrice[i & 0x1f];
      i = toaddr->node;
      box32[5] = duotrice[(i >> 10) & 0x1f];
      box32[6] = duotrice[(i >> 5) & 0x1f];
      box32[7] = duotrice[i & 0x1f];
      i = toaddr->point;
      box32[8] = '.';
      box32[9] = duotrice[(i >> 5) & 0x1f];
      box32[10] = duotrice[i & 0x1f];
      if (hold)
  {
    box32[11] = 'H';
    box32[12] = DIRSEP[0];
    box32[13] = 0;
  }
      else
  {
    box32[11] = DIRSEP[0];
    box32[12] = 0;
  }
      strupr (box32);
      mystrncat (ret, box32, 16, DirSize);
      /*strupr(ret); */
      break;

    case 1:
#if defined (__linux__) || defined (__FreeBSD__)
      sprintf (boxlong, "%u.%u.%u.%u%s/", toaddr->zone, toaddr->net,
         toaddr->node, toaddr->point, hold ? ".H" : "");
#else
      sprintf (boxlong, "%u.%u.%u.%u%s\\", toaddr->zone, toaddr->net,
         toaddr->node, toaddr->point, hold ? ".H" : "");
#endif
      mystrncat (ret, boxlong, DirSize, DirSize);
      break;

    case 2:
      memcpy (tdomain, toaddr->domain, 8);
      tdomain[8] = 0;
#if defined (__linux__) || defined (__FreeBSD__)
      sprintf (boxlong, "%s.%u.%u.%u.%u%s/", tdomain, toaddr->zone,
         toaddr->net, toaddr->node, toaddr->point,
         hold ? ".Hold" : ".Normal");
#else
      sprintf (boxlong, "%s.%u.%u.%u.%u%s\\", tdomain, toaddr->zone,
         toaddr->net, toaddr->node, toaddr->point,
         hold ? ".Hold" : ".Normal");
#endif
      mystrncat (ret, boxlong, DirSize, DirSize);
      break;
    }
  return ret;
}

/*
void deletepath(char *path)
 {
  char curpath[(DirSize+1)],last[(DirSize+1)],*temp=NULL,*temp2=NULL;
  short curdisk,needdisk,realdisk;
  unsigned int total;
  int res=1;
  if(path[0])
   {
    mystrncpy(curpath,path,DirSize);
    do
     {
      temp=strrchr('\\',curpath);
      if(temp==NULL)
        return;
      mystrncpy(last,temp,DirSize);
      temp[0]=0;
      chdir(curpath);
      res=rmdir(last);
     }
    while(res);
   }
  return;
 }
*/
