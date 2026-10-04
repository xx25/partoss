// MaxiM: find_t memicmp

#include "partoss.h"
#include "globext.h"

#include "partserv.h"
#include "lowlevel.h"
#include "morfiles.h"
#include "errors.h"
#include "control.h"
#include "scanbase.h"
#include "times.h"
#include "packets.h"
#include "parsrout.h"
#include "partsqd.h"
#include "buftomsg.h"
#include "template.h"
#include "chains.h"
#include "attach.h"
#include "msgtobuf.h"

struct uplname *uareas = NULL;
short badlink, manager = 0, temptoklen;
char *temptoken = NULL;

void server(void)
{
  short nomore, msg, checkall, namelen, tcarea;
  char tmpfile[(DirSize + 1)], tfile[(DirSize + 1)];
  struct find_t fblk;
  struct myaddr *taddr = NULL;
  struct manname *tmname = NULL;
  struct link *blink = NULL;
  struct alists *ttlist = NULL, *tttlist = NULL;

  chsize(temppkt, 0);
  lseek(temppkt, 0, SEEK_SET);
  mystrncpy(logout, "Processing messages to Echo Manager", BufSize);
  logwrite(1, 4);
  if(!quiet)
    ccprintf("\r\n%s\r\n", logout);
  if(bcfg.netserv[0])
    checkall = 0;
  else
    checkall = 1;
  tlist = rlist;
  while(tlist)
  {
    ttlist = tlist;
    for(carea = 0; carea < tlist->numlists; carea++)
    {
      tttlist = tlist;
      tcarea = carea;
      if(tlist->alist[carea].type == 0)
      {
        namelen = (short)strlen(tlist->alist[carea].areaname);
        if(strlen(bcfg.netserv) > namelen)
          namelen = (short)strlen(bcfg.netserv);
        if(checkall || (memicmp(tlist->alist[carea].areaname, bcfg.netserv, namelen) == 0))
        {
          lseek(areaset, tlist->alist[carea].areaoffs, SEEK_SET);
          rread(areaset, newarea, szarea, __FILE__, __LINE__);
          mystrncpy(tmpfile, newarea->areafp, DirSize);
          mystrncat(tmpfile, "*.msg", 7, DirSize);
          nomore = (short)_dos_findfirst(tmpfile, findattr, &fblk);
          while(nomore == 0)
          {
            if(!(fblk.attrib & 0x1f))
            {
              mystrncpy(tfile, tmpfile, DirSize);
              tfile[strlen(tfile) - 5] = 0;
              mystrncat(tfile, fblk.name, 16, DirSize);
              mystrncpy(confile, tfile, DirSize);
              msgtobuf(tfile);
              if(bcfg.mankill || !(bufmess.flags & 4))
              {
                taddr = bcfg.address.chain;
                while(taddr)
                {
                  if(cmpaddr(taddr, &node) == 0)
                    break;
                  taddr = taddr->next;
                }
                if(taddr)
                {
                  tmname = bcfg.names;
                  while(tmname)
                  {
                    if(stricmp(tmname->name, bufmess.toname) == 0)
                      break;
                    tmname = tmname->next;
                  }
                  if(tmname)
                  {
                    tmname = bcfg.names2;
                    while(tmname)
                    {
                      if((strnicmp
                          (tmname->name,
                           bufmess.fromname,
                           strlen(tmname->name)) == 0) && (strlen(tmname->name) == strlen(bufmess.fromname)))
                        break;
                      tmname = tmname->next;
                    }
                    if(!tmname)
                    {
                      blink = bcfg.links.chain;
                      while(blink)
                      {
                        if(cmpaddr(&(blink->address), &mfnode) == 0)
                          break;
                        blink = blink->next;
                      }
                      if(blink)
                      {
                        if((blink->echopass[0])
                           && (strnicmp(blink->echopass, bufmess.subj, strlen(blink->echopass)) == 0))
                        {
                          badlink = 0;
                          manager = blink->manager;
                        }
                        else
                        {
                          badlink = 1;
                          manager = 0;
                        }
                      }
                      else
                        badlink = 2;
                      doserv();
                      if(bcfg.mankill)
                        unlink(tfile);
                      else
                      {
                        if((msg = (short)sopen(tfile, O_RDWR | O_BINARY, SH_DENYWR)) == -1)
                        {
                          mystrncpy(errname, tfile, DirSize);
                          errexit(2, __FILE__, __LINE__);
                        }
                        rread(msg, &bufmsg, (unsigned short)(szmessage - szchar), __FILE__, __LINE__);
                        bufmsg.flags |= 4;
                        lseek(msg, 0, SEEK_SET);
                        wwrite(msg, &bufmsg, (unsigned short)(szmessage - szchar), __FILE__, __LINE__);
                        cclose(&msg, __FILE__, __LINE__);
                      }
                    }
                  }
                }
              }
              delctrl(3);
            }
            nomore = (short)_dos_findnext(&fblk);
          }
          _dos_findclose(&fblk);
         /***ash***/
        }
      }
      tlist = tttlist;
      carea = tcarea;
    }
    tlist = ttlist->next;
  }
  makeattach(0);
}

void doserv(void)
{
  short i, j, k, l, numcomm, numofarc, temprescan, sort, linkchg = 0, tupl, tnorep, isforw, tcarea;
  unsigned short curr;
  short rendstring, rendblock, rendinput, rs, rulesent;
  char *rstring = NULL, *rtoken = NULL;
  long zbigmess;
  char tempsqdn[(DirSize + 1)], tempserv[(DirSize + 1)], *temp =
    NULL, *temp2 = NULL, fname[DirSize + 1], ttoken[arealength + 1], wild[arealength + 1];
  char *commands[] = {
    "---",                      //  0
    "%Help",                    //  1
    "%List",                    //  2
    "%Query",                   //  3
    "%Notify",                  //  4
    "%Links",                   //  5
    "%Rescan",                  //  6
    "%Passive",                 //  7
    "%Active",                  //  8
    "%Status",                  //  9
    "%Password",                // 10
    "%PktSize",                 // 11
    "%Packer",                  // 12
    "%All",                     // 13
    "+%All",                    // 14
    "-%All",                    // 15
    "%Group",                   // 16
    "+%Group",                  // 17
    "-%Group",                  // 18
    "+",                        // 19
    "-",                        // 20
    "\1",                       // 21
    "* Origin",                 // 22
    "%EList",                   // 23
    "%EFList",                  // 24
    "%Pause",                   // 25
    "%Avail",                   // 26
    "%FAvail",                  // 27
    "%Resume",                  // 28
    "%Address",                 // 29
    "%PKTPass"                  // 30
  };
  struct uplname *areas = NULL, *tareas = NULL;
  struct uplname ttaname, *tname = NULL, *tuname = NULL;
  struct alists *ttlist = NULL;
  struct link *blink = NULL, tblink, *ttblink = NULL;
  struct packer arcdef;
  struct myaddr *taddr = NULL;

  numcomm = 31;
  rescandays = bcfg.rescdays;
  rulesent = bcfg.rulesent;
  if(badlink != 2)
  {
    blink = bcfg.links.chain;
    while(blink)
    {
      if(cmpaddr(&(blink->address), &mfnode) == 0)
        break;
      blink = blink->next;
    }
    if(blink == NULL)           // server() only calls us for known links
      badlink = 2;
    else
    {
      memcpy(&tblink, blink, szlink);
      if(blink->rules == 1)
        rulesent = 1;
      if(blink->rules == 65535ul)
        rulesent = 0;
    }
  }
  logprintf("%s message from %u:%u/%u.%u",
          (mode & 1024) ? "Fake" : "Real", mfnode.zone, mfnode.net, mfnode.node, mfnode.point);
  logwrite(1, 5);
  if(!quiet)
    ccprintf("%s\r\n", logout);
  if(mode & 1024 || mbigmess)
    tempsqd = temppkt;
  else
  {
    mystrncpy(tempsqdn, bcfg.workdir, DirSize);
    mystrncat(tempsqdn, "tempsqd.$$$", 16, DirSize);
    if((tempsqd = (short)sopen(tempsqdn, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
    {
      mystrncpy(errname, tempsqdn, DirSize);
      errexit(2, __FILE__, __LINE__);
    }
  }
//  mystrncpy (tempserv, outbound, DirSize);
  mystrncpy(tempserv, bcfg.workdir, DirSize);
  mystrncat(tempserv, "tempserv.$$$", 16, DirSize);
  if((tempsrv = (short)sopen(tempserv, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
  {
    mystrncpy(errname, tempserv, DirSize);
    errexit(2, __FILE__, __LINE__);
  }
  chsize(tempsrv, 0);
  memset(&bufpkt, 0, szpackmess);
  bufpkt.packtype = 2;
  bufpkt.tozone = bufmess.fromzone;
  bufpkt.tonet = bufmess.fromnet;
  bufpkt.tonode = bufmess.fromnode;
  bufpkt.topoint = bufmess.frompoint;
  bufpkt.fromzone = bufmess.tozone;
  bufpkt.fromnet = bufmess.tonet;
  bufpkt.fromnode = bufmess.tonode;
  bufpkt.frompoint = bufmess.topoint;
  sftime = time(NULL);
  mylocaltime(&sftime, &tmt);
  mystrncpy(tstrtime, asctime(&tmt), 39);
  converttime(tstrtime);
  mystrncpy(bufpkt.datetime, ftstime, 19);
  bufpkt.fromname = (char *)myalloc(36, __FILE__, __LINE__);
  bufpkt.toname = (char *)myalloc(36, __FILE__, __LINE__);
  bufpkt.subj = (char *)myalloc(72, __FILE__, __LINE__);
  mystrncpy(bufpkt.fromname, bcfg.manfrom, 35);
  mystrncpy(bufpkt.toname, bufmess.fromname, 35);
  mystrncpy(bufpkt.subj, bcfg.subj, 71);
  ptolen = strlen(bufpkt.toname);
  pfromlen = strlen(bufpkt.fromname);
  psubjlen = strlen(bufpkt.subj);
  bufpkt.flags = 0x181;
  if(!badlink)
  {
    if(blink->hold == 1)
      bufpkt.flags = 0x381;
    else
      bufpkt.flags = 0x181;
  }
  pbigmess = 1;
  if(!(mode & 1024 || mbigmess))
  {
    if(mtextlen > 0)
      wwrite(tempsqd, bufmess.text, (unsigned short)mtextlen, __FILE__, __LINE__);
    else
    {
      temp = strchr(bufmess.subj, ' ');
      while(temp && ((temp - bufmess.subj) <= msubjlen))
      {
        temp2 = temp;
        while(isspace(*temp2))
          temp2++;
        if(temp2[0] == '-')
        {
          switch (temp2[1])
          {
          case 'L':
          case 'l':
            mywrite(tempsqd, "%List\r", __FILE__, __LINE__);
            break;
          case 'N':
          case 'n':
            mywrite(tempsqd, "%Notify\r", __FILE__, __LINE__);
            break;
          case 'Q':
          case 'q':
            mywrite(tempsqd, "%Query\r", __FILE__, __LINE__);
            break;
          case 'H':
          case 'h':
            mywrite(tempsqd, "%Help\r", __FILE__, __LINE__);
            break;
          }
        }
        temp = strchr(temp2, ' ');
      }
    }
  }
  delctrl(3);
  tail = (char *)myalloc(BufSize, __FILE__, __LINE__);
  sprintf(tail, "\r--- ParToss %s\r", version);
  addorig = 1;
  memcpy(&bufmess, &bufpkt, szpackmess);
  zbigmess = mbigmess;
  mbigmess = 1;
  lseek(tempsqd, 0, SEEK_SET);
  if(badlink)
    goto badrep;
  endinput[0] = 0;
  if(rmbigmess)
    lseek(tempsqd, mtolen + mfromlen + msubjlen + 3, SEEK_SET);
  while(!endinput[0])
  {
    readblock(tempsqd, 0);
    endblock[0] = 0;
    do
    {
      getstring(0);
      gettoken(0);
      if(!strlen(token))
        continue;
      if(maxstr[0] <= BufSize)
        mystrncpy(logout,::string, (unsigned short)maxstr[0]);
      else
        mystrncpy(logout,::string, BufSize);
      logwrite(1, 8);
      for(j = 0; j < numcomm; j++)
        if(strnicmp(token, commands[j], strlen(commands[j])) == 0)
          break;
      if(j == 25)
        j = 7;
      if(j == 28)
        j = 8;
      if(j == 2 && bcfg.asavail)
        j = 26;
      switch (j)
      {
      case 0:
      case 21:
        logprintf("End of message detected");
        logwrite(1, 9);
        goto finish;

      case 1:
        logprintf("Help Request detected");
        logwrite(1, 9);
        makehelp();
        makemsg(tempsrv, "%Help", bcfg.mantmpl);
        chsize(tempsrv, 0);
        lseek(tempsrv, 0, SEEK_SET);
        break;

      case 2:
      case 3:
      case 4:
      case 23:
        dolist((short)(j - 1));
        if(j == 2 && bcfg.asfull)
          goto availtoo;
        break;

      case 5:
        logprintf("Links Request detected");
        logwrite(1, 9);
        gettoken(0);
        tokencpy(logout, BufSize);
        makelinks(logout);
        makemsg(tempsrv, "%Links", bcfg.mantmpl);
        chsize(tempsrv, 0);
        lseek(tempsrv, 0, SEEK_SET);
        break;

      case 6:                  // Рескан эхи
        if(bcfg.rescan)         // рескан разрешён
        {
          if(alog == 0)         // echolog.$$$ не открыт
          {
            mustlog = -1;
            mystrncpy(echologt, bcfg.workdir, DirSize);
            mystrncat(echologt, "echolog.$$$", DirSize, DirSize);
            if((alog =
                (short)sopen(echologt, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
            {                   // не открылся
              mystrncpy(errname, echologt, DirSize);
              errexit(2, __FILE__, __LINE__);
            }
          }
          /*
             print file position
           */
          //logprintf("echolog.$$$ position before truncate = %ld", tell(alog));
          //logwrite(1, 13);

          if(chsize(alog, 0) != 0)
          {
            logprintf("Error truncating %s, error %d", errname, errno);
            logwrite(1, 13);
          };
          lseek(alog, 0, SEEK_SET);

          /*
             print file position
           */
          //logprintf("echolog.$$$ position after truncate = %ld", tell(alog));
          //logwrite(1, 13);

          if(endstring[0])      // а эха-то и не указана!
            break;
          gettoken(0);
          rstring =::string;
          rtoken = token;
          rendstring = endstring[0];
          rendblock = endblock[0];
          rendinput = endinput[0];
          for(l = 0; l < numcomm; l++)  // пробег по строке в поисках %all и %group
            if(strnicmp(token, commands[l], strlen(commands[l])) == 0)
              break;
          switch (l)
          {
          case 0:
          case 1:
          case 2:
          case 3:
          case 4:
          case 5:
          case 6:
          case 7:
          case 8:
          case 9:
          case 10:
          case 11:
          case 12:
          case 15:
          case 18:
          case 19:
          case 20:
          case 21:
          case 22:
          case 23:
          case 24:
          case 25:
          case 26:
          case 27:
          case 28:
          case 29:
            l = -1;
            break;

          case 13:             // %all
          case 14:
            ttlist = rlist;
            while(ttlist)
            {
              for(i = 0; i < ttlist->numlists; i++)
              {
                if(ttlist->alist[i].type == 1)
                {
                  if(bcfg.gric ? (strichr(blink->group, ttlist->alist[i].group) != NULL) :
                                 (strchr(blink->group, ttlist->alist[i].group) != NULL))
                  {
                    inecholog(ttlist->alist[i].areaname);
                  }
                }
              }
              ttlist = ttlist->next;
            }
            break;

          case 16:             // %group
          case 17:
            gettoken(0);
            for(k = 0; k < toklen; k++)
            {
              if(bcfg.gric ? (strichr(blink->group, token[k]) != NULL) : (strchr(blink->group, token[k]) != NULL))
              {
                ttlist = rlist;
                while(ttlist)
                {
                  for(i = 0; i < ttlist->numlists; i++)
                  {
                    if(ttlist->alist[i].type == 1)
                    {
                      if(toupper(ttlist->alist[i].group) == toupper(token[k]))
                      {
                        inecholog(ttlist->alist[i].areaname);
                      }
                    }
                  }
                  ttlist = ttlist->next;
                }
              }
            }
            break;

          default:             // нифига - значит имя эхи или шаблон
            if(toklen)
            {
              tokencpy(wild, (short)((toklen >= arealength) ? (arealength - 1) : toklen));
              temp = strchr(wild, '*');
              if(temp == NULL)
                temp = strchr(wild, '?');
              if(temp)          // шаблон
              {
                ttlist = rlist;
                while(ttlist)
                {
                  for(i = 0; i < ttlist->numlists; i++)
                  {
                    if(ttlist->alist[i].type == 1)
                    {
                      if((wildcard
                          (wild,
                           ttlist->alist[i].areaname) ==
                          0)
                         && (bcfg.
                             gric
                             ? (strichr
                                (blink->group,
                                 ttlist->alist[i].
                                 group) != NULL) : (strchr(blink->group, ttlist->alist[i].group) != NULL)))
                      {
                        inecholog(ttlist->alist[i].areaname);
                      }
                    }
                  }
                  ttlist = ttlist->next;
                }
              }
              else              // обычное имя эхи
              {
                tokencpy(ttoken, arealength - 1);
                inecholog(ttoken);
              }
            }
            break;
          }
          endinput[0] = rendinput;
          endblock[0] = rendblock;
          endstring[0] = rendstring;
          token = rtoken;
          ::string = rstring;
          if(!endstring[0])
          {
            gettoken(0);
            rescandays = (unsigned short)atoi(token);
          }
          rescan = 1;
          rnode = mfnode;
          temprescan = tempsqd;
          logprintf("ReScan Request detected and processed");
          logwrite(1, 9);
          scanbase(echolog, 1);
          tempsqd = temprescan;
        }
        else
        {                       // рескан запрещён
          logprintf("ReScan Request detected but ignored");
          logwrite(1, 9);
        }
        break;

      case 7:
      case 8:
        logprintf("%s Request detected", (j == 7 ? "Passive" : "Active"));
        logwrite(1, 9);
        if(!endstring[0])
        {
          gettoken(0);
          if(strnicmp(token, commands[13], 4) == 0)
            goto sall;
          else if(strnicmp(token, commands[16], 6) == 0)
          {
            gettoken(0);
            if(bcfg.gric ? (strichr(blink->group, *token) != NULL) : (strchr(blink->group, *token) != NULL))
            {
              ttlist = rlist;
              while(ttlist)
              {
                for(i = 0; i < ttlist->numlists; i++)
                {
                  if(ttlist->alist[i].type == 1)
                  {
                    if(toupper(ttlist->alist[i].group) == toupper(*token))
                      addsarea(&areas, &ttaname, ttlist->alist[i].areaname, (j == 7) ? 3 : 4, 1);
                  }
                }
                ttlist = ttlist->next;
              }
            }
          }
          else
          {
            ttlist = rlist;
            while(ttlist)
            {
              for(i = 0; i < ttlist->numlists; i++)
              {
                if(ttlist->alist[i].type == 1)
                {
                  if(strnicmp
                     (ttlist->alist[i].areaname, token,
                      (toklen > strlen(ttlist->alist[i].areaname)) ? toklen : strlen(ttlist->alist[i].areaname)) == 0)
                  {
                    addsarea(&areas, &ttaname, ttlist->alist[i].areaname, (j == 7) ? 3 : 4, 0);
                    goto send;
                  }
                }
              }
              ttlist = ttlist->next;
            }
          }
        }
      sall:
        {
          ttlist = rlist;
          while(ttlist)
          {
            for(i = 0; i < ttlist->numlists; i++)
            {
              if(ttlist->alist[i].type == 1)
              {
                if(bcfg.
                   gric
                   ? (strichr
                      (blink->group,
                       ttlist->alist[i].group) != NULL) : (strchr(blink->group, ttlist->alist[i].group) != NULL))
                {
                  addsarea(&areas, &ttaname, ttlist->alist[i].areaname, (j == 7) ? 3 : 4, 1);
                }
              }
            }
            ttlist = ttlist->next;
          }
        }
      send:
        break;

      case 9:
        logprintf("Status Request detected");
        logwrite(1, 9);
        makestatus(blink);
        makemsg(tempsrv, "%Status", bcfg.mantmpl);
        chsize(tempsrv, 0);
        lseek(tempsrv, 0, SEEK_SET);
        break;

      case 10:
      case 11:
      case 12:
      case 30:
        logprintf("Status change Request detected");
        logwrite(1, 9);
        linkchg = 1;
        gettoken(0);
        if(j == 10)
        {
          if(toklen > 71)
            toklen = 71;
          mystrncpy(tblink.echopass, token, toklen);
          tblink.mask |= 4;
        }
        else
        {
          if(j == 30)
          {
            if(toklen > 8)      // password[9]
              toklen = 8;
            mystrncpy(tblink.password, token, toklen);
            tblink.mask |= 512;
          }
          else
          {
            if(j == 12)
            {
              if(toklen > 9)
                toklen = 9;
              numofarc = (short)(filelength(compset) / szpacker);
              lseek(compset, 0, SEEK_SET);
              for(k = 0; k < numofarc; k++)
              {
                rread(compset, &arcdef, szpacker, __FILE__, __LINE__);
                if((strnicmp(arcdef.name, token, toklen)) == 0 && (strlen(arcdef.name) == toklen))
                  break;
              }
              if(k < numofarc)
              {
                mystrncpy(tblink.packer, token, toklen);
                tblink.mask |= 32;
              }
              else
                mystrncpy(tblink.packer, blink->packer, 9);
            }
            else
            {
              tblink.pktsize = atol(token);
              temp2 = token;
              while(isdigit(*temp2))
                temp2++;
              if(toupper(*temp2) == 'K')
              {
                tblink.pktsize <<= 10;
                temp2++;
              }
              if(*temp2 == ',')
              {
                tblink.arcsize = atol(token);
                temp2 = token;
                while(isdigit(*temp2))
                  temp2++;
                if(toupper(*temp2) == 'K')
                {
                  tblink.arcsize <<= 10;
                  temp2++;
                }
              }
              tblink.mask |= 1;
            }
          }
        }
        break;

      case 13:
      case 14:
      case 15:
        logprintf("%sSubscribe for all echoes Request detected", (j == 15 ? "Un" : ""));
        logwrite(1, 9);
        ttlist = rlist;
        while(ttlist)
        {
          for(i = 0; i < ttlist->numlists; i++)
          {
            if(ttlist->alist[i].type == 1)
            {
              if(bcfg.
                 gric
                 ? (strichr
                    (blink->group,
                     ttlist->alist[i].group) != NULL) : (strchr(blink->group, ttlist->alist[i].group) != NULL))
              {
                addsarea(&areas, &ttaname, ttlist->alist[i].areaname, (j == 15) ? 2 : 1, 1);
              }
            }
          }
          ttlist = ttlist->next;
        }
        break;

      case 16:
      case 17:
      case 18:
        logprintf("%sSubscribe for some groups Request detected", (j == 18 ? "Un" : ""));
        logwrite(1, 9);
        gettoken(0);
        for(k = 0; k < toklen; k++)
        {
          if(bcfg.gric ? (strichr(blink->group, token[k]) != NULL) : (strchr(blink->group, token[k]) != NULL))
          {
            ttlist = rlist;
            while(ttlist)
            {
              for(i = 0; i < ttlist->numlists; i++)
              {
                if(ttlist->alist[i].type == 1)
                {
                  if(toupper(ttlist->alist[i].group) == toupper(token[k]))
                  {
                    addsarea(&areas, &ttaname, ttlist->alist[i].areaname, (j == 18) ? 2 : 1, 1);
                  }
                }
              }
              ttlist = ttlist->next;
            }
          }
        }
        break;

      case 19:
      case 20:
        logprintf("%sSubscribe for echo Request detected", (j == 20 ? "Un" : ""));
        logwrite(1, 9);
        if(isspace(token[1]))
        {
          gettoken(0);
          tokencpy(wild, (short)((toklen >= arealength) ? (arealength - 1) : (toklen)));
        }
        else
          mystrncpy(wild, token + 1, (short)((toklen > arealength) ? (arealength - 1) : (toklen - 1)));
        strupr(wild);
        if(wild[0] && !isspace(wild[0]))
        {
          temp = strchr(wild, '*');
          if(temp == NULL)
            temp = strchr(wild, '?');
          if(temp)
          {
            ttlist = rlist;
            while(ttlist)
            {
              for(i = 0; i < ttlist->numlists; i++)
              {
                if(ttlist->alist[i].type == 1)
                {
                  if((wildcard
                      (wild, ttlist->alist[i].areaname) == 0)
                     && (bcfg.
                         gric
                         ? (strichr
                            (blink->group,
                             ttlist->alist[i].group) != NULL) : (strchr(blink->group, ttlist->alist[i].group) != NULL)))
                  {
                    addsarea(&areas, &ttaname, ttlist->alist[i].areaname, (j == 19) ? 1 : 2, 1);
                  }
                }
              }
              ttlist = ttlist->next;
            }
          }
          else
          {
            mystrncpy(ttoken, wild, arealength);
            addsarea(&areas, &ttaname, ttoken, (j == 19) ? 1 : 2, 0);
          }
        }
        break;

      case 22:
        logprintf("Origin string detected");
        logwrite(1, 9);
        goto finish;

      case 24:
        sort = (short)(bcfg.sort >> 1);
        if(!endstring[0])
        {
          gettoken(0);
          if(toupper(token[0]) == 'N')
            sort = 1;
          else if(toupper(token[0]) == 'G')
            sort = 2;
        }
        logprintf("Extended List as file Request detected");
        logwrite(1, 9);
        makelist(4, sort);
        cclose(&tempsrv, __FILE__, __LINE__);
        mystrncpy(fname, outbound, DirSize);
        mystrncat(fname, "EchoList.", 12, DirSize);
        logout[0] = duotrice[(bcfg.address.chain->node >> 8) & 0x0f];
        logout[1] = duotrice[(bcfg.address.chain->node >> 4) & 0x0f];
        logout[2] = duotrice[(bcfg.address.chain->node) & 0x0f];
        logout[3] = 0;
        mystrncat(fname, logout, 5, DirSize);
        rrename(tempserv, fname);
        addtpack(&mfnode);
        mystrncpy(tpack->name, fname, DirSize);
        tpack->file = tpack->touched = 1;
        memcpy(&tpack->outaddr, &mfnode, szmyaddr);
        // memcpy(&tpack->outaddr,&tpack->fromaddr,szmyaddr);
        if((tempsrv =
            (short)sopen(tempserv, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
        {
          mystrncpy(errname, tempserv, DirSize);
          errexit(2, __FILE__, __LINE__);
        }
        chsize(tempsrv, 0);
        lseek(tempsrv, 0, SEEK_SET);
        break;

      case 26:
      availtoo:
        logprintf("UpLink's Lists Request detected");
        logwrite(1, 9);
        if(bcfg.uplname)
        {
          logprintf("\r\nAvailable areas from all UpLinks:\r\n");
          mywrite(tempsrv, logout, __FILE__, __LINE__);
          tname = bcfg.uplname;
          while(tname)
          {
            tupl = (short)sopen(tname->echolist, O_RDONLY | O_BINARY, SH_DENYNO);
            if(tupl != -1)
            {
              logprintf("\r\nUpLink %u:%u/%u.%u\r\n",
                      tname->upaddr.zone, tname->upaddr.net, tname->upaddr.node, tname->upaddr.point);
              mywrite(tempsrv, logout, __FILE__, __LINE__);
              curr = (unsigned short)rread(tupl, logout, BufSize, __FILE__, __LINE__);
              while(curr)
              {
                wwrite(tempsrv, logout, curr, __FILE__, __LINE__);
                curr = (unsigned short)rread(tupl, logout, BufSize, __FILE__, __LINE__);
              }
              cclose(&tupl, __FILE__, __LINE__);
              mywrite(tempsrv, "\r\n", __FILE__, __LINE__);
            }
            tname = tname->next;
          }
        }
        else
        {
          logprintf("\r\nSubscribe forwards are not allowed\r\n");
          mywrite(tempsrv, logout, __FILE__, __LINE__);
        }
        makemsg(tempsrv, "%Avail", "");
        chsize(tempsrv, 0);
        lseek(tempsrv, 0, SEEK_SET);
        break;

      case 27:
        logprintf("UpLink's Lists as file Request detected");
        logwrite(1, 9);
        if(bcfg.uplname)
        {
          logprintf("\r\nAvailable areas from all UpLinks:\r\n");
          mywrite(tempsrv, logout, __FILE__, __LINE__);
          tname = bcfg.uplname;
          while(tname)
          {
            tupl = (short)sopen(tname->echolist, O_RDONLY | O_BINARY, SH_DENYNO);
            if(tupl != -1)
            {
              logprintf("\r\nUpLink %u:%u/%u.%u\r\n",
                      tname->upaddr.zone, tname->upaddr.net, tname->upaddr.node, tname->upaddr.point);
              mywrite(tempsrv, logout, __FILE__, __LINE__);
              curr = (unsigned short)rread(tupl, logout, BufSize, __FILE__, __LINE__);
              while(curr)
              {
                wwrite(tempsrv, logout, curr, __FILE__, __LINE__);
                curr = (unsigned short)rread(tupl, logout, BufSize, __FILE__, __LINE__);
              }
              cclose(&tupl, __FILE__, __LINE__);
              mywrite(tempsrv, "\r\n", __FILE__, __LINE__);
            }
            tname = tname->next;
          }
          cclose(&tempsrv, __FILE__, __LINE__);
          mystrncpy(fname, outbound, DirSize);
          mystrncat(fname, "uplinks.", 12, DirSize);
          logout[0] = duotrice[(bcfg.address.chain->node >> 8) & 0x0f];
          logout[1] = duotrice[(bcfg.address.chain->node >> 4) & 0x0f];
          logout[2] = duotrice[(bcfg.address.chain->node) & 0x0f];
          logout[3] = 0;
          mystrncat(fname, logout, 5, DirSize);
          rrename(tempserv, fname);
          addtpack(&mfnode);
          mystrncpy(tpack->name, fname, DirSize);
          tpack->file = tpack->touched = 1;
          memcpy(&tpack->outaddr, &mfnode, szmyaddr);
          // memcpy(&tpack->outaddr,&tpack->fromaddr,szmyaddr);
          if((tempsrv =
              (short)sopen(tempserv, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
          {
            mystrncpy(errname, tempserv, DirSize);
            errexit(2, __FILE__, __LINE__);
          }
          chsize(tempsrv, 0);
          lseek(tempsrv, 0, SEEK_SET);
        }
        else
        {
          logprintf("\r\nSubscribe forwards are not allowed\r\n");
          mywrite(tempsrv, logout, __FILE__, __LINE__);
          makemsg(tempsrv, "%Avail", "");
          chsize(tempsrv, 0);
          lseek(tempsrv, 0, SEEK_SET);
        }
        break;

      case 29:
        if(manager)
        {
          gettoken(0);
//            parseaddr(token,&tblink.address,toklen);
          parseaddr(token, &(blink->address), toklen);
          memcpy(&tblink, blink, szlink);
          memcpy(&mfnode, &tblink.address, szmyaddr);
          ttblink = bcfg.links.chain;
          while(ttblink)
          {
            if(cmpaddr(&(ttblink->address), &mfnode) == 0)
              break;
            ttblink = ttblink->next;
          }
          if(ttblink)
            tblink.manager = ttblink->manager;
          else
            tblink.manager = 0;
          logprintf("Switch to address %u:%u/%u.%u detected",
                  tblink.address.zone, tblink.address.net, tblink.address.node, tblink.address.point);
          logwrite(1, 9);
        }
        break;

      default:
        logprintf("Subscribe to echoes Request detected");
        logwrite(1, 9);
        // defblock:
        if(toklen)
        {
          tokencpy(wild, (short)((toklen >= arealength) ? (arealength - 1) : toklen));
          strupr(wild);
          temp = strchr(wild, '*');
          if(temp == NULL)
            temp = strchr(wild, '?');
          if(temp)
          {
            ttlist = rlist;
            while(ttlist)
            {
              for(i = 0; i < ttlist->numlists; i++)
              {
                if(ttlist->alist[i].type == 1)
                {
                  if((wildcard
                      (wild, ttlist->alist[i].areaname) == 0)
                     && (bcfg.
                         gric
                         ? (strichr
                            (blink->group,
                             ttlist->alist[i].group) != NULL) : (strchr(blink->group, ttlist->alist[i].group) != NULL)))
                  {
                    addsarea(&areas, &ttaname, ttlist->alist[i].areaname, 1, 1);
                  }
                }
              }
              ttlist = ttlist->next;
            }
          }
          else
          {
            mystrncpy(ttoken, wild, arealength);
            addsarea(&areas, &ttaname, wild, 1, 0);
          }
        }
        break;
      }
    }
    while(!endblock[0]);
  }
finish:
  if(areas)
  {
    changearea(areas);
    makemsg(tempsrv, "subscribe", bcfg.mantmpl);
    chsize(tempsrv, 0);
    lseek(tempsrv, 0, SEEK_SET);
    tareas = areas;
    while(tareas)
    {
      tname = tareas->next;
//      Here will be sending of rules, if they are present
// /*
      if(rulesent && (tareas->where == 1 || (tareas->where == 4 && tareas->touched)))
      {
        tlist = rlist;
        while(tlist)
        {
          for(carea = 0; carea < tlist->numlists; carea++)
          {
            tcarea = carea;
            if(strnicmp
               (tareas->persarea, tlist->alist[carea].areaname,
                strlen(tareas->persarea)) == 0 && strlen(tlist->alist[carea].areaname) == strlen(tareas->persarea))
            {
              lseek(areaset, tlist->alist[carea].areaoffs, SEEK_SET);
              rread(areaset, newarea, szarea, __FILE__, __LINE__);
              newarea->links.chain = newarea->links.last = NULL;
              newarea->links.numelem = 0;
              mystrncpy(fname, newarea->areafp, DirSize);
              mystrncat(fname, ".sqr", 6, DirSize);
              if(access(fname, 0) == 0)
              {
                if((newarea->sqd.sqr = (short)sopen(fname, O_RDONLY | O_BINARY, SH_DENYNO)) != -1)
                {
                  while((rs = (unsigned short)rread(newarea->sqd.sqr, logout, BufSize, __FILE__, __LINE__)) > 0)
                    wwrite(tempsrv, logout, rs, __FILE__, __LINE__);
                  makemsg(tempsrv, "send rules", "");
                  chsize(tempsrv, 0);
                  lseek(tempsrv, 0, SEEK_SET);
                  cclose(&newarea->sqd.sqr, __FILE__, __LINE__);
                  goto rulesent;
                }
              }
            }
            carea = tcarea;
          }
          tlist = tlist->next;
        }
      }
// */
    rulesent:
      myfree((void **)&tareas, __FILE__, __LINE__);
      tareas = tname;
    }
    chsize(tempsrv, 0);
    lseek(tempsrv, 0, SEEK_SET);
    if(bcfg.uplname && uareas)
    {
      tuname = bcfg.uplname;
      while(tuname)
      {
        isforw = 0;
        tname = uareas;
        while(tname)
        {
          if(!tname->touch)
          {
            if(cmpaddr(&(tuname->upaddr), &(tname->upaddr)) == 0)
            {
              memcpy(&pktaddr, &(tuname->upaddr), szmyaddr);
              logprintf("%s%s\r", (tname->where == 1) ? "+" : "-", tname->persarea);
              mywrite(tempsrv, logout, __FILE__, __LINE__);
              isforw = 1;
              tname->touch = 1;
              // break;
            }
          }
          tname = tname->next;
        }
        if(isforw)
        {
          bufmess.tozone = tuname->upaddr.zone;
          bufmess.tonet = tuname->upaddr.net;
          bufmess.tonode = tuname->upaddr.node;
          bufmess.topoint = tuname->upaddr.point;
          taddr = bcfg.address.chain;
          while(taddr)
          {
            if(taddr->point || bufmess.topoint)
            {
              if((taddr->zone == bufmess.tozone) && (taddr->net == bufmess.tonet) && (taddr->node == bufmess.tonode))
                break;
            }
            else if(taddr->zone == bufmess.tozone)
              break;
            taddr = taddr->next;
          }
          if(taddr == NULL)
            taddr = bcfg.address.chain;
          bufmess.fromzone = taddr->zone;
          bufmess.fromnet = taddr->net;
          bufmess.fromnode = taddr->node;
          bufmess.frompoint = taddr->point;
          mystrncpy(bufmess.fromname, bcfg.manffrom, 35);
          mystrncpy(bufmess.toname, tuname->upname, 35);
          mystrncpy(bufmess.subj, tuname->uppass, 71);
          bufmess.flags = 0x181;
          tnorep = noreport;
          noreport = 0;
          makemsg(tempsrv, "forwarding", "");
          noreport = tnorep;
          chsize(tempsrv, 0);
          lseek(tempsrv, 0, SEEK_SET);
        }
        tuname = tuname->next;
      }
      tareas = uareas;
      while(tareas)
      {
        tname = tareas->next;
        myfree((void **)&tareas, __FILE__, __LINE__);
        tareas = tname;
      }
      uareas = NULL;
      tuname = NULL;
    }
  }
  if(linkchg)
  {
    logprintf("Status change for %u:%u/%u.%u\r\n\r\n",
            blink->address.zone, blink->address.net, blink->address.node, blink->address.point);
    mywrite(tempsrv, logout, __FILE__, __LINE__);
    if(strcmp(tblink.echopass, blink->echopass) != 0)
    {
      logprintf("Password changed to %s\r\n", tblink.echopass);
      mywrite(tempsrv, logout, __FILE__, __LINE__);
    }
    if(strcmp(tblink.packer, blink->packer) != 0)
    {
      logprintf("Archiver changed to %s\r\n", tblink.packer);
      mywrite(tempsrv, logout, __FILE__, __LINE__);
    }
    if(tblink.pktsize != blink->pktsize)
    {
      logprintf("Max packet size changed to %lu\r\n", tblink.pktsize);
      mywrite(tempsrv, logout, __FILE__, __LINE__);
    }
    if(tblink.arcsize != blink->arcsize)
    {
      logprintf("Max archive size changed to %lu\r\n", tblink.arcsize);
      mywrite(tempsrv, logout, __FILE__, __LINE__);
    }
    memcpy(blink, &tblink, szlink);
    changelink(blink);
    makemsg(tempsrv, "Status change", bcfg.mantmpl);
    chsize(tempsrv, 0);
    lseek(tempsrv, 0, SEEK_SET);
  }
badrep:
  if(badlink == 1)
  {
    mystrncpy(bufpkt.subj, "Wrong password!", 71);
    makemsg(tempsrv, "Wrong password!", bcfg.badtmpl);
    chsize(tempsrv, 0);
    lseek(tempsrv, 0, SEEK_SET);
  }
  if(badlink == 2)
  {
    mystrncpy(bufpkt.subj, "Unknown link!", 71);
    makemsg(tempsrv, "Unknown link!", bcfg.badtmpl);
    chsize(tempsrv, 0);
    lseek(tempsrv, 0, SEEK_SET);
  }
  myfree((void **)&tail, __FILE__, __LINE__);
  addorig = 0;
  cclose(&tempsrv, __FILE__, __LINE__);
  unlink(tempserv);
  mbigmess = zbigmess;
  if(!(mode & 1024 || mbigmess))
  {
    cclose(&tempsqd, __FILE__, __LINE__);
    unlink(tempsqdn);
  }
  else
    tempsqd = 0;
}

void makehelp(void)
{
  if(bcfg.help[0])
  {
    if((thelp = (short)sopen(bcfg.help, O_RDONLY | O_BINARY, SH_DENYWR)) == -1)
    {
      mystrncpy(errname, bcfg.help, DirSize);
      errexit(2, __FILE__, __LINE__);
    }
    while((fmax = (unsigned short)rreadz(thelp, pktbuf, buflen, __FILE__, __LINE__)) > 0)
      wwrite(tempsrv, pktbuf, fmax, __FILE__, __LINE__);
    cclose(&thelp, __FILE__, __LINE__);
  }
  else
    mywrite(tempsrv, "\r\nHelp file is not available. Sorry.\r\n", __FILE__, __LINE__);
  flushbuf(tempsrv);
}

void makelist(short type, short sort)   // type: 1 - list, 2 - query,
             // 3 - notify, 4 - extended list
             // sort: 0 - no, 2 - name, 3 - group+name
{
  short i, j, status, dend, numstr, k, gwr = 0;
  char *sstatus[] =
    { "Active", "Unlinked", "Restricted", "Passive", "ReadOnly" }, *descr =
    NULL, *tdesc = NULL, *tdesc2 = NULL, format[arealength + 1], curgr = ' ', glogout[DirSize + 8];
  struct myaddr *link = NULL, tsnd;
  struct link *blink = NULL;
  struct alists *ttlist = NULL;
  struct incl *tgroup = NULL;

  cfname[strlen(cfname) - 1] = 'd';
  memset(glogout, 0, DirSize + 1);
  blink = bcfg.links.chain;
  while(blink)
  {
    if(cmpaddr(&(blink->address), &mfnode) == 0)
      break;
    blink = blink->next;
  }
  if(blink->hide)
    hide = (blink->hide == 1);
  else
    hide = bcfg.hiderestr;
  if(type == 4)
    hide = 1;
  switch (type)
  {
  case 1:
    logprintf("List of all areas on %u:%u/%u.%u\r\n\r\n", node.zone, node.net, node.node, node.point);
    break;
  case 2:
    mystrncpy(logout, "List of areas You are connected to\r\n\r\n", BufSize);
    break;
  case 3:
    mystrncpy(logout, "List of available areas You aren't connected to\r\n\r\n", BufSize);
    break;
  case 4:
    mystrncpy(logout, "", BufSize);
    break;
  }
  mywrite(tempsrv, logout, __FILE__, __LINE__);
  if(sort)
    areasort(sort);
  ttlist = rlist;
  while(ttlist)
  {
    for(j = 0; j < ttlist->numlists; j++)
    {
      if(ttlist->alist[j].type == 1)
      {
        lseek(areaset, ttlist->alist[j].areaoffs, SEEK_SET);
        rread(areaset, newarea, szarea, __FILE__, __LINE__);
        newarea->links.chain = newarea->links.last = NULL;
        newarea->links.numelem = 0;
        if(bcfg.gric ? (strichr(bcfg.hides, newarea->group) == NULL) : (strchr(bcfg.hides, newarea->group) == NULL))
        {
          for(i = 0; i < newarea->numlinks; i++)
          {
            rread(areaset, &tsnd, szmyaddr, __FILE__, __LINE__);
            addaddr(&(newarea->links), &tsnd);
          }
          if(bcfg.
             gric ? (strichr(blink->group, newarea->group) == NULL) : (strchr(blink->group, newarea->group) == NULL))
            status = 2;
          else
          {
            link = newarea->links.chain;
            while(link)
            {
              if(cmpaddr(link, &mfnode) == 0)
                break;
              link = link->next;
            }
            if(link)
            {
              if(link->deny)
                goto nextarea;
              if(link->passive)
                status = 3;
              else
              {
                if(link->rdonly)
                  status = 4;
                else
                  status = 0;
              }
            }
            else
            {
              /*
                 if(strchr(blink->rog,newarea->group))
                 status=4;
                 else
               */
              status = 1;
            }
          }
          if(!(status == 2 && hide))
          {
            if(sort == 2)
            {
              if(bcfg.gric ? toupper(newarea->group) != toupper(curgr) : (newarea->group != curgr))
              {
                tgroup = bcfg.tgroup;
                while(tgroup)
                {
                  if(bcfg.gric ? toupper(newarea->group) == toupper(tgroup->group) : (newarea->group == tgroup->group))
                  {
                    sprintf(glogout, "\r\n%s\r\n\r\n", tgroup->name);
//                    mywrite(tempsrv,logout,__FILE__,__LINE__);
                    curgr = tgroup->group;
                    gwr = 0;
                    goto groupwritten;
                  }
                  tgroup = tgroup->next;
                }
              }
            }
          groupwritten:
            mystrncpy(format, newarea->areaname, arealength);
            for(k = (short)strlen(format); k < maxtaglen; k++)
              format[k] = ' ';
            format[maxtaglen] = 0;
            if(ttlist->alist[j].desclen)
            {
              lseek(areadesc, ttlist->alist[j].descoffs, SEEK_SET);
              descr = (char *)myalloc((ttlist->alist[j].desclen + 1), __FILE__, __LINE__);
              rread(areadesc, descr, (unsigned short)(ttlist->alist[j].desclen + 1), __FILE__, __LINE__);
            }
            else
            {
              descr = (char *)myalloc((strlen(bcfg.mandesc) + 1), __FILE__, __LINE__);
              mystrncpy(descr, bcfg.mandesc, (short)strlen(bcfg.mandesc));
            }
            if(type == 4)
            {
              if(!gwr)
              {
                mywrite(tempsrv, glogout, __FILE__, __LINE__);
                gwr = 1;
              }
              logprintf("%s %s\r\n", format, descr);
              mywrite(tempsrv, logout, __FILE__, __LINE__);
            }
            if(type == 1)
            {
              if(!bcfg.manlen)
              {
                if(!gwr)
                {
                  mywrite(tempsrv, glogout, __FILE__, __LINE__);
                  gwr = 1;
                }
                logprintf("%s %-10s [%c] %s\r", format, sstatus[status], newarea->group, descr);
                mywrite(tempsrv, logout, __FILE__, __LINE__);
              }
              else
              {
                dend = 0;
                numstr = 0;
                tdesc = descr;
                while(!dend)
                {
                  if(!numstr)
                  {
                    if(!gwr)
                    {
                      mywrite(tempsrv, glogout, __FILE__, __LINE__);
                      gwr = 1;
                    }
                    logprintf("%s %-10s [%c] ", format, sstatus[status], newarea->group);
                    numstr = 1;
                  }
                  else
                  {
                    memset(logout, ' ', maxtaglen + 16);
                    logout[maxtaglen + 16] = 0;
                  }
                  if(strlen(tdesc) <= (bcfg.manlen - maxtaglen - 16))
                  {
                    mystrncat(logout, tdesc, (short)(strlen(tdesc) + 1), BufSize);
                    mystrncat(logout, "\r", 2, BufSize);
                    dend = 1;
                  }
                  else
                  {
                    tdesc2 = tdesc + bcfg.manlen - maxtaglen - 16;
                    while((tdesc2 > tdesc) && (*tdesc2 != ' '))
                      tdesc2--;
                    if(tdesc2 == tdesc)
                    {
                      mystrncat(logout, tdesc, (short)(bcfg.manlen - maxtaglen - 15), BufSize);
                      tdesc += bcfg.manlen - maxtaglen - 16;
                    }
                    else
                    {
                      mystrncat(logout, tdesc, (short)(tdesc2 - tdesc + 1), BufSize);
                      tdesc = tdesc2;
                    }
                    mystrncat(logout, "\r", 2, BufSize);
                    while(*tdesc && isspace(*tdesc))
                      tdesc++;
                  }
                  mywrite(tempsrv, logout, __FILE__, __LINE__);
                }
              }
            }
            else
            {
              if((type == 2 && (status == 0 || status == 4)) || (type == 3 && (status == 1 || status == 3)))
              {
                if(!gwr)
                {
                  mywrite(tempsrv, glogout, __FILE__, __LINE__);
                  gwr = 1;
                }
                if(!bcfg.manlen)
                {
                  switch (status)
                  {
                  case 0:
                  case 1:
                    logprintf("%s [%c] %s\r", format, newarea->group, descr);
                    break;
                  case 3:
                    logprintf("%s (%c) %s\r", format, newarea->group, descr);
                    break;
                  case 4:
                    logprintf("%s {%c} %s\r", format, newarea->group, descr);
                    break;
                  }
                  mywrite(tempsrv, logout, __FILE__, __LINE__);
                }
                else
                {
                  dend = 0;
                  numstr = 0;
                  tdesc = descr;
                  while(!dend)
                  {
                    if(!numstr)
                    {
                      logprintf("%s [%c] ", format, newarea->group);
                      numstr = 1;
                    }
                    else
                    {
                      memset(logout, ' ', maxtaglen + 6);
                      logout[maxtaglen + 6] = 0;
                    }
                    if(strlen(tdesc) <= (bcfg.manlen - maxtaglen - 6))
                    {
                      mystrncat(logout, tdesc, (short)(strlen(tdesc) + 1), BufSize);
                      mystrncat(logout, "\r", 2, BufSize);
                      dend = 1;
                    }
                    else
                    {
                      tdesc2 = tdesc + bcfg.manlen - maxtaglen - 6;
                      while((tdesc2 > tdesc) && (*tdesc2 != ' '))
                        tdesc2--;
                      if(tdesc2 == tdesc)
                      {
                        mystrncat(logout, tdesc, (short)(bcfg.manlen - maxtaglen - 5), BufSize);
                        tdesc += bcfg.manlen - maxtaglen - 6;
                      }
                      else
                      {
                        mystrncat(logout, tdesc, (short)(tdesc2 - tdesc + 1), BufSize);
                        tdesc = tdesc2;
                      }
                      mystrncat(logout, "\r", 2, BufSize);
                      while(*tdesc && isspace(*tdesc))
                        tdesc++;
                    }
                    mywrite(tempsrv, logout, __FILE__, __LINE__);
                  }
                }
              }
            }
            myfree((void **)&descr, __FILE__, __LINE__);
            descr = NULL;
          }
        nextarea:
          deladdr(&(newarea->links));
        }
      }
    }
    ttlist = ttlist->next;
  }
  mywrite(tempsrv, "\r\n", __FILE__, __LINE__);
  flushbuf(tempsrv);
}

void makestatus(struct link *blink)
{
  short k, numofarc;
  struct packer arcdef;

  logprintf("Status of Your station\r\n\r\n");
  mywrite(tempsrv, logout, __FILE__, __LINE__);
  logprintf("Address - %u:%u/%u.%u\r", blink->address.zone,
          blink->address.net, blink->address.node, blink->address.point);
  mywrite(tempsrv, logout, __FILE__, __LINE__);
  logprintf("AutoCreate from Your station - %s\r", (blink->create == 1) ? "enabled" : "disabled");
  mywrite(tempsrv, logout, __FILE__, __LINE__);
  logprintf("Put on hold ArcMail to You - %s\r", (blink->hold == 1) ? "yes" : "no");
  mywrite(tempsrv, logout, __FILE__, __LINE__);
  if(blink->autoadd)
  {
    logprintf("Auto subscribing on echoes with mask %s\r", blink->crmask);
    mywrite(tempsrv, logout, __FILE__, __LINE__);
  }
  if(blink->pktsize)
  {
    logprintf("Max packet size - %lu\r", blink->pktsize);
    mywrite(tempsrv, logout, __FILE__, __LINE__);
  }
  if(blink->arcsize)
  {
    logprintf("Max archive size - %lu\r", blink->arcsize);
    mywrite(tempsrv, logout, __FILE__, __LINE__);
  }
  logprintf("Archiver used - %s\r", blink->packer);
  mywrite(tempsrv, logout, __FILE__, __LINE__);
  logprintf("Password for Echo Manager - %s\r", blink->echopass);
  mywrite(tempsrv, logout, __FILE__, __LINE__);
  logprintf("Echo groups available to You - %s\r", blink->group);
  mywrite(tempsrv, logout, __FILE__, __LINE__);

  logprintf("List of available archivers:\r");
  mywrite(tempsrv, logout, __FILE__, __LINE__);
//  cfname[strlen(cfname)-1]='c';
//  if((arccfb=sopen(cfname,O_RDONLY|O_BINARY,SH_DENYWR))==-1) errexit(2,__FILE__,__LINE__);
  numofarc = (short)(filelength(compset) / szpacker);
  lseek(compset, 0, SEEK_SET);
  for(k = 0; k < numofarc; k++)
  {
    rread(compset, &arcdef, szpacker, __FILE__, __LINE__);
    logprintf("%s ", arcdef.name);
    mywrite(tempsrv, logout, __FILE__, __LINE__);
  }
  logprintf("\r");
  mywrite(tempsrv, logout, __FILE__, __LINE__);
//  cclose(&arccfb,__FILE__,__LINE__);
  mywrite(tempsrv, "\r\n", __FILE__, __LINE__);
  flushbuf(tempsrv);
}

void makelinks(char *areaname)
{
  short i, j;
  struct myaddr tsnd;
  char aname[arealength + 1];
  struct alists *ttlist = NULL;

  mystrncpy(aname, areaname, arealength);
  ttlist = rlist;
  while(ttlist)
  {
    for(j = 0; j < ttlist->numlists; j++)
    {
      i = (short)strlen(ttlist->alist[j].areaname);
      if(i < strlen(aname))
        i = (short)strlen(aname);
      if(strnicmp(ttlist->alist[j].areaname, aname, i) == 0)
      {
        lseek(areaset, ttlist->alist[j].areaoffs, SEEK_SET);
        rread(areaset, newarea, szarea, __FILE__, __LINE__);
        logprintf(
                "Area %s on %u:%u/%u.%u is subscribed to:\r\n\r\n",
                aname, newarea->myaka.zone, newarea->myaka.net, newarea->myaka.node, newarea->myaka.point);
        mywrite(tempsrv, logout, __FILE__, __LINE__);
        for(i = 0; i < newarea->numlinks; i++)
        {
          rread(areaset, &tsnd, szmyaddr, __FILE__, __LINE__);
          if(!tsnd.deny)
          {
            logprintf("%u:%u/%u.%u%s%s\r\n", tsnd.zone,
                    tsnd.net, tsnd.node, tsnd.point,
                    tsnd.rdonly ? " (Read-only)" : "", tsnd.passive ? " (Passive)" : "");
            mywrite(tempsrv, logout, __FILE__, __LINE__);
          }
        }
        break;
      }
    }
    ttlist = ttlist->next;
  }
  mywrite(tempsrv, "\r\n", __FILE__, __LINE__);
  flushbuf(tempsrv);
}

void changearea(struct uplname *areas)
{
  struct uplname *tname = NULL, utarea, *tuplink = NULL, *tareas = NULL;
  struct uplname *ttname = NULL;
  struct link *blink = NULL;
  struct myaddr tpktaddr;
  short tfound;
  short i;

  mystrncpy(logout, "Report of areas add/remove\r\n\r\n", BufSize);
  mywrite(tempsrv, logout, __FILE__, __LINE__);
fordelarea:
  chareacfg(areas, mainconf);
  tincl = bcfg.incl;
  while(tincl)
  {
    chareacfg(areas, tincl->name);
    tincl = tincl->next;
  }
  blink = bcfg.links.chain;
  while(blink)
  {
    if(cmpaddr(&(blink->address), &mfnode) == 0)
      break;
    blink = blink->next;
  }
  tname = areas;
  while(tname)
  {
    if(tname->found != 1)
    {
      tfound = 0;
      if(tname->where == 1 && !blink->noforward)
      {
        tuplink = bcfg.uplname;
        while(tuplink)
        {
          if(tname->found == 2 || tname->found == 5)
          {
            //1
            tlist = rlist;
            while(tlist)
            {
              for(i = 0; i < tlist->numlists; i++)
              {
                if((strnicmp
                    (tname->persarea, tlist->alist[i].areaname,
                     strlen(tname->persarea)) == 0) && strlen(tname->persarea) == strlen(tlist->alist[i].areaname))
                  goto delfound;
              };
              tlist = tlist->next;
            };
          delfound:
            if(tlist == NULL)
            {
              tokencpy(errname, arealength);
              errexit(5, __FILE__, __LINE__);
            };
            lseek(areaset, tlist->alist[i].areaoffs, SEEK_SET);
            rread(areaset, newarea, szarea, __FILE__, __LINE__);
            //2
            ttname = bcfg.uplname;
            while(ttname)
            {
              if(cmpaddr(&ttname->upaddr, newarea->links.chain) == 0)
                break;
              ttname = ttname->next;
            };
            //3
            if(ttname)
              if(!seekarea(bcfg.dalist, tname->persarea))
                if(tfound = seekarea(ttname->echolist, tname->persarea))
                {
                  tuplink = ttname;
                  if(tname->found == 2)
                  {
                    tname->found = 3;
                    goto fordelarea;
                  };
                };
          };

          if(!seekarea(bcfg.dalist, tname->persarea))
            if(tfound = seekarea(tuplink->echolist, tname->persarea))
            {
              if(tname->found == 2)
              {
                tname->found = 4;
                goto fordelarea;
              };

              if(tname->found > 5)
                goto next;      //continue;

              if(tname->found < 5)
              {
                logprintf("Area %s added\r\n", tname->persarea);
                mywrite(tempsrv, logout, __FILE__, __LINE__);
              };

              memcpy(&utarea, tuplink, sizeof(struct uplname));
              mystrncpy(utarea.persarea, tname->persarea, arealength - 1);
              utarea.where = 1;
//            memcpy(&utarea.upaddr,&tuplink->upaddr,szmyaddr);
              if(uareas == NULL)
              {
                uareas = (struct uplname *)myalloc(sizeof(struct uplname), __FILE__, __LINE__);
                tareas = uareas;
              }
              else
              {
                tareas = uareas;
                while(tareas->next)
                  tareas = tareas->next;
                tareas->next = (struct uplname *)myalloc(sizeof(struct uplname), __FILE__, __LINE__);
                tareas = tareas->next;
              }
              memcpy(tareas, &utarea, sizeof(struct uplname));
              tareas->touch = 0;
              tareas->next = NULL;
              memcpy(&ufnode, &tuplink->upaddr, szmyaddr);
              memcpy(&tpktaddr, &pktaddr, szmyaddr);
              memcpy(&pktaddr, &tuplink->upaddr, szmyaddr);
              if(tname->found < 5)
                createarea(tname->persarea, 3, &tuplink->upaddr);
              memcpy(&pktaddr, &tpktaddr, szmyaddr);
              if(tname->found > 4)
              {
                tname->found = 6;
                goto fordelarea;
              };
              if(tname->found == 4 || tname->found == 0)
                tname->found = 7;
              goto next;
            }
          tuplink = tuplink->next;
        }
      }
      if(tname->found != 8)
      {
        logprintf("Area %s not found\r\n", tname->persarea);
        mywrite(tempsrv, logout, __FILE__, __LINE__);
      }
      if(tname->found == 2)
        tname->found = 8;
    }
  next:
    tname = tname->next;
  }
}

short seekarea(char *echolist, char *area)
{
  short alist;

//  char tdesc[128];
  alist = mysopen(echolist, 2, __FILE__, __LINE__);
  if(alist == -1)
    return 0;
  mystrncpy(confile, echolist, DirSize);
  lineno[2] = 0;
  endinput[2] = 0;
  while(!endinput[2])
  {
    readblock(alist, 2);
    endblock[2] = 0;
    do
    {
      getstring(2);
      gettoken(2);
      if(strnicmp(token, area, strlen(area)) == 0 && strlen(area) == toklen)
      {
//        gettoken(2);
//        tokencpy(tdesc,toklen);
        cclose(&alist, __FILE__, __LINE__);
        return 1;
      }
    }
    while(!endblock[2]);
    lineno[2] += numcr[2];
  }
  cclose(&alist, __FILE__, __LINE__);
  return 0;
}

void chareacfg(struct uplname *areas, char *file)
{
  short linked, nowork, i = 0, m = 0;
  char bakname[(DirSize + 1)], tbakname[(DirSize + 1)], tgroup, *descr = NULL, *temp = NULL;
  struct myaddr *link = NULL, tsnd;
  struct link *blink = NULL;
  struct addrchain lchain;
  struct uplname *tname = NULL, *ttname = NULL, utarea /*,*tareas=NULL */ ;

  temptoken = NULL;
  setf = mysopen(file, 0, __FILE__, __LINE__);
  mystrncpy(tbakname, file, DirSize);
  tbakname[strlen(tbakname) - 3] = '_';
  if((prttemp = (short)sopen(tbakname, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
  {
    mystrncpy(errname, tbakname, DirSize);
    errexit(2, __FILE__, __LINE__);
  }
  chsize(prttemp, 0);
  cfname[strlen(cfname) - 1] = 'd';
  lseek(areaset, 0, SEEK_SET);
  blink = bcfg.links.chain;
  while(blink)
  {
    if(cmpaddr(&(blink->address), &mfnode) == 0)
      break;
    blink = blink->next;
  }
  endinput[0] = 0;
  while(!endinput[0])
  {
    readblock(setf, 0);
    endblock[0] = 0;
    do
    {
      getstring(0);
      gettoken(0);
      if(strnicmp(token, "EchoArea", 8) == 0)
      {
        gettoken(0);
        linked = nowork = 0;
        tname = areas;
        while(tname)
        {
          if(strnicmp(token, tname->persarea, toklen) == 0 && toklen == strlen(tname->persarea))
            break;
          tname = tname->next;
        }
        if(tname)
        {
          if(tname->found == 7 || tname->found == 1)
          {
            wwrite(prttemp,::string, maxstr2[0], __FILE__, __LINE__);
            continue;
          };
          if(tname->found == 6)
            tname->found = 7;
          if(!tname->found)
            tname->found = 1;
          tlist = rlist;
          while(tlist)
          {
            for(i = 0; i < tlist->numlists; i++)
              if(stricmp(tlist->alist[i].areaname, tname->persarea) == 0)
                goto nfound;
            tlist = tlist->next;
          }
        nfound:
          if(tlist == NULL)
          {
            mystrncpy(errname, tname->persarea, DirSize);
            errexit(5, __FILE__, __LINE__);
          }
          lseek(areaset, tlist->alist[i].areaoffs, SEEK_SET);
          rread(areaset, newarea, szarea, __FILE__, __LINE__);
          if(tlist->alist[i].desclen)
          {
            lseek(areadesc, tlist->alist[i].descoffs, SEEK_SET);
            descr = (char *)myalloc((tlist->alist[i].desclen + 1), __FILE__, __LINE__);
            rread(areadesc, descr, (unsigned short)(tlist->alist[i].desclen + 1), __FILE__, __LINE__);
          }
          else
            descr = NULL;
          newarea->links.chain = newarea->links.last = NULL;
          newarea->links.numelem = 0;

/*
          for(i=0;i<newarea->numlinks;i++)
           {
            rread(areaset,&tsnd,szmyaddr,__FILE__,__LINE__);
            addaddr(&(newarea->links),&tsnd);
           }
*/

          temptoken = token;
          temptoklen = toklen;
          gettoken(0);
          while(!endstring[0])
          {
            gettoken(0);
            memset(&tsnd, 0, szmyaddr);
            switch (token[0])
            {
            case '-':
              switch (token[1])
              {
              case 'p':
              case 'P':
                temp = token + 2;
                parseaddr(temp, &(newarea->myaka), (short)(toklen - 2));
                break;

              case 'x':
              case 'X':
              case 'y':
              case 'Y':
              case 'z':
              case 'Z':
                temp = token + 1;
                for(m = 0; m < 3; m++)
                {
                  if(toupper(temp[m]) == 'X')
                    tsnd.rdonly = 1;
                  else if(toupper(temp[m]) == 'Y')
                    tsnd.passive = 1;
                  else if(toupper(temp[m]) == 'Z')
                    tsnd.rdonly = tsnd.passive = tsnd.deny = 1;
                  else
                    break;
                }
                temp += m;
                parseaddr(temp, &tsnd, (short)(toklen - 2));
                if(tsnd.zone)
                {
                  if(addaddr(&(newarea->links), &tsnd))
                    newarea->numlinks++;
                }
                break;
              }
              break;
            default:
              if(token[0] != '.' || isdigit(token[1]))
              {
                parseaddr(token, &tsnd, toklen);
                if(tsnd.zone)
                  if(addaddr(&(newarea->links), &tsnd))
                    newarea->numlinks++;
              }
              break;
            }
          }
          token = temptoken;
          toklen = temptoklen;
          endstring[0] = 0;

          tgroup = newarea->group;
          link = newarea->links.chain;
          while(link)
          {
            if(cmpaddr(link, &mfnode) == 0)
              break;
            link = link->next;
          }
          if(link)
          {
            if(link->deny)
            {
              wwrite(prttemp,::string, maxstr2[0], __FILE__, __LINE__);
              goto nextarea2;
            }
            if(link->passive)
              linked = 2;
            else
              linked = 1;
          }
//          deladdr(&(newarea->links));
          if(bcfg.gric ? (strichr(blink->group, tgroup) == NULL) : (strchr(blink->group, tgroup) == NULL))
          {
            if(!tname->wild)
            {
              logprintf("Area %s is not available for You\r\n", tname->persarea);
              mywrite(tempsrv, logout, __FILE__, __LINE__);
              wwrite(prttemp,::string, maxstr2[0], __FILE__, __LINE__);
            }
          }
          else
          {
            if(tname->where == 1 && linked)
            {
              nowork = 1;
              if(!tname->wild)
              {
                logprintf("Area %s already connected for You\r\n", tname->persarea);
                mywrite(tempsrv, logout, __FILE__, __LINE__);
              }
            }
            if(tname->where == 2 && !linked)
            {
              nowork = 1;
              if(!tname->wild)
              {
                logprintf("Area %s is not connected for You\r\n", tname->persarea);
                mywrite(tempsrv, logout, __FILE__, __LINE__);
              }
            }
            if(tname->where == 3)
            {
              if(linked == 2)
              {
                if(!tname->wild)
                {
                  logprintf("Area %s is already passive for You\r\n", tname->persarea);
                  mywrite(tempsrv, logout, __FILE__, __LINE__);
                }
              }
              if(linked != 1)
                nowork = 1;
            }
            if(tname->where == 4)
            {
              if(linked == 1)
              {
                if(!tname->wild)
                {
                  logprintf("Area %s is already active for You\r\n", tname->persarea);
                  mywrite(tempsrv, logout, __FILE__, __LINE__);
                }
              }
              if(linked != 2)
                nowork = 1;
            }
            if(!nowork)
            {
              memcpy(&defaddr, &(newarea->myaka), szmyaddr);
              lchain.chain = lchain.last = NULL;
              lchain.numelem = 0;
              link = newarea->links.chain;
              while(link)
              {
                if(cmpaddr(link, &mfnode) == 0)
                  switch (tname->where)
                  {
                  case 1:
                    break;
                  case 2:
                    break;
                  case 3:
                    link->passive = 1;
                    break;
                  case 4:
                    if(link->passive)
                      tname->touched = 1;
                    else
                      tname->touched = 0;
                    link->passive = 0;
                    break;
                  }
                if(tname->where != 2 || cmpaddr(link, &mfnode))
                  addaddr(&lchain, link);
                link = link->next;
              }
              deladdr(&(newarea->links));
              link = lchain.chain;
              while(link)
              {
                addaddr(&(newarea->links), link);
                link = link->next;
              }
              deladdr(&lchain);
              if(tname->where == 1)
              {
                if(blink->rog[0] && bcfg.gric ? (strichr(blink->rog, tgroup)) : (strchr(blink->rog, tgroup)))
                  mfnode.rdonly = 1;
                else
                  mfnode.rdonly = 0;
                addaddr(&newarea->links, &mfnode);
              }
              if(!bcfg.uplname || blink->noforward ||
                 !(newarea->passthr && (newarea->links.numelem == 1)) || !bcfg.killorph)
              {
                temp = strstr(::string, "-$");
                if(temp)
                {
                  wwrite(prttemp,::string, (unsigned short)(temp -::string + 2), __FILE__, __LINE__);
                  writearea(prttemp, newarea, descr, 2);
                }
                else
                  wwrite(prttemp,::string, maxstr2[0], __FILE__, __LINE__);
                mystrncpy(logout,::string + maxstr[0], (short)(maxstr2[0] - maxstr[0]));
                mywrite(prttemp, logout, __FILE__, __LINE__);
              }
              else
              {
                delorphn(&utarea, ttname, descr);
              }
              switch (tname->where)
              {
              case 1:
                logprintf("Area %s %s\r\n", tname->persarea, "added");
                break;
              case 2:
                logprintf("Area %s %s\r\n", tname->persarea, "deleted");
                break;
              case 3:
                logprintf("Area %s %s\r\n", tname->persarea, "passivated");
                break;
              case 4:
                logprintf("Area %s %s\r\n", tname->persarea, "activated");
                break;
              }
              mywrite(tempsrv, logout, __FILE__, __LINE__);
            }
            else
            {
              goto delorphb;
            }
          }
        nextarea2:
          if(descr)
            myfree((void **)&descr, __FILE__, __LINE__);
        }
        else
        {
        delorphb:
          if(bcfg.killorph)
          {
            tlist = rlist;
            while(tlist)
            {
              for(i = 0; i < tlist->numlists; i++)
              {
                if((strnicmp
                    (token, tlist->alist[i].areaname, toklen) == 0) && toklen == strlen(tlist->alist[i].areaname))
                  goto nfound3;
              }
              tlist = tlist->next;
            }
          nfound3:
            if(tlist == NULL)
            {
              tokencpy(errname, arealength);
              errexit(5, __FILE__, __LINE__);
            }
            lseek(areaset, tlist->alist[i].areaoffs, SEEK_SET);
            rread(areaset, newarea, szarea, __FILE__, __LINE__);
            /*
               if(tlist->alist[i].desclen)
               {
               lseek(areadesc,tlist->alist[i].descoffs,SEEK_SET);
               descr=(char *)myalloc(tlist->alist[i].desclen+1,__FILE__,__LINE__);
               rread(areadesc,descr,tlist->alist[i].desclen+1,__FILE__,__LINE__);
               }
               else
               descr=NULL;
               newarea->links.chain=newarea->links.last=NULL;
               newarea->links.numelem=0;
               for(i=0;i<newarea->numlinks;i++)
               {
               rread(areaset,&tsnd,szmyaddr,__FILE__,__LINE__);
               addaddr(&(newarea->links),&tsnd);
               }
               tgroup=newarea->group;
             */
            /*
               link=newarea->links.chain;
               while(link)
               {
               if(cmpaddr(link,&mfnode)==0)
               break;
               link=link->next;
               }
             */
            if(newarea->passthr && (newarea->numlinks <= 1) && bcfg.uplname && !blink->noforward)
              delorphn(&utarea, ttname, descr);
            else
              wwrite(prttemp,::string, maxstr2[0], __FILE__, __LINE__);
          }
          else
            wwrite(prttemp,::string, maxstr2[0], __FILE__, __LINE__);
        }
      }
      else
      {
        if(strnicmp(token, "DeletedArea", 11) == 0 && toklen == 11)
        {
          gettoken(0);
          gettoken(0);
          tname = areas;
          while(tname)
          {
            if((strnicmp(token, tname->persarea, toklen) == 0) && (toklen == strlen(tname->persarea)))
              break;
            tname = tname->next;
          };
          if(tname)
          {
            switch (tname->found)
            {
            case 0:
              curtpos[0] = 0;
              gettoken(0);
              if(!delkill(0))
                tname->found = 2;
              break;
            case 1:
            case 2:
            case 8:
              wwrite(prttemp,::string, maxstr2[0], __FILE__, __LINE__);
              break;
            case 3:            //restored from deleted
              mywrite(prttemp, "EchoArea   ", __FILE__, __LINE__);
              wwrite(prttemp, token, maxstr2[0] - curtpos[0] + toklen, __FILE__, __LINE__);
              logprintf("Deleted Area %s restored to EchoArea by Echo Manager", tname->persarea);
              logwrite(1, 6);
              if((crtrep = (short)sopen(crtreprt, O_RDWR | O_BINARY, SH_DENYWR)) == -1)
              {
                if((crtrep =
                    (short)sopen(crtreprt, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
                {
                  mystrncpy(errname, crtreprt, DirSize);
                  errexit(2, __FILE__, __LINE__);
                }
              }
              lseek(crtrep, 0, SEEK_END);
              mywrite(crtrep, logout, __FILE__, __LINE__);
              mywrite(crtrep, "\r\n", __FILE__, __LINE__);
              cclose(&crtrep, __FILE__, __LINE__);
              tname->found = 5;
              break;
            case 4:            //kill&create
              curtpos[0] = 0;
              gettoken(0);
              gettoken(0);
              delkill(1);
              break;
            };
          }
          else
          {
            curtpos[0] = 0;
            gettoken(0);
            delkill(0);
          }
        }
        else
          wwrite(prttemp,::string, maxstr2[0], __FILE__, __LINE__);
      }
    }
    while(!endblock[0]);
  }
  cclose(&prttemp, __FILE__, __LINE__);
  cclose(&setf, __FILE__, __LINE__);
  mystrncpy(bakname, file, DirSize);
  temp = strchr(bakname, '.');
  if(temp)
    mystrncpy(temp, ".bak", 5);
  else
    mystrncat(bakname, ".bak", 5, DirSize);
  rrename(file, bakname);
  rrename(tbakname, file);
}

void changelink(struct link *blink)
{
  chlinkcfg(blink, mainconf);
  tincl = bcfg.incl;
  while(tincl)
  {
    chlinkcfg(blink, tincl->name);
    tincl = tincl->next;
  }
}

void chlinkcfg(struct link *blink, char *file)
{
  short prttemp;
  char bakname[(DirSize + 1)], tbakname[(DirSize + 1)], tstyle[4], *temp = NULL, tstr[96], *mas = "0000";

  setf = mysopen(file, 0, __FILE__, __LINE__);
  mystrncpy(tbakname, file, DirSize);
  tbakname[strlen(tbakname) - 3] = '_';
  if((prttemp = (short)sopen(tbakname, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
  {
    mystrncpy(errname, tbakname, DirSize);
    errexit(2, __FILE__, __LINE__);
  }
  chsize(prttemp, 0);
  endinput[0] = 0;
  while(!endinput[0])
  {
    readblock(setf, 0);
    endblock[0] = 0;
    do
    {
      getstring(0);
      gettoken(0);
      if((strnicmp(token, "Link", 4) == 0 && toklen == 4) || (strnicmp(token, "LinkManager", 11) == 0 && toklen == 11))
      {
        gettoken(0);
        parseaddr(token, &defaddr, toklen);
        if((cmpaddr(&(blink->address), &defaddr) == 0) && (blink->written == 0))
        {
          tstyle[0] = tstyle[1] = tstyle[2] = tstyle[3] = 0;
          switch (blink->style)
          {
          case 1:
            tstyle[0] = '+';
            tstyle[1] = 'S';
            break;
          case 2:
            tstyle[0] = '+';
            tstyle[1] = 'X';
            break;
          case 65534u:
            tstyle[0] = '-';
            tstyle[1] = 'X';
            break;
          case 65535u:
            tstyle[0] = '-';
            tstyle[1] = 'S';
            break;
          }
          tstyle[2] = ' ';
          logprintf("%s %u:%u/%u.%u ",
                  blink->manager ? "LinkManager" : "Link",
                  blink->address.zone, blink->address.net, blink->address.node, blink->address.point);
          if(blink->mask & 256)
          {
            sprintf(tstr, "~\"%s\" ", blink->name);
            mystrncat(logout, tstr, (unsigned short)(strlen(tstr) + 1), BufSize);
          }
          if(blink->mask & 1)
          {
            sprintf(tstr, "%lu", blink->pktsize);
            mystrncat(logout, tstr, (unsigned short)(strlen(tstr) + 1), BufSize);
            if(blink->mask & 2)
            {
              sprintf(tstr, ",%lu", blink->arcsize);
              mystrncat(logout, tstr, (unsigned short)(strlen(tstr) + 1), BufSize);
            }
            mystrncat(logout, " ", 2, BufSize);
          }
          if(blink->mask & 4)
          {
            sprintf(tstr, "#%s ", blink->echopass);
            mystrncat(logout, tstr, (unsigned short)(strlen(tstr) + 1), BufSize);
          }
          if(blink->mask & 16)
          {
            sprintf(tstr, "$%s ", blink->group);
            mystrncat(logout, tstr, (unsigned short)(strlen(tstr) + 1), BufSize);
            if(blink->mask & 8)
            {
              sprintf(tstr, "$-%s ", blink->rog);
              mystrncat(logout, tstr, (unsigned short)(strlen(tstr) + 1), BufSize);
            }
          }
          if(blink->mask & 32)
          {
            sprintf(tstr, "&%s ", blink->packer);
            mystrncat(logout, tstr, (unsigned short)(strlen(tstr) + 1), BufSize);
          }
          if(blink->mask & 64)
          {
            sprintf(tstr, "!%s ", blink->crmask);
            mystrncat(logout, tstr, (unsigned short)(strlen(tstr) + 1), BufSize);
          }
          if(blink->mask & 128)
          {
            sprintf(tstr, "%%%u ", blink->days);
            mystrncat(logout, tstr, (unsigned short)(strlen(tstr) + 1), BufSize);
          }
          if(blink->mask & 512)
          {
            sprintf(tstr, "?%s ", blink->password);
            mystrncat(logout, tstr, (unsigned short)(strlen(tstr) + 1), BufSize);
          }
          if(blink->mask & 1024)
            mystrncat(logout, (char *)((blink->create == 1) ? "+A " : "-A "), 5, BufSize);
          if(blink->mask & 2048)
          {
            switch (blink->boxes)
            {
            case 1:
              mystrncat(logout, "+B ", 5, BufSize);
              break;
            case 2:
              mystrncat(logout, "+T ", 5, BufSize);
              break;
            case 4:
              mystrncat(logout, "+I ", 5, BufSize);
              break;
            }
          }
          if(blink->mask & 4096)
            mystrncat(logout, (char *)((blink->addarc == 1) ? "+C " : "-C "), 5, BufSize);
          if(blink->mask & 8192)
            mystrncat(logout, (char *)((blink->hold == 1) ? "+H " : "-H "), 5, BufSize);
          if(blink->mask & 16384)
            if(blink->fake)
              mystrncat(logout, "+L ", 5, BufSize);
          if(blink->mask & 32768L)
            if(blink->nokrep)
              mystrncat(logout, "+N ", 5, BufSize);
          if(blink->mask & 65536L)
            mystrncat(logout, (char *)((blink->hide == 1) ? "+R " : "-R "), 5, BufSize);
          if(blink->mask & 131072L)
            mystrncat(logout, tstyle, 7, BufSize);
          if(blink->mask & 262144L)
            if(blink->noforward)
              mystrncat(logout, "+U ", 5, BufSize);
          if(blink->mask & 524288L)
            mystrncat(logout, "+Z ", 5, BufSize);
          if(blink->mask & 4194304L)
          {
            mystrncat(logout, "^", 5, BufSize);
            switch (blink->boxstyle)
            {
            case 0:
              mystrncat(logout, "0", 5, BufSize);
              break;
            case 1:
              mystrncat(logout, "1", 5, BufSize);
              break;
            case 2:
              mystrncat(logout, "2", 5, BufSize);
              mystrncat(logout, blink->address.domain, 9, BufSize);
              break;
            }
            mystrncat(logout, " ", 5, BufSize);
          }
          if(blink->mask & 0x300000L)
          {
            mystrncat(logout, "@", 3, BufSize);
            mas = itoa((unsigned)((blink->mask & 0x300000ul) >> 20), mas, 10);
            mystrncat(logout, mas, 5, BufSize);
          }
          if(blink->rules)
          {
            if(blink->rules == 1)
              mystrncat(logout, " +D", 5, BufSize);
            else
              mystrncat(logout, " -D", 5, BufSize);
          }
          mywrite(prttemp, logout, __FILE__, __LINE__);
          mystrncpy(logout,::string + maxstr[0], (short)(maxstr2[0] - maxstr[0]));
          mywrite(prttemp, logout, __FILE__, __LINE__);
          blink->written = 1;
        }
        else
          wwrite(prttemp,::string, maxstr2[0], __FILE__, __LINE__);
      }
      else
        wwrite(prttemp,::string, maxstr2[0], __FILE__, __LINE__);
    }
    while(!endblock[0]);
  }
  cclose(&prttemp, __FILE__, __LINE__);
  cclose(&setf, __FILE__, __LINE__);
  mystrncpy(bakname, file, DirSize);
  temp = strchr(bakname, '.');
  if(temp)
  {
    temp[1] = 'b';
    temp[2] = 'a';
    temp[3] = 'k';
    temp[4] = 0;
  }
  else
    mystrncat(bakname, ".bak", 5, DirSize);
  unlink(bakname);
  rrename(file, bakname);
  rrename(tbakname, file);
}

void makemsg(short handle, char *what, char *templ)
{
  long i, j, k, l, msglen, splitsize, bufsize;
  short tempsplt, mhandle, ihandle;
  char tmpsplt[(DirSize + 1)];

  if(bcfg.setdir)
    setdir = 1;
  if(!noreport)
  {
    if((templ != NULL) && templ[0] != 0)
    {
      if((ihandle = (short)sopen(templ, O_RDONLY | O_BINARY, SH_DENYWR)) == -1)
      {
        mystrncpy(errname, templ, DirSize);
        errexit(2, __FILE__, __LINE__);
      }
      mhandle = templat(handle, ihandle);
      cclose(&ihandle, __FILE__, __LINE__);
    }
    else
      mhandle = handle;
    lseek(mhandle, 0, SEEK_SET);
    if(bcfg.mansize && ((msglen = filelength(mhandle)) > bcfg.mansize))
    {
      i = 1;
      j = msglen;
      bufsize = (bcfg.mansize < 4096) ? bcfg.mansize : 4096;
      if(bufsize > buflen)
        bufsize = buflen;
      while(j > (bcfg.mansize - 100))
      {
        j -= (bcfg.mansize - 100);
        i++;
      }
      mystrncpy(tmpsplt, bcfg.workdir, DirSize);
      mystrncat(tmpsplt, "partsplt.$$$", 16, DirSize);
      if((tempsplt = (short)sopen(tmpsplt, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
      {
        mystrncpy(errname, tmpsplt, DirSize);
        errexit(2, __FILE__, __LINE__);
      }
      for(j = 1; j <= i; j++)
      {
        chsize(tempsplt, 0);
        lseek(tempsplt, 0, SEEK_SET);
        if(strcmp(what, "forwarding"))
        {
          logprintf("Splitted by Parma Tosser, part %u from %u\r\r", (unsigned short)j, (unsigned short)i);
          mywrite(tempsplt, logout, __FILE__, __LINE__);
/* Maybe temporary included strings */
          logprintf("%s, part %u from %u", bcfg.subj, (unsigned short)j, (unsigned short)i);
          mystrncpy(bufpkt.subj, logout, 71);
/* Maybe temporary included strings */
        }
        else
          logprintf("%s", bcfg.subj);
        splitsize = strlen(logout);
        if(j < i)
        {
          while(splitsize < (bcfg.mansize - 100))
          {
            fmax =
              (unsigned short)rreadz(mhandle, pktbuf,
                                    (unsigned
                                     short)((bcfg.mansize -
                                             splitsize) >
                                            bufsize ? bufsize : (bcfg.mansize - splitsize)), __FILE__, __LINE__);
            if(fmax)
            {
              k = fmax - 1;
              l = 0;
              while(k && (pktbuf[(unsigned)k] != '\r' && pktbuf[(unsigned)k] != '\n'))
                k--, l++;
              fmax = (short)(k + 1);
              lseek(mhandle, -l, SEEK_CUR);
              wwrite(tempsplt, pktbuf, fmax, __FILE__, __LINE__);
              splitsize += fmax;
            }
            else
              splitsize = bcfg.mansize;
          }
        }
        else
          while((fmax =
                 (unsigned short)rreadz(mhandle, pktbuf,
                                       (unsigned
                                        short)((bcfg.mansize -
                                                splitsize) >
                                               bufsize ? bufsize
                                               : (bcfg.mansize - splitsize)), __FILE__, __LINE__)) != 0)
            wwrite(tempsplt, pktbuf, fmax, __FILE__, __LINE__);
        if(strcmp(what, "forwarding") == 0)
        {
          if(j < i)
            logprintf("\rContinued in next message\r");
          else
            logprintf("\rEnd of splitted text\r");
          mywrite(tempsplt, logout, __FILE__, __LINE__);
        }
        flushbuf(tempsplt);
        lseek(tempsplt, 0, SEEK_SET);
        tempmsg = tempsplt;
        needout = 1;
        buftomsg(4);
        if(strcmp(what, "forwarding"))
          mystrncpy(bufpkt.subj, bcfg.subj, 71);
        logprintf("Created splitted reply (%s), part %u from %u", what, (unsigned short)j, (unsigned short)i);
        logwrite(1, 6);
        if(!quiet)
          ccprintf("%s\r\n", logout);
      }
      cclose(&tempsplt, __FILE__, __LINE__);
      unlink(tmpsplt);
    }
    else
    {
      tempmsg = mhandle;
      needout = 1;
      buftomsg(4);
      logprintf("Created reply (%s)", what);
      logwrite(1, 6);
      if(!quiet)
        ccprintf("%s\r\n", logout);
    }
    chsize(mhandle, 0);
    lseek(mhandle, 0, SEEK_SET);
    if((templ != NULL) && templ[0] != 0)
    {
      cclose(&mhandle, __FILE__, __LINE__);
      unlink(pttmpl);
    }
  }
  setdir = 0;
}

short getweight(struct myaddr *address)
{
  if(address->zone == defaddr.zone)
    if(address->net == defaddr.net)
      if(address->node == defaddr.node)
        return 0;
      else
        return 1;
    else
      return 2;
  else
    return 3;
}

void swapaddr(struct myaddr *first, struct myaddr *second)
{
  struct myaddr temp;

  temp.zone = first->zone;
  temp.net = first->net;
  temp.node = first->node;
  temp.point = first->point;
  temp.rdonly = first->rdonly;
  temp.passive = first->passive;
  first->zone = second->zone;
  first->net = second->net;
  first->node = second->node;
  first->point = second->point;
  first->rdonly = second->rdonly;
  first->passive = second->passive;
  second->zone = temp.zone;
  second->net = temp.net;
  second->node = temp.node;
  second->point = temp.point;
  second->rdonly = temp.rdonly;
  second->passive = temp.passive;
}

void areasort(short sort)
{
  struct areaindex temp;
  struct alists *ttlist;
  short i, j, comp, cur;

  if(sort)
  {
    for(i = 0; i < numarea; i++)
    {
      cur = 0;
      ttlist = rlist;
      while(ttlist)
      {
        for(j = 0; j < ttlist->numlists - 1; j++)
        {
          if(sort == 2)
          {
            if(bcfg.gric)
              comp = (short)(toupper(ttlist->alist[j].group) - toupper(ttlist->alist[j + 1].group));
            else
              comp = (short)(ttlist->alist[j].group - ttlist->alist[j + 1].group);
          }
          else
            comp = 0;
          if(!comp)
            comp = (short)stricmp(ttlist->alist[j].areaname, ttlist->alist[j + 1].areaname);
          if(comp > 0)
          {
            memcpy(&temp, &ttlist->alist[j], szareaindex);
            memcpy(&ttlist->alist[j], &ttlist->alist[j + 1], szareaindex);
            memcpy(&ttlist->alist[j + 1], &temp, szareaindex);
          }
          cur++;
          if(cur >= numarea - i)
            goto next;
        }
        if(ttlist->next)
        {
          if(sort == 2)
          {
            if(bcfg.gric)
              comp =
                (short)(toupper(ttlist->alist[ttlist->numlists - 1].group) - toupper(ttlist->next->alist[0].group));
            else
              comp = (short)(ttlist->alist[ttlist->numlists - 1].group - ttlist->next->alist[0].group);
          }
          else
            comp = 0;
          if(!comp)
            comp = (short)stricmp(ttlist->alist[ttlist->numlists - 1].areaname, ttlist->next->alist[0].areaname);
          if(comp > 0)
          {
            memcpy(&temp, &(ttlist->alist[ttlist->numlists - 1]), szareaindex);
            memcpy(&(ttlist->alist[ttlist->numlists - 1]), &(ttlist->next->alist[0]), szareaindex);
            memcpy(&(ttlist->next->alist[0]), &temp, szareaindex);
          }
          cur++;
          if(cur >= numarea - i)
            goto next;
        }
        ttlist = ttlist->next;
      }
    next:
      ;
    }
  }
}

void addsarea(struct uplname **chain, struct uplname *tempor, char *areaname, short where, short wild)
{
  struct uplname *tareas = NULL, *ttareas = NULL;
  short tfound = 0;

  mystrncpy(tempor->persarea, areaname, arealength - 1);
  tempor->where = where;
  tempor->found = 0;
  tempor->touched = 0;
  if(*chain == NULL)
  {
    *chain = (struct uplname *)myalloc(sizeof(struct uplname), __FILE__, __LINE__);
    tareas = *chain;
  }
  else
  {
    tareas = *chain;
    while(tareas && !tfound)
    {
      ttareas = tareas;
      if(stricmp(tareas->persarea, tempor->persarea) == 0)
        tfound = 1;
      else
        tareas = tareas->next;
    }
    if(!tfound)
    {
      tareas = ttareas;
      tareas->next = (struct uplname *)myalloc(sizeof(struct uplname), __FILE__, __LINE__);
      tareas = tareas->next;
    }
  }
// foundarea:
  memcpy(tareas, tempor, sizeof(struct uplname) - szlong);
  tareas->wild = wild;
  if(!tfound)
    tareas->next = NULL;
}

void inecholog(char *areaname)
{
  short present = 0;

  lseek(alog, 0, SEEK_SET);
  endinput[3] = 0;
  while(!endinput[3])
  {
    readblock(alog, 3);
    endblock[3] = 0;
    do
    {
      getstring(3);
      while(!endstring[3])
      {
        gettoken(3);
        if((strnicmp(token, areaname, toklen) == 0) && (strlen(areaname) == toklen))
          present = 1;
      }
    }
    while(!endblock[3]);
  }
  if(!present)
  {
    lseek(alog, 0, SEEK_END);
    logprintf("%s\r\n", areaname);
    mywrite(alog, logout, __FILE__, __LINE__);
    flushbuf(alog);
  }
}

void delorph(struct uplname *utarea, struct uplname *ttname)
{
  struct uplname *tareas = NULL;
  char *ttemp = NULL;
  short fpart;

  ttname = bcfg.uplname;
  while(ttname)
  {
    if(cmpaddr(&ttname->upaddr, newarea->links.chain) == 0)
      break;
    ttname = ttname->next;
  }
  if(ttname)
  {
    memcpy(utarea, ttname, sizeof(struct uplname));
    mystrncpy(utarea->persarea, newarea->areaname, arealength - 1);
    utarea->where = 2;
    if(uareas == NULL)
    {
      uareas = (struct uplname *)myalloc(sizeof(struct uplname), __FILE__, __LINE__);
      tareas = uareas;
    }
    else
    {
      tareas = uareas;
      while(tareas->next)
        tareas = tareas->next;
      tareas->next = (struct uplname *)myalloc(sizeof(struct uplname), __FILE__, __LINE__);
      tareas = tareas->next;
    }
    memcpy(tareas, utarea, sizeof(struct uplname));
    tareas->touch = 0;
    tareas->next = NULL;
  }
  logprintf("Echo Area %s (orphaned) killed by Echo Manager", newarea->areaname);
  logwrite(1, 6);
  if((crtrep = (short)sopen(crtreprt, O_RDWR | O_BINARY, SH_DENYWR)) == -1)
  {
    if((crtrep = (short)sopen(crtreprt, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
    {
      mystrncpy(errname, crtreprt, DirSize);
      errexit(2, __FILE__, __LINE__);
    }
  }

  lseek(crtrep, 0, SEEK_END);
  mywrite(crtrep, logout, __FILE__, __LINE__);
  mywrite(crtrep, "\r\n", __FILE__, __LINE__);
  cclose(&crtrep, __FILE__, __LINE__);
  if(bcfg.delfiles)
  {
    mystrncpy(logout, newarea->areafp, DirSize);
    mystrncat(logout, ".sqd", 6, DirSize);
    unlink(logout);
    logout[strlen(logout) - 1] = 'i';
    unlink(logout);
    logout[strlen(logout) - 1] = 'l';
    unlink(logout);
    logout[strlen(logout) - 1] = 'p';
    unlink(logout);
    /*
       for other extensions
       logout[strlen(logout)-1]='?';
       unlink(logout);
       logout[strlen(logout)-1]='?';
       unlink(logout);
     */
  }
  token = temptoken;
  toklen = temptoklen;
  endstring[0] = 0;
  gettoken(0);
  ttemp = token + toklen;
  fpart = (unsigned short)(ttemp -::string);
  sftime = time(NULL);
  mylocaltime(&sftime, &tmt);
  wwrite(prttemp,::string, fpart, __FILE__, __LINE__);
  logprintf(" %-4u%-2u%-2u ", tmt.tm_year, tmt.tm_mon, tmt.tm_mday);
  wwrite(prttemp, ttemp + 1, maxstr[0] - fpart - 1, __FILE__, __LINE__);
}

void delorphn(struct uplname *utarea, struct uplname *ttname, char *descr)
{
  struct uplname *tareas = NULL;
  char *ttemp = NULL /*, *dtemp = "     " */ ;
  char *temp = NULL;
  short fpart;

  ttname = bcfg.uplname;
  while(ttname)
  {
    if(cmpaddr(&ttname->upaddr, newarea->links.chain) == 0)
      break;
    ttname = ttname->next;
  }
  if(ttname)
  {
    memcpy(utarea, ttname, sizeof(struct uplname));
    mystrncpy(utarea->persarea, newarea->areaname, arealength - 1);
    utarea->where = 2;
    if(uareas == NULL)
    {
      uareas = (struct uplname *)myalloc(sizeof(struct uplname), __FILE__, __LINE__);
      tareas = uareas;
    }
    else
    {
      tareas = uareas;
      while(tareas->next)
        tareas = tareas->next;
      tareas->next = (struct uplname *)myalloc(sizeof(struct uplname), __FILE__, __LINE__);
      tareas = tareas->next;
    }
    memcpy(tareas, utarea, sizeof(struct uplname));
    tareas->touch = 0;
    tareas->next = NULL;
  }
  logprintf("Echo Area %s (orphaned) marked as DeletedArea by Echo Manager", newarea->areaname);
  logwrite(1, 6);
  if((crtrep = (short)sopen(crtreprt, O_RDWR | O_BINARY, SH_DENYWR)) == -1)
  {
    if((crtrep = (short)sopen(crtreprt, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
    {
      mystrncpy(errname, crtreprt, DirSize);
      errexit(2, __FILE__, __LINE__);
    }
  }

  lseek(crtrep, 0, SEEK_END);
  mywrite(crtrep, logout, __FILE__, __LINE__);
  mywrite(crtrep, "\r\n", __FILE__, __LINE__);
  cclose(&crtrep, __FILE__, __LINE__);

  endstring[0] = 0;
  curtpos[0] = 0;
  gettoken(0);
  ttemp = token + toklen;
  fpart = ttemp -::string;
  sftime = time(NULL);
  mylocaltime(&sftime, &tmt);
//  wwrite(prttemp,string,fpart,__FILE__,__LINE__);
  logprintf(" %04u%02u%02u ", tmt.tm_year + 1900, tmt.tm_mon + 1, tmt.tm_mday);
/*  dtemp=itoa(tmt->tm_year+1900,dtemp,10);
  mystrncpy(logout," ",2);
  mystrncat(logout,dtemp,5,DirSize);
  dtemp=itoa(tmt->tm_mon+1,dtemp,10);
  if(tmt->tm_mon<9)
    mystrncat(logout,"0",3,DirSize);
  mystrncat(logout,dtemp,5,DirSize);
  dtemp=itoa(tmt->tm_mday,dtemp,10);
  if(tmt->tm_mday<9)
    mystrncat(logout,"0",3,DirSize);
  mystrncat(logout,dtemp,5,DirSize);
  mystrncat(logout," ",2,DirSize);*/
  mywrite(prttemp, "DeletedArea ", __FILE__, __LINE__);
  mywrite(prttemp, logout, __FILE__, __LINE__);
  //
  temp = strstr(ttemp + 1, "-$");
  if(temp)
  {
    wwrite(prttemp, ttemp + 1, (unsigned short)(temp - ttemp + 1), __FILE__, __LINE__);
    writearea(prttemp, newarea, descr, 2);
  }
  else
    wwrite(prttemp, ttemp + 1, maxstr2[0] - fpart - 1, __FILE__, __LINE__);
  mystrncpy(logout,::string + maxstr[0], (short)(maxstr2[0] - maxstr[0]));
  mywrite(prttemp, logout, __FILE__, __LINE__);
//  wwrite (prttemp, ttemp + 1, maxstr2[0] - fpart - 1, __FILE__, __LINE__);
}

short delkill(short deltype)
{
  time_t curtime, basetime;
  struct tm ttime;
  char ttmp[100];

//  unsigned long currtime,filetime;
  short diff = 0;
  int i = 0;

  if(!deltype)
  {
    token = temptoken;
    toklen = temptoklen;
    endstring[0] = 0;
    gettoken(0);
//  gettoken(0);

    curtime = time(NULL);

    ttime.tm_sec = 0;
    ttime.tm_min = 0;
    ttime.tm_hour = 0;

    mystrncpy(tstrtime, asctime(&tmt), 39);
//  currtime=strtime(tstrtime);
//  tokencpy(ttmp,9);
    tokencpy(ttmp, 4);
    ttmp[4] = 0;
    ttime.tm_year = atoi(ttmp) - 1900;
    mystrncpy(ttmp, token + 4, 2);
    ttmp[2] = 0;
    ttime.tm_mon = atoi(ttmp) - 1;
    mystrncpy(ttmp, token + 6, 2);
    ttmp[2] = 0;
    ttime.tm_mday = atoi(ttmp);
    ttime.tm_wday = 0;
    ttime.tm_yday = 0;
    ttime.tm_isdst = 0;
    basetime = mktime(&ttime);

    //diff=diffdays(filetime,currtime);
    diff = (curtime - basetime) / 86400;
  };
  if((diff > bcfg.deldays) || deltype)
  {
    gettoken(0);
    tlist = rlist;
    while(tlist)
    {
      for(i = 0; i < tlist->numlists; i++)
        if((strnicmp(tlist->alist[i].areaname, token, toklen) == 0) && (strlen(tlist->alist[i].areaname) == toklen))
          goto nfoundd;
      tlist = tlist->next;
    }
  nfoundd:
    if(tlist == NULL)
    {
      tokencpy(errname, DirSize);
      errexit(5, __FILE__, __LINE__);
    }
    lseek(areaset, tlist->alist[i].areaoffs, SEEK_SET);
    rread(areaset, newarea, szarea, __FILE__, __LINE__);
//    logprintf("Echo Area %s (orphaned) killed by Echo Manager",newarea->areaname);
    logprintf(
            "Expired DeletedArea %s keyword (%i days) killed by Echo Manager", newarea->areaname, deltype ? 0 : diff);
    logwrite(1, 6);
    if(bcfg.delfiles)
    {
      mystrncpy(logout, newarea->areafp, DirSize);
      mystrncat(logout, ".sqd", 6, DirSize);
      unlink(logout);
      logout[strlen(logout) - 1] = 'i';
      unlink(logout);
      logout[strlen(logout) - 1] = 'l';
      unlink(logout);
      logout[strlen(logout) - 1] = 'p';
      unlink(logout);
    }
    return 1;
  }
  else
  {
    wwrite(prttemp,::string, maxstr2[0], __FILE__, __LINE__);
    return 0;
  };
}

void dolist(short rt)
{
  int sort;

  if(rt == 22)
    rt = 4;
  sort = bcfg.sort >> 1;
  if(!endstring[0])
  {
    gettoken(0);
    if(toupper(token[0]) == 'N')
      sort = 1;
    else if(toupper(token[0]) == 'G')
      sort = 2;
  }
  switch (rt)
  {
  case 1:
    logprintf("List Request detected");
    break;
  case 2:
    logprintf("Query Request detected");
    break;
  case 3:
    logprintf("Notify Request detected");
    break;
  case 4:
    logprintf("Extended List Request detected");
    break;
  }
  logwrite(1, 9);
  makelist(rt, (short)sort);
  switch (rt)
  {
  case 1:
    makemsg(tempsrv, "%List", bcfg.mantmpl);
    break;
  case 2:
    makemsg(tempsrv, "%Query", bcfg.mantmpl);
    break;
  case 3:
    makemsg(tempsrv, "%Notify", bcfg.mantmpl);
    break;
  case 4:
    makemsg(tempsrv, "%ExtList", bcfg.mantmpl);
    break;
  }
  chsize(tempsrv, 0);
  lseek(tempsrv, 0, SEEK_SET);
}

void relink(void)
{
  short i, isforw;
  char tempserv[(DirSize + 1)] /*, *temp = NULL, *temp2 = NULL */ ;

//  struct uplname *areas = NULL, *tareas = NULL;
  struct uplname /**tname = NULL,*/ *tuname = NULL;

//  struct alists *ttlist = NULL;
//  struct link *blink = NULL;
  struct myaddr *taddr = NULL, tsnd, tprev;

  mbigmess = 1;
//  mystrncpy (tempserv, outbound, DirSize);
  mystrncpy(tempserv, bcfg.workdir, DirSize);
  mystrncat(tempserv, "tempserv.$$$", 16, DirSize);
  if((tempsrv = (short)sopen(tempserv, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
  {
    mystrncpy(errname, tempserv, DirSize);
    errexit(2, __FILE__, __LINE__);
  }
  chsize(tempsrv, 0);
  sftime = time(NULL);
  mylocaltime(&sftime, &tmt);
  mystrncpy(tstrtime, asctime(&tmt), 39);
  converttime(tstrtime);
  tail = (char *)myalloc(BufSize, __FILE__, __LINE__);
  sprintf(tail, "\r--- ParToss %s\r", version);
  addorig = 1;
  lseek(tempsqd, 0, SEEK_SET);

  tuname = bcfg.uplname;
  while(tuname)
  {
    memcpy(&tprev, &tuname->upaddr, szmyaddr);
    if(!(rnode.zone || rnode.net || rnode.node) || (compaddr(&rnode, &tuname->upaddr) == 0))
    {
      isforw = 0;
      tlist = rlist;
      while(tlist)
      {
        for(carea = 0; carea < tlist->numlists; carea++)
        {
          lseek(areaset, tlist->alist[carea].areaoffs, SEEK_SET);
          rread(areaset, newarea, szarea, __FILE__, __LINE__);
          newarea->links.chain = newarea->links.last = NULL;
          newarea->links.numelem = 0;
          if(newarea->type == 1)
          {
            for(i = 0; i < newarea->numlinks; i++)
            {
              rread(areaset, &tsnd, szmyaddr, __FILE__, __LINE__);
              if(cmpaddr(&tsnd, &tuname->upaddr) == 0)
              {
                logprintf("+%s\r", newarea->areaname);
                mywrite(tempsrv, logout, __FILE__, __LINE__);
                isforw = 1;
              }
            }
          }
        }
        tlist = tlist->next;
      }
      if(isforw)
      {
        bufmess.tozone = tuname->upaddr.zone;
        bufmess.tonet = tuname->upaddr.net;
        bufmess.tonode = tuname->upaddr.node;
        bufmess.topoint = tuname->upaddr.point;
        taddr = bcfg.address.chain;
        while(taddr)
        {
          if(taddr->point || bufmess.topoint)
          {
            if((taddr->zone == bufmess.tozone) && (taddr->net == bufmess.tonet) && (taddr->node == bufmess.tonode))
              break;
          }
          else if(taddr->zone == bufmess.tozone)
            break;
          taddr = taddr->next;
        }
        if(taddr == NULL)
          taddr = bcfg.address.chain;
        bufmess.fromzone = taddr->zone;
        bufmess.fromnet = taddr->net;
        bufmess.fromnode = taddr->node;
        bufmess.frompoint = taddr->point;
        bufmess.fromname = (char *)myalloc(36, __FILE__, __LINE__);
        bufmess.toname = (char *)myalloc(36, __FILE__, __LINE__);
        bufmess.subj = (char *)myalloc(72, __FILE__, __LINE__);
        mystrncpy(bufmess.fromname, bcfg.manffrom, 35);
        mystrncpy(bufmess.toname, tuname->upname, 35);
        mystrncpy(bufmess.subj, tuname->uppass, 71);
        bufmess.flags = 0x181;

        memset(&bufpkt, 0, szpackmess);
        bufpkt.packtype = 2;
        bufpkt.tozone = bufmess.fromzone;
        bufpkt.tonet = bufmess.fromnet;
        bufpkt.tonode = bufmess.fromnode;
        bufpkt.topoint = bufmess.frompoint;
        bufpkt.fromzone = bufmess.tozone;
        bufpkt.fromnet = bufmess.tonet;
        bufpkt.fromnode = bufmess.tonode;
        bufpkt.frompoint = bufmess.topoint;
        sftime = time(NULL);
        mylocaltime(&sftime, &tmt);
        mystrncpy(tstrtime, asctime(&tmt), 39);
        converttime(tstrtime);
        mystrncpy(bufpkt.datetime, ftstime, 19);
        bufpkt.fromname = (char *)myalloc(36, __FILE__, __LINE__);
        bufpkt.toname = (char *)myalloc(36, __FILE__, __LINE__);
        bufpkt.subj = (char *)myalloc(72, __FILE__, __LINE__);
        mystrncpy(bufpkt.fromname, bcfg.manfrom, 35);
        mystrncpy(bufpkt.toname, bufmess.fromname, 35);
        mystrncpy(bufpkt.subj, bcfg.subj, 71);
        ptolen = strlen(bufpkt.toname);
        pfromlen = strlen(bufpkt.fromname);
        psubjlen = strlen(bufpkt.subj);
        bufpkt.flags = 0x181;

        noreport = 0;
        makemsg(tempsrv, "relinking", "");
        myfree((void **)&bufmess.subj, __FILE__, __LINE__);
        myfree((void **)&bufmess.toname, __FILE__, __LINE__);
        myfree((void **)&bufmess.fromname, __FILE__, __LINE__);
        chsize(tempsrv, 0);
        lseek(tempsrv, 0, SEEK_SET);
      }
    }
    while(tuname && cmpaddr(&tprev, &tuname->upaddr) == 0)
      tuname = tuname->next;
  }

  myfree((void **)&tail, __FILE__, __LINE__);
  addorig = 0;
  cclose(&tempsrv, __FILE__, __LINE__);
  unlink(tempserv);
}
