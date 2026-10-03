// MaxiM: memicmp

#include "partoss.h"
#include "globext.h"
#include "globfunc.h"

#include "parsmain.h"
#include "lowlevel.h"
#include "morfiles.h"
#include "errors.h"
#include "environ.h"
#include "arealias.h"
#include "chains.h"
#include "control.h"

#if defined (__linux__) || defined (__FreeBSD__)
#include "mappath.h"
#include "locks.h"
#endif

char *keywords[] = {
  "Address",                    //  0 Add to list of addresses
  "AddToSeen",                  //  1 Set variable addtoseen
  "ArcMailAttach",              //  2 ArcmailAttach style (default)
  "AreasBBS",                   //  3 Set path & filename of areas.bbs
  "BatchUnArc",                 //  4 Set variable batchunarc
  "Buffers",                    //  5 Set buffers size
  "Compress",                   //  6 Set path & filename for compress.cfg
  "DefaultPacker",              //  7 Set default packer name
  "Duplicates",                 //  8 Set counter of duplicates
  "LogFile",                    //  9 Set path & filename for log
  "LogLevel",                   // 10 Set level of log
  "NetFile",                    // 11 Set inbound directory
  "Origin",                     // 12 Set default origin line
  "Outbound",                   // 13 Set outbound directory
  "SysOpName",                  // 14 Set name for persmail area
  "ZoneGate",                   // 15 Set strip seen-by for address
  "NetArea",                    // 16 Set Netmail area
  "EchoArea",                   // 17 Set echo area
  "BadArea",                    // 18 Set bad area
  "DupeArea",                   // 19 Set dupe area
  "LocalArea",                  // 20 Set local area
  "EchoPath",                   // 21 Set path for new areas
  "Secure",                     // 22 Set secure mode
  "AutoCreate",                 // 23 Enable autocreate new areas
  "Routing",                    // 24 Set path & filename of route.cfg
  "Swap",                       // 25 Enable Swap and set swap directory
  "Swaptype",                   // 26 Set types of memory for swap
  "Killdupes",                  // 27 Don't save duplicate messages
  "RenameBad",                  // 28 Rename bad archives
  "FileBoxes",                  // 29 Set T-Mail fileboxes method and path
  "WorkDir",                    // 30 Set work directory
  "Link",                       // 31 Set links and they parameters
  "SaveControlInfo",            // 32 Set "Delete SEEN-BY and @PATH lines" flag
  "AddToArc",                   // 33 Enable to update existing mail archives
  "QuietArc",                   // 34 Suppress screen output for archivers
  "MaxPktSize",                 // 35 Set limit for size of outbound packets
  "AutoSend",                   // 36 Enable auto pack outbound archives
  "PackNetmail",                // 37 Enable pack and archive netmail
  "BinkMode",                   // 38 Bink-style outbound (disable other modes)
  "LinkType",                   // 39 Type of reply-linking - @MSGID/@REPLY or Subj
  "LinkLength",                 // 40 Length of subj's part for linking
  "SecureInbound",              // 41 Set secure inbound directory
  "KillInTransit",              // 42 Kill transit netmail after sending
  "StripAttributes",            // 43 Strip Cra and Hld attributes in received netmail
  "TinySeenBys",                // 44 List of nodes, for which need use "Tiny" seenbys
  "PostingFile",                // 45 path and file name for Partoss.Pst
  "Inbound",                    // 46 Set inbound directory (AKA NetFile)
  "Semaphore",                  // 47 Set semaphore name for mailer's rescan
  "ManagerName",                // 48 Set alternate name for Echo manager
  "ManagerHelp",                // 49 Set file name for %HELP function
  "ManagerDesc",                // 50 Set default description for echo areas
  "ManagerKill",                // 51 Set method for preventing duplicate processing
  "ManagerGroup",               // 52 Set default group for echo areas
  "ManagerSubj",                // 53 Set subj for echo manager replies
  "ManagerSize",                // 54 Set message size for split
  "ManagerReScan",              // 55 Enable %ReScan command
  "ManagerTemplate",            // 56 Set template name for echo manager
  "CreateList",                 // 57 Set template name for Auto Create
  "SwapLib",                    // 58 Set swapping library
  "PackFrequency",              // 59 Pack outbound packets after each inbound or not
  "DefaultDays",                // 60 Set default days limit for Auto Create
  "DefaultMessages",            // 61 Set default messages limit for Auto Create
  "DefaultSkip",                // 62 Set default skip messages limit for Auto Create
  "ManagerHide",                // 63 Set "hide" groups for Echo Manager
  "ManagerUnVisible",           // 64 Synonym for ManagerHide
  "AreaBuffer",                 // 65 Set buffer size for area index chain
  "KillTemplate",               // 66 Set template for kill ArcMail report
  "CarbonCopy",                 // 67 Synonym to SysOpName
  "DefaultPassThrough",         // 68 Set default passthru for Auto Create
  "ManagerGuardCharacter",      // 69 Set guard character for Hand command
  "NetMailInbound",             // 70 Set area name for incoming netmail
  "NetMailOutbound",            // 71 Set area name for outgoing netmail
  "SaveLeftKludges",            // 72 Set "Delete left kludges" flag
  "ScreenOutput",               // 73 Write text to screen by BIOS or direct
  "ManagerUpLink",              // 74 Set uplink parameters for subscribe forwarding
  "ManagerKillOrphan",          // 75 Kill orphaned passthru areas
  "ManagerHideRestricted",      // 76 Hide restricted areas from report
  "ManagerSortEnable",          // 77 Enable sort areas
  "ManagerString",              // 78 Max string length for report
  "ExportStyle",                // 79 Set export style - multiple or single packets
  "Include",                    // 80 Set name of include file
  "AreaFile",                   // 81 Set file name for Auto Create
  "DefaultArea",                // 82 Set default area parameters
  "ExternalLimits",             // 83 Disable refresh area limits
  "FlagDirectory",              // 84 Directory for session flags
  "ScanPassThrough",            // 85 Scan passthru areas
  "ForwardString",              // 86 String to put in forwarded messages
  "MaxArchiveSize",             // 87 Set limit for size of outbound packets
  "MakeAreaList",               // 88
  "DomainGate",                 // 89
  "DupeLookPath",               // 90
  "CarbonMove",                 // 91
  "PurgeAnalyse",               // 92
  "PurgeKillTrash",             // 93
  "NetMailDupes",               // 94
  "VisualSleep",                // 95
  "PurgePassThrough",           // 96
  "LockedAsBad",                // 97 (obsoleted - see LockedAreaBehavior)
  "DelKilledPassThru",          // 98
  "MultiTaskNoLock",            // 99 (obsoleted - see LockedAreaBehavior)
  "ManagerFromName",            // 100
  "ManagerBadTemplate",         //101
  "LockedAreaBehavior",         // 102
  "SaveTempEchoLog",            // 103
  "BinkSentBehavior",           // 104
  "NetMailManager",             // 105
  "ManagerForwardName",         // 106
  "ForceINTL",                  // 107
  "Kamikadze",                  // 108
  "SortArcMailBundles",         // 109
  "LinkNetMail",                // 110
  "LinkAdvanced",               // 111
  "AddKillSent",                // 112
  "FixedOutAddress",            // 113
  "BinkGenerateDLO",            // 114
  "UnPackMinSpace",             // 115 not implemented yet
  "TossMinSpace",               // 116 not implemented yet
  "BadLog",                     // 117
  "UnTossDir",                  // 118
  "PurgeProcents",              // 119
  "GroupsIgnoreCase",           // 120
  "TossStatistic",              // 121
  "SendStatistic",              // 122
  "LinkManager",                // 123
  "GroupName",                  // 124
  "AreaListShowAll",            // 125
  "AutoCreateFromBad",          // 126
  "PreservePath",               // 127
  "SysOpNameExact",             // 128
  "CarbonCopyExact",            // 129
  "CarbonMoveExact",            // 130
  "WorkOutbound",               // 131
  "DelFromSeen",                // 132
  "ManagerIgnoreFrom",          // 133
  "EnableSelfAKAs",             // 134
  "ListAsAvail",                // 135
  "CarbonFromNetMail",          // 136
  "StripExtended",              // 137
  "NetMailSemaphore",           // 138
  "SafeWrites",                 // 139
  "EchoOnlyAreaList",           // 140
  "SinglePass",                 // 141
  "LinkFVerbStep",              // 142
  "TranslateRusHp",             // 143
  "ExtensionShift",             // 144
  "ManagerReScanDays",          // 145
  "LongAreaPath",               // 146
  "EchoMailSemaphore",          // 147
  "CarbonSetLocal",             // 148
  "ListAsFull",                 // 149
  "DoNotCheckCSY",              // 150
  "BeforeUnPack",               // 151
  "BeforePack",                 // 152
  "AfterUnPackAll",             // 153
  "AfterUnPack",                // 154
  "AfterPack",                  // 155
  "LogLevelShow",               // 156
  "BoxStyle",                   // 157
  "TestForMustDie",             // 158
  "DoNotCheckBSY",              // 159
  "DoNotTossIfDamaged",         // 160
  "ManagerReplyDirect",         // 161
  "PasswordIgnoreCase",         // 162
  "ManagerSendRules",           // 163
  "DoNotCarbonFromPassThru",    // 164
  "DeletedArea",                // 165
  "DeletedAreaDays",            // 166
  "MapPath",                    // 167
  "SoftMapPath",                // 168
  "AreaAlias",                  // 169
  "FirstGoodName",              // 170
  "Umask",                      // 171
  "DoNotSearchInboundPKT",      // 172
  "KeepLogFileOpened",          // 173   (must be 1.06.09 LogAlwaysOpen <YES|NO>)
  "StripToFTS",                 // 174
  "PurgeLastRead",              // 175
  "LogAlwaysOpen",              // 176 Synonym for KeepLogFileOpened
  "DoNotCheckFD",               // 177
  "FixManagerReadOnly",         // 178
  "DeletedAreaList",            // 179
  "UseTID"                      // 180
};
short numtoken = 181;

void runmainset(void)
{
  short finish;

  edlist = 0;
  memset(&bcfg, 0, szbincfg);
  bcfg.method = 1;
  bcfg.lookpath = 1;
  bcfg.kamikadze = 1;
  mystrncpy(bcfg.subj, "Reply from Parma Tosser Echo Manager", 71);
  mystrncpy(bcfg.areadesc, "Description not available", 39);
  mystrncpy(bcfg.fwdstr, "@Return* Copied from area @Area by Parma Tosser *@Return@Return", BufSize);
  mystrncpy(bcfg.manfrom, "Parma Tosser", 35);
  mystrncpy(bcfg.manffrom, "Parma Tosser", 35);
  mystrncpy(bcfg.packcfg, "compress.cfg", DirSize);
  mystrncpy(bcfg.route, "route.cfg", DirSize);
  bcfg.defarea.group = ' ';
  bcfg.guard = '#';
  cfname[strlen(cfname) - 1] = 'a';
  finish = 0;
  while(!finish)
  {
#if defined (__linux__) || defined (__FreeBSD__)
    if(checklock(lockname))
    {
#else
    areaset = (short)sopen(cfname, O_RDWR | O_BINARY, SH_DENYNO);
    if(areaset == -1)
    {
      switch (errno)
      {
      case ENOENT:
        if((areaset = (short)sopen(cfname, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
        {
          mystrncpy(errname, cfname, DirSize);
          errexit(2, __FILE__, __LINE__);
        }
        finish = 1;
        break;
      case EMFILE:
        mystrncpy(errname, cfname, DirSize);
        errexit(2, __FILE__, __LINE__);
      case EACCES:
      case -1:
#endif
        if(mustdie)
          errexit(14, __FILE__, __LINE__);
        else if(lich)
        {
          sprintf(logout, "Waiting for open/create %s", cfname);
          logwrite(1, 1);
        }
        mtsleep(5);
#if !defined (__linux__) && !defined (__FreeBSD__)
        break;
      default:
        mystrncpy(errname, cfname, DirSize);
        errexit(2, __FILE__, __LINE__);
      }
#endif
    }
    else
      finish = 1;
  }
#if defined (__linux__) || defined (__FreeBSD__)
  if(writelock(lockname) == -1)
  {
    mystrncpy(errname, lockname, DirSize);
    errexit(2, __FILE__, __LINE__);
  };
  lck = 1;
  if((areaset = (short)sopen(cfname, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
  {
    mystrncpy(errname, cfname, DirSize);
    errexit(2, __FILE__, __LINE__);
  }
#endif
  chsize(areaset, 0);
  lseek(areaset, 0, SEEK_SET);
  cfname[strlen(cfname) - 1] = 'i';
  finish = 0;
  while(!finish)
  {
    areandx = (short)sopen(cfname, O_RDWR | O_BINARY, SH_DENYWR);
    if(areandx == -1)
    {
      switch (errno)
      {
      case ENOENT:
        if((areandx = (short)sopen(cfname, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
        {
          mystrncpy(errname, cfname, DirSize);
          errexit(2, __FILE__, __LINE__);
        }
        finish = 1;
        break;
      case EMFILE:
        mystrncpy(errname, cfname, DirSize);
        errexit(2, __FILE__, __LINE__);
      case EACCES:
      case -1:
        if(lich)
        {
          sprintf(logout, "Waiting for open/create %s", cfname);
          logwrite(1, 1);
        }
        mtsleep(5);
        break;
      default:
        mystrncpy(errname, cfname, DirSize);
        errexit(2, __FILE__, __LINE__);
      }
    }
    else
      finish = 1;
  }
  chsize(areandx, 0);
  lseek(areandx, 0, SEEK_SET);
  cfname[strlen(cfname) - 1] = 'd';
  finish = 0;
  while(!finish)
  {
    areadesc = (short)sopen(cfname, O_RDWR | O_BINARY, SH_DENYWR);
    if(areadesc == -1)
    {
      switch (errno)
      {
      case ENOENT:
        if((areadesc = (short)sopen(cfname, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
        {
          mystrncpy(errname, cfname, DirSize);
          errexit(2, __FILE__, __LINE__);
        }
        finish = 1;
        break;
      case EMFILE:
        mystrncpy(errname, cfname, DirSize);
        errexit(2, __FILE__, __LINE__);
      case EACCES:
      case -1:
        if(lich)
        {
          sprintf(logout, "Waiting for open/create %s", cfname);
          logwrite(1, 1);
        }
        mtsleep(5);
        break;
      default:
        mystrncpy(errname, cfname, DirSize);
        errexit(2, __FILE__, __LINE__);
      }
    }
    else
      finish = 1;
  }
  chsize(areadesc, 0);
  lseek(areadesc, 0, SEEK_SET);
  cfname[strlen(cfname) - 1] = 'p';
  finish = 0;
  while(!finish)
  {
    areapool = (short)sopen(cfname, O_RDWR | O_BINARY, SH_DENYWR);
    if(areapool == -1)
    {
      switch (errno)
      {
      case ENOENT:
        if((areapool = (short)sopen(cfname, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
        {
          mystrncpy(errname, cfname, DirSize);
          errexit(2, __FILE__, __LINE__);
        }
        finish = 1;
        break;
      case EMFILE:
        mystrncpy(errname, cfname, DirSize);
        errexit(2, __FILE__, __LINE__);
      case EACCES:
      case -1:
        if(lich)
        {
          sprintf(logout, "Waiting for open/create %s", cfname);
          logwrite(1, 1);
        }
        mtsleep(5);
        break;
      default:
        mystrncpy(errname, cfname, DirSize);
        errexit(2, __FILE__, __LINE__);
      }
    }
    else
      finish = 1;
  }
  chsize(areapool, 0);
  lseek(areapool, 0, SEEK_SET);
  memset(&defaddr, 0, szmyaddr);
  mystrncpy(bcfg.creatfile, mainconf, DirSize);
  parser(mainconf, 0);
  if(bcfg.grof <= 0 || bcfg.grof > 8)
    bcfg.grof = 8;
  mystrncpy(bcfg.version, version, 19);
  if(bcfg.bufsize < 2048)
    bcfg.bufsize = 2048;
  if(bcfg.bufsize > 64000ul)
    bcfg.bufsize = 64000ul;
  maxtaglen++;
  if(edlist)
    cclose(&edlist, __FILE__, __LINE__);
}

void parser(char *file, short level)
{
  short tsetf, i, j, isdescr, ispool, tnet, tnum, pm, k, dday, dmonth, dyear /*,di */ , dj;
  unsigned long ts = 0;
  char *temp = NULL, *temp2 = NULL, *temp3 = NULL, *descr = NULL, *pool = NULL, hfile[DirSize + 1], tdat[6];
  struct sysname ourname;
  struct zgate *zg = NULL;
  struct dngate *tdn = NULL;
  struct areaindex aindex;
  struct myaddr tsnd, *link = NULL;
  struct link blink, *tlink = NULL;
  struct manname *tmname = NULL;
  struct area *ttarea1 = NULL;
  struct uplname tuplink, *tupl = NULL, bladv;
  struct pktname *tinbound = NULL;
  struct incl *tgroup = NULL;

#if defined (__linux__) || defined (__FreeBSD__)
  char dos_path[DirSize], lnx_path[DirSize];
  char umaskstr[32];
#endif
  addhome(hfile, file);
  tsetf = mysopen(hfile, 0, __FILE__, __LINE__);
  mystrncpy(confile, hfile, DirSize);
// getftime(tsetf,&ftm);
//   if(!level)
//    memcpy(&bcfg.maindt,&ftm,szlong);
//  else
//    memcpy(&(tincl->stamp),&ftm,szlong);
  lineno[level] = 1;
  endinput[level] = 0;
  while(!endinput[level])
  {
    readblock(tsetf, level);
    endblock[level] = 0;
    do
    {
      getstring(level);
      gettoken(level);
      if(*token != ';')
      {
        for(i = 0; i < numtoken; i++)
          if((toklen == strlen(keywords[i])) && (strnicmp(token, keywords[i], toklen) == 0))
            break;
        switch (i)
        {
        default:
          tokencpy(logout, BufSize);
          if(strlen(logout))
            ccprintf("Incorrect keyword \"%s\" in %s (line %d)\r\n", logout, hfile, lineno[level]);
          break;
#if defined (__linux__) || defined (__FreeBSD__)
//Попытка реализовать MapPath
        case 167:
          gettoken(level);
          tokencpy((char *)&dos_path, DirSize);
          gettoken(level);
          tokencpy((char *)&lnx_path, DirSize);
          pmapper.addpath((char *)&dos_path, (char *)&lnx_path, 0);
          break;
//Попытка реализовать SoftMapPath
        case 168:
          gettoken(level);
          tokencpy((char *)&dos_path, DirSize);
          gettoken(level);
          tokencpy((char *)&lnx_path, DirSize);
          pmapper.addpath((char *)&dos_path, (char *)&lnx_path, 1);
          break;
        case 171:
          gettoken(level);
          tokencpy((char *)&umaskstr, 32);
          umask_val = strtol((char *)&umaskstr, NULL, 8);
//    printf("umask: %d & 0777 = %d\n",umask_val,(umask_val&777));
          break;
#endif

        case 0:
          gettoken(level);
          parseaddr(token, &tsnd, toklen);
          if(tsnd.zone)
          {
            if(addaddr(&(bcfg.address), &tsnd))
              bcfg.numaddr++;
            if(!(defaddr.zone || defaddr.net || defaddr.node || defaddr.point))
              memcpy(&defaddr, &tsnd, szmyaddr);
          }
          break;

        case 1:
          while(!endstring[level])
          {
            gettoken(level);
            bcfg.numseenby++;
            parseaddr(token, &tsnd, toklen);
            if(tsnd.zone)
              addaddr(&(bcfg.seenby), &tsnd);
          }
          break;

        case 2:
          bcfg.method = 2;
          break;

        case 3:
          gettoken(level);
          tokencpy(logout, DirSize);
          addhome(bcfg.areacfg, logout);
          break;

        case 4:
          bcfg.bunarc = 1;
          break;

        case 5:
          long tmpbuf;

          gettoken(level);
          if(memicmp(token, "Small", toklen) == 0)
            bcfg.bufsize = 16384;
          else if(memicmp(token, "Medium", toklen) == 0)
            bcfg.bufsize = 24576;
          else if(memicmp(token, "Large", toklen) == 0)
            bcfg.bufsize = 32768u;
          else
          {
            tmpbuf = atoi(token);
            temp = token;
            while(isdigit(*temp++));
            temp--;
            if(toupper(*temp) == 'K')
              tmpbuf <<= 10;
            if(tmpbuf > 64000)
              tmpbuf = 64000;
            bcfg.bufsize = (unsigned short)tmpbuf;
          }
          break;

        case 6:
          gettoken(level);
          tokencpy(logout, DirSize);
          addhome(bcfg.packcfg, logout);
          break;

        case 7:
          gettoken(level);
          tokencpy(bcfg.defarc, 9);
          break;

        case 8:
          gettoken(level);
          bcfg.defarea.dupes = atoi(token);
          bcfg.maxdupes = bcfg.defarea.dupes;
          break;

        case 9:
          gettoken(level);
          tokencpy(logout, DirSize);
          addhome(bcfg.logfile, logout);
          break;

        case 10:
          gettoken(level);
          bcfg.loglevel = (short)atoi(token);
          break;

        case 11:
        case 41:
        case 46:
          if(bcfg.inbound == NULL)
          {
            bcfg.inbound = (struct pktname *)myalloc(szpktname, __FILE__, __LINE__);
            tinbound = bcfg.inbound;
          }
          else
          {
            tinbound = bcfg.inbound;
            while(tinbound->next)
              tinbound = tinbound->next;
            tinbound->next = (struct pktname *)myalloc(szpktname, __FILE__, __LINE__);
            tinbound = tinbound->next;
          }
          gettoken(level);
          tokencpy(tinbound->name, DirSize);
          if(tinbound->name[toklen - 1] != DIRSEP[0])
          {
            tinbound->name[toklen] = DIRSEP[0];
            tinbound->name[toklen + 1] = 0;
          }
          if(i == 41)
            tinbound->where = 1;
          else
            tinbound->where = 0;
          if(!endstring[level])
          {
            gettoken(level);
            if(stricmp(token, "Secure") == 0)
              tinbound->where = 1;
          }
          tinbound->next = NULL;
          bcfg.numinbound++;
          break;

        case 12:
          gettoken(level);
          if(*(token - 1) == '"')
            tokencpy(bcfg.origin, 80);
          else
          {
            mystrncpy(bcfg.origin, token, (short)(maxstr[level] - (token -::string)));
            temp = strchr(bcfg.origin, '\r');
            if(temp)
              *temp = 0;
            temp = strchr(bcfg.origin, '\n');
            if(temp)
              *temp = 0;
          }
          break;

        case 13:
          gettoken(level);
          tokencpy(bcfg.outbound, DirSize);
          if(bcfg.outbound[toklen - 1] == DIRSEP[0])
            bcfg.outbound[toklen - 1] = 0;
          temp = strrchr(bcfg.outbound, '.');
          if(temp && ((temp - bcfg.outbound) > (strlen(bcfg.outbound) - 4)))
            *temp = 0;
          break;

        case 14: // "SysOpName"
        case 67: // "CarbonCopy"
        case 91: // "CarbonMove"
        case 128: // "SysOpNameExact"
        case 129: // "CarbonCopyExact"
        case 130: // "CarbonMoveExact"
          gettoken(level);
          memset(&ourname, 0, szsysname);
          tokencpy(logout, BufSize);
          if(logout[0] == '%')
            parseaddr(logout + 1, &ourname.address, (short)(toklen - 1));
          else
          {
            if(strlen(logout) > 35)
              logout[35] = 0;
            mystrncpy(ourname.name, logout, 35);
          }
          gettoken(level);
          tokencpy(ourname.persarea, arealength - 1);
          if(!endstring[level])
          {
            gettoken(level);
            if(strnicmp(token, "From", 4) == 0)
              ourname.where = 2;
            else if(strnicmp(token, "To", 2) == 0)
              ourname.where = 1;
            else if(strnicmp(token, "Both", 4) == 0)
              ourname.where = 3; // 2 + 1
            else if(strnicmp(token, "Subj", 4) == 0)
              ourname.where = 4;
            else if(strnicmp(token, "All", 3) == 0)
              ourname.where = 7; // 2 + 1 + 4
          }
          if(!ourname.where)
            ourname.where = 1;
          if(ourname.where < 4)
          {
            if(!endstring[level])
            {
              gettoken(level);
              tokencpy(logout, DirSize);
              addhome(ourname.templ, logout);
            }
          }
          if(i == 91)
            ourname.move = 1;
          else
            ourname.move = 0;
          if((i == 128) || (i == 129) || (i == 130))
            ourname.exact = 1;
          addname(&(bcfg.myname), &ourname);
          bcfg.numnames++;
          break;

        case 15:
          if(bcfg.zonegate == NULL)
          {
            bcfg.zonegate = (struct zgate *)myalloc(szzgate, __FILE__, __LINE__);
            zg = bcfg.zonegate;
          }
          else
          {
            zg = bcfg.zonegate;
            while(zg->next)
              zg = zg->next;
            zg->next = (struct zgate *)myalloc(szzgate, __FILE__, __LINE__);
            zg = zg->next;
          }
          zg->next = NULL;
          zg->zseen.chain = zg->zseen.last = NULL;
          zg->numseen = zg->zseen.numelem = 0;
          bcfg.numgates++;
          gettoken(level);
          parseaddr(token, &zg->address, toklen);
          if(zg->address.zone)
          {
            while(!endstring[level])
            {
              gettoken(level);
              if((temp = strchr(token, '/')) != NULL && ((temp - token) < toklen))
              {
                tnet = (unsigned short)atoi(token);
                tnum = (unsigned short)atoi(temp + 1);
              }
              else
                tnum = (unsigned short)atoi(temp + 1);
              addshort(&(zg->zseen), tnet, tnum);
              zg->numseen++;
            }
            sortsnb(&(zg->zseen));
          }
          break;

        case 16: //"NetArea"
        case 17: //"EchoArea"
        case 18: //"BadArea"
        case 19: //"DupeArea"
        case 20: //"LocalArea"
        case 82: //"DefaultArea"
        case 165://"DeletedArea"
          isdescr = 0;
          ispool = 0;
          if(i != 82)
          {
            ttarea1 = newarea;
            memset(newarea, 0, szarea);
          }
          else
            ttarea1 = &bcfg.defarea;
          memcpy(&defaddr, bcfg.address.chain, szmyaddr);
          ttarea1->type = (short)(i - 16);
          if(i == 165)
            ttarea1->type >>= 4;        //=9
          if(i < 18)
            ttarea1->dupes = bcfg.defarea.dupes;
          if(i == 165)
          {
            gettoken(level);
            memset(tdat, 0, 6);
            memcpy(tdat, token, 4);
            dyear = (short)atoi(tdat);
            memset(tdat, 0, 6);
            memcpy(tdat, token + 4, 2);
            dmonth = (short)atoi(tdat);
            memset(tdat, 0, 6);
            memcpy(tdat, token + 6, 2);
            dday = (short)atoi(tdat);
            dj = dyear;
            dj <<= 4;
            dj |= dmonth;
            dj <<= 5;
            dj |= dday;
            ttarea1->delday = dj;
          }
          gettoken(level);
          tokencpy(ttarea1->areaname, arealength - 1);
          if(maxtaglen < strlen(ttarea1->areaname))
            maxtaglen = (short)strlen(ttarea1->areaname);
          gettoken(level);
//FIXME
//Странно, но тут вместо 79 по идее должен быть DirSize
//            tokencpy(ttarea1->areafp,79);
          tokencpy(ttarea1->areafp, DirSize);
#if defined (__linux__) || defined (__FreeBSD__)
//По идее, тут надо бы сделать mappath в случае необходимости.
          pmapper.remap(ttarea1->areafp);
#endif
          ttarea1->seenby.chain = ttarea1->seenby.last = NULL;
          ttarea1->seenby.numelem = 0;
          ttarea1->group = bcfg.defarea.group;
          ttarea1->killd = bcfg.killdupes;
          if(i == 16)
          {
            if(ttarea1->areafp[toklen - 1] != DIRSEP[0])
              ttarea1->areafp[toklen] = DIRSEP[0];
          }
          else
          {
            if(fatmode)
            {
              temp = strrchr(ttarea1->areafp, DIRSEP[0]);
              if(temp == NULL)
                temp = ttarea1->areafp;
              else
                temp++;
              if(strlen(temp) > 8)
                temp[8] = 0;
            }
          }
          while(!endstring[level])
          {
            gettoken(level);
            memset(&tsnd, 0, szmyaddr);
            switch (token[0])
            {
            case '-':
              switch (token[1])
              {
              case '$':
                switch (token[2])
                {
                case 'd':
                case 'D':
                  ttarea1->days = (short)atoi(token + 3);
                  break;
                case 'm':
                case 'M':
                  ttarea1->messages = (short)atoi(token + 3);
                  break;
                case 's':
                case 'S':
                  ttarea1->skipmsg = (short)atoi(token + 3);
                  break;
                case 'b':
                case 'B':
                  switch (token[3])
                  {
                  case 'k':
                  case 'K':
                    ttarea1->dupes = atoi(token + 4);
                    ttarea1->killd = 1; // удалять все дупы независимо от настроек
                    ttarea1->killd_modified = 1;        // индикатор наличия модификатора - для пересоздания строки при необходимости
                    break;
                  case 'n':
                  case 'N':
                    ttarea1->dupes = atoi(token + 4);
                    ttarea1->killd = 0; // НЕ удалять все дупы независимо от настроек
                    ttarea1->killd_modified = 1;        // индикатор наличия модификатора - для пересоздания строки при необходимости
                    break;
                  default:
                    ttarea1->dupes = atoi(token + 3);
                    ttarea1->killd = bcfg.killdupes;
                    ttarea1->killd_modified = 0;
                  }
                  break;
                case 'l':
                case 'L':
                  ttarea1->linktype = (short)atoi(token + 3);
                  break;
                case 'g':
                case 'G':
                  ttarea1->group = *(token + 3);
                  break;
                case 'n':
                case 'N':
                  temp = token + 3;
                  if(*temp == '"')
                  {
                    temp++;
                    temp2 = strchr(temp, '"');
                    toklen = (short)(temp2 - token - 1);
                    curtpos[level] = (short)(temp2 -::string + 1);
                  }
                  if(i < 21)
                  {
                    descr = (char *)myalloc((toklen + 1), __FILE__, __LINE__);
                    mystrncpy(descr, temp, (short)(toklen - 3));
                    isdescr = 1;
                  }
                  else
                    mystrncpy(bcfg.areadesc, temp, (short)(toklen - 3));
                  break;
                case 'f':
                case 'F':
                  temp = token + 3;
                  if(*temp == '"')
                  {
                    temp++;
                    temp2 = strchr(temp, '"');
                    toklen = (short)(temp2 - token - 1);
                    curtpos[level] = (short)(temp2 -::string + 1);
                  }
                  if(i < 21)
                  {
                    pool = (char *)myalloc((toklen + 1), __FILE__, __LINE__);
                    mystrncpy(pool, temp, (short)(toklen - 3));
                    isdescr = 1;
                    pool[toklen - 2] = 0;
                    if(pool[strlen(pool) - 1] != DIRSEP[0])
                      mystrncat(pool, DIRSEP, 3, DirSize);
                  }
                  else
                  {
                    mystrncpy(bcfg.areapool, temp, (short)(toklen - 3));
                    bcfg.areapool[toklen - 2] = 0;
                    if(bcfg.areapool[strlen(bcfg.areapool) - 1] != DIRSEP[0])
                      mystrncat(bcfg.areapool, (char *)DIRSEP, 3, DirSize);
                  }
                  ispool = 1;
                  break;
                case '@':
                  ttarea1->saveci = 1;
                  break;
                }
                break;
              case 'p':
              case 'P':
                temp = token + 2;
                parseaddr(temp, &(ttarea1->myaka), (short)(toklen - 2));
                break;

              case 'x':
              case 'X':
              case 'y':
              case 'Y':
              case 'z':
              case 'Z':
                if(i < 21)
                {
                  j = 0;
                  temp = token + 1;
                  short m;

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
                  parseaddr(temp + j, &tsnd, (short)(toklen - (2 + j)));
                  if(tsnd.zone)
                  {
                    if(addaddr(&(ttarea1->links), &tsnd))
                      ttarea1->numlinks++;
                  }
                }
                break;

              case '0':
                ttarea1->passthr = 1;
                break;

              case '+':
                if(i < 21)
                {
                  temp = token + 2;
                  tnet = (unsigned short)atoi(temp);
                  temp = strchr(token, '/');
                  tnum = (unsigned short)atoi(temp + 1);
                  addshort(&(ttarea1->seenby), tnet, tnum);
                }
                break;
              }
              break;
            default:
              if(i < 21 || i == 165)
              {
                parseaddr(token, &tsnd, toklen);
                if(tsnd.zone)
                {
                  if(addaddr(&(ttarea1->links), &tsnd))
                    ttarea1->numlinks++;
                }
              }
              break;
            }
          }
          if(ttarea1->myaka.net == 0 && ttarea1->myaka.node == 0)
            memcpy(&ttarea1->myaka, bcfg.address.chain, szmyaddr);
          if(ttarea1->dupes > bcfg.maxdupes)
            bcfg.maxdupes = ttarea1->dupes;
          if(i < 21 || i == 165)
          {
            aindex.areaoffs = lseek(areaset, 0, SEEK_END);
            memcpy(aindex.areaname, ttarea1->areaname, arealength);
            aindex.descoffs = (isdescr ? lseek(areadesc, 0, SEEK_END) : 0);
            aindex.desclen = (short)(isdescr ? strlen(descr) : 0);
            aindex.scanned = 0;
            aindex.type = ttarea1->type;
            aindex.toss = aindex.sent = aindex.dupes = 0;
            aindex.tossed = 0;
            aindex.group = ttarea1->group;
            // ttarea1->links.chain=ttarea1->links.last=NULL;
            ttarea1->links.numelem = 0;
            ttarea1->pooloffs = (ispool ? (lseek(areapool, 0, SEEK_END)) : 0);
            ttarea1->poollen = (ispool ? (strlen(pool)) : 0);
            wwrite(areaset, ttarea1, szarea, __FILE__, __LINE__);
            if(isdescr)
            {
              wwrite(areadesc, descr, (unsigned short)(aindex.desclen + 1), __FILE__, __LINE__);
//                myfree((void **)&descr,__FILE__,__LINE__);
            }
            if(ispool)
            {
              wwrite(areapool, pool, (unsigned short)(ttarea1->poollen + 1), __FILE__, __LINE__);
//                myfree((void **)&pool,__FILE__,__LINE__);
            }
            if(edlist && (!ttarea1->passthr || bcfg.showall) && (!bcfg.echoonly || (i == 17)))
            {
              temp = bcfg.shablon;
              temp2 = temp;
              while(temp && *temp)
              {
                while(*temp2 && (*temp2 != '@'))
                  temp2++;
                wwrite(edlist, temp, (unsigned short)(temp2 - temp), __FILE__, __LINE__);
                temp2++;
                switch (toupper(*temp2))
                {
                case 'K':
                  switch (i)
                  {
                  case 16:
                    mywrite(edlist, "NetArea  ", __FILE__, __LINE__);
                    break;
                  case 17:
                    mywrite(edlist, "EchoArea ", __FILE__, __LINE__);
                    break;
                  default:
                    mywrite(edlist, "LocalArea", __FILE__, __LINE__);
                    break;
                  }
                  break;
                case 'T':
                  mywrite(edlist, ttarea1->areaname, __FILE__, __LINE__);
                  break;
                case 'P':
                  mywrite(edlist, ttarea1->areafp, __FILE__, __LINE__);
                  break;
                case 'F':
                  temp3 = strrchr(ttarea1->areafp, DIRSEP[0]);
                  if(temp3)
                  {
                    temp3++;
                    if(*temp3)
                      mywrite(edlist, temp3, __FILE__, __LINE__);
                  }
                  else
                    mywrite(edlist, ttarea1->areafp, __FILE__, __LINE__);
                  break;
                case 'Y':
                  if(ttarea1->type && ttarea1->type < 10)
                    mywrite(edlist, "-$", __FILE__, __LINE__);
                  break;
                case 'G':
                  sprintf(logout, "%c", ttarea1->group);
                  mywrite(edlist, logout, __FILE__, __LINE__);
                  break;
                case 'D':
                  mywrite(edlist, "\"", __FILE__, __LINE__);
                  if(isdescr)
                    mywrite(edlist, descr, __FILE__, __LINE__);
                  else
                    mywrite(edlist, bcfg.areadesc, __FILE__, __LINE__);
                  mywrite(edlist, "\"", __FILE__, __LINE__);
                  break;
                case 'O':
                  mywrite(edlist, "\"", __FILE__, __LINE__);
                  if(isdescr)
                    mywrite(edlist, descr, __FILE__, __LINE__);
                  else
                    mywrite(edlist, ttarea1->areaname, __FILE__, __LINE__);
                  mywrite(edlist, "\"", __FILE__, __LINE__);
                  break;
                case 'A':
                  sprintf(logout, "%u:%u/%u.%u",
                          ttarea1->myaka.zone, ttarea1->myaka.net, ttarea1->myaka.node, ttarea1->myaka.point);
                  mywrite(edlist, logout, __FILE__, __LINE__);
                  break;
                default:
                  temp2--;
                  break;
                }
                temp2++;
                temp = temp2;
              }
              mywrite(edlist, "\r\n", __FILE__, __LINE__);
            }
            if(isdescr)
              myfree((void **)&descr, __FILE__, __LINE__);
            if(ispool)
              myfree((void **)&pool, __FILE__, __LINE__);
            wwrite(areandx, &aindex, szareaindex, __FILE__, __LINE__);
            link = ttarea1->links.chain;
            while(link)
            {
              wwrite(areaset, link, szmyaddr, __FILE__, __LINE__);
              link = link->next;
            }
            deladdr(&(ttarea1->links));
          }
          break;

        case 21:
          gettoken(level);
          tokencpy(bcfg.areapath, DirSize);
          if(bcfg.areapath[toklen - 1] != DIRSEP[0])
            bcfg.areapath[toklen] = DIRSEP[0];
          break;

        case 22:
          bcfg.secure = 1;
          break;

        case 23:
          bcfg.create = 1;
          break;

        case 24:
          gettoken(level);
          tokencpy(logout, DirSize);
          addhome(bcfg.route, logout);
          break;

        case 25:
          bcfg.swapping = 1;
          gettoken(level);
          tokencpy(bcfg.swapfile, DirSize);
          if(bcfg.swapfile[toklen - 1] != DIRSEP[0])
            bcfg.swapfile[toklen] = DIRSEP[0];

          break;

        case 26:
          bcfg.swapping = 1;
          bcfg.swaptype = 0;
          gettoken(level);
          for(j = 0; j < toklen; j++)
            switch (token[j])
            {
            case 'x':
            case 'X':
              bcfg.swaptype |= 1;
              break;
            case 'e':
            case 'E':
              bcfg.swaptype |= 2;
              break;
            case 'd':
            case 'D':
//                  bcfg.swaptype|=SWAP_DISK;
              break;
            }
          if(bcfg.swaptype & 1 && bcfg.swaptype & 2)
            bcfg.swaptype |= 0x10;
          break;

        case 27:
          bcfg.killdupes = 1;
          break;

        case 28:
          bcfg.renbad = 1;
          break;

        case 29:
          bcfg.method = 1;
          gettoken(level);
          tokencpy(bcfg.boxes, DirSize);
          if(bcfg.boxes[toklen - 1] != DIRSEP[0])
            bcfg.boxes[toklen] = DIRSEP[0];
          break;

        case 30:
          gettoken(level);
          tokencpy(bcfg.workdir, DirSize);
          if(bcfg.workdir[toklen - 1] != DIRSEP[0])
            bcfg.workdir[toklen] = DIRSEP[0];
          break;

        case 31:
        case 123:
          memset(&blink, 0, szlink);
          gettoken(level);
          parseaddr(token, &(blink.address), toklen);
          if(bcfg.boxstyle)
          {
            blink.boxstyle = bcfg.boxstyle;
            memcpy(blink.address.domain, bcfg.defdomain, 8);
          }
          if(blink.address.zone)
          {
            tlink = bcfg.links.chain;
            while(tlink)
            {
              if(cmpaddr(&(blink.address), &(tlink->address)) == 0)
                break;
              tlink = tlink->next;
            }
            if(tlink)
              memcpy(&blink, tlink, szlink);
            while(!endstring[level])
            {
              gettoken(level);
              if(isdigit(token[0]))
              {
                blink.mask |= 1;
                blink.pktsize = atol(token);
                temp = token;
                while(isdigit(*temp++));
                temp--;
                if(toupper(*temp) == 'K')
                {
                  blink.pktsize <<= 10;
                  temp++;
                }
                if(*temp == ',')
                {
                  blink.mask |= 2;
                  temp++;
                  blink.arcsize = atol(temp);
                  while(isdigit(*temp++));
                  temp--;
                  if(toupper(*temp) == 'K')
                    blink.arcsize <<= 10;
                }
                else
                  blink.arcsize = 0;
              }
              else
/*
                 {
                  if(token[0]=='#')
                   {
                    blink.mask|=4;
                    mystrncpy(blink.echopass,token+1,(short)(toklen-1));
                   }
                  else
                   {
                    if(token[0]=='$')
                     {
                      if(token[1]=='-')
                       {
                        blink.mask|=8;
                        mystrncpy(blink.rog,token+2,(short)(toklen-2));
                       }
                      else
                       {
                        blink.mask|=16;
                        mystrncpy(blink.group,token+1,(short)(toklen-1));
                       }
                     }
                    else
                     {
                      if(token[0]=='&')
                       {
*/
              {
                switch (token[0])
                {
                case ',':
                  blink.mask |= 2;
                  blink.arcsize = atol(token + 1);
                  temp = token + 1;
                  while(isdigit(*temp++));
                  temp--;
                  if(toupper(*temp) == 'K')
                    blink.arcsize <<= 10;
                  break;
                case '#':
                  blink.mask |= 4;
                  mystrncpy(blink.echopass, token + 1, (short)(toklen - 1));
                  break;
                case '$':
                  if(token[1] == '-')
                  {
                    blink.mask |= 8;
                    mystrncpy(blink.rog, token + 2, (short)(toklen - 2));
                  }
                  else
                  {
                    blink.mask |= 16;
                    mystrncpy(blink.group, token + 1, (short)(toklen - 1));
                  };
                  break;
                case '&':
                  blink.mask |= 32;
                  mystrncpy(blink.packer, token + 1, (short)(toklen - 1));
                  break;
                case '!':
                  blink.mask |= 64;
                  blink.autoadd = 1;
                  if(toklen > 1)
                    memcpy(blink.crmask, token + 1, (short)(toklen - 1));
                  else
                    memcpy(blink.crmask, "*", 1);
                  break;
                case '%':
                  blink.mask |= 128;
                  blink.days = (short)atoi(token + 1);
                  break;
                case '~':
                  blink.mask |= 256;
                  temp = token + 1;
                  if(*temp == '"')
                  {
                    temp++;
                    temp2 = strchr(temp, '"');
                    toklen = (short)(temp2 - token - 1);
                    curtpos[level] = (unsigned short)(temp2 -::string + 1);
                  }
                  mystrncpy(blink.name, temp, (short)(toklen - 1));
                  break;
                case '?':
                  blink.mask |= 512;
                  mystrncpy(blink.password, token + 1, (short)((toklen > 9) ? 8 : (toklen - 1)));
                  break;
                case '@':
                  ts = atoi(token + 1);
                  ts <<= 20;
                  blink.mask |= ts;
                  break;
                case '^':
                  ts = atoi(token + 1);
                  if(ts == 2)
                  {
                    memset(blink.address.domain, 0, 8);
                    memcpy(blink.address.domain, token + 2, (((toklen - 2) > 8) ? 8 : (toklen - 2)));
                  }
                  blink.boxstyle = (short)ts;
                  blink.mask |= 4194304L;
                  break;
                default:
                  pm = (token[0] == '+' ? 1 : 65535u);
                  j = 1;
                  while(!isspace(token[j]))
                  {
                    switch (toupper(token[j]))
                    {
                    case 'A':
                      blink.mask |= 1024;
                      blink.create = pm;
                      break;
                    case 'B':
                      blink.mask |= 2048;
                      blink.boxes = 1;
                      break;
                    case 'C':
                      blink.mask |= 4096;
                      blink.addarc = pm;
                      break;
                    case 'D':
                      // blink.mask|=4096;
                      blink.rules = pm;
                      break;
                    case 'H':
                      blink.mask |= 8192;
                      blink.hold = pm;
                      break;
                    case 'I':
                      blink.mask |= 2048;
                      blink.boxes = 4;
                      break;
                    case 'L':
                      blink.mask |= 16384;
                      blink.fake = ((pm == 1) ? 1 : 0);
                      break;
                    case 'N':
                      blink.mask |= 32768L;
                      blink.nokrep = (pm == 1);
                      break;
                    case 'R':
                      blink.mask |= 65536L;
                      blink.hide = pm;
                      break;
                    case 'S':
                      blink.mask |= 131072L;
                      blink.style = pm;
                      break;
                    case 'T':
                      blink.mask |= 2048;
                      blink.boxes = 2;
                      break;
                    case 'U':
                      blink.mask |= 262144L;
                      blink.noforward = (pm == 1);
                      break;
                    case 'X':
                      blink.mask |= 131072L;
                      blink.style = (short)(pm << 1);
                      break;
                    case 'Z':
                      blink.mask |= 524288L;
                      blink.style = 10;
                      break;
                    }
                    j++;
                  }
                }
              }
            }
            if(i == 123)
              blink.manager = 1;
            if(blink.mask & 512)
            {
              if((blink.mask & (3L << 20)) == 0)
                blink.mask |= (1L << 20);
            }
            else
              blink.mask &= 0xffdffffful;
            if(tlink)
              memcpy(tlink, &blink, szlink);
            else
            {
              addlink(&(bcfg.links), &blink);
              bcfg.numlink++;
            }
          }
          break;

        case 32:
          gettoken(level);
          if(memicmp(token, "No", 2) == 0)
            bcfg.delinfo = 1;
          if(memicmp(token, "Path", 4) == 0)
            bcfg.delinfo = 2;
          break;

        case 33:
          bcfg.addarc = 1;
          break;

        case 34:
          bcfg.quiet = 1;
          break;

        case 35:
          gettoken(level);
          bcfg.pktsize = atol(token);
          temp = token;
          while(isdigit(*temp++));
          temp--;
          if(toupper(*temp) == 'K')
            bcfg.pktsize <<= 10;
          break;

        case 36:
          bcfg.autosend = 1;
          break;

        case 37:
          bcfg.pack = 1;
          break;

        case 38:
          bcfg.method = 4;
          break;

        case 39:
          gettoken(level);
          if(strnicmp(token, "Subj", 4) == 0)
            bcfg.linktype = 1;
          else if(strnicmp(token, "Flat", 4) == 0)
            bcfg.linktype = 2;
          else if(strnicmp(token, "TimEd", 5) == 0)
            bcfg.linktype = 3;
          else if(strnicmp(token, "None", 4) == 0)
            bcfg.linktype = 4;
          break;

        case 40:
          gettoken(level);
          bcfg.linklength = (short)atoi(token);
          if(bcfg.linklength > 72)
            bcfg.linklength = 0;
          break;

        case 42:
          bcfg.killtr = 1;
          break;

        case 43:
          bcfg.stripattr = 1;
          break;

        case 44:
          gettoken(level);
          parseaddr(token, &tsnd, toklen);
          if(tsnd.zone)
          {
            if(addaddr(&(bcfg.tinysb), &tsnd))
              bcfg.numts++;
          }
          break;

        case 45:
          gettoken(level);
          tokencpy(logout, DirSize);
          addhome(bcfg.post, logout);
          break;

        case 47:
          gettoken(level);
          tokencpy(tuplink.echolist, DirSize);
          if(bcfg.semaphore == NULL)
          {
            bcfg.semaphore = (struct uplname *)myalloc(sizeof(struct uplname), __FILE__, __LINE__);
            tupl = bcfg.semaphore;
          }
          else
          {
            tupl = bcfg.semaphore;
            while(tupl->next)
              tupl = tupl->next;
            tupl->next = (struct uplname *)myalloc(sizeof(struct uplname), __FILE__, __LINE__);
            tupl = tupl->next;
          }
          memcpy(tupl, &tuplink, sizeof(struct uplname));
          tupl->next = NULL;
          bcfg.numsem++;
          break;

        case 48:
          if(bcfg.names == NULL)
          {
            bcfg.names = (struct manname *)myalloc(sizeof(struct manname), __FILE__, __LINE__);
            tmname = bcfg.names;
          }
          else
          {
            tmname = bcfg.names;
            while(tmname->next)
              tmname = tmname->next;
            tmname->next = (struct manname *)myalloc(sizeof(struct manname), __FILE__, __LINE__);
            tmname = tmname->next;
          }
          tmname->next = NULL;
          bcfg.nummans++;
          gettoken(level);
          tokencpy(tmname->name, 35);
          break;

        case 49:
          gettoken(level);
          tokencpy(logout, DirSize);
          addhome(bcfg.help, logout);
          break;

        case 50:
          gettoken(level);
          tokencpy(bcfg.mandesc, toklen);
          break;

        case 51:
          bcfg.mankill = 1;
          break;

        case 52:
          gettoken(level);
          bcfg.defarea.group = token[0];
          break;

        case 53:
          gettoken(level);
          tokencpy(bcfg.subj, 71);
          break;

        case 54:
          gettoken(level);
          bcfg.mansize = atoi(token);
          temp = token;
          while(isdigit(*temp++));
          temp--;
          if(toupper(*temp) == 'K')
            bcfg.mansize <<= 10;
          if(bcfg.mansize < 2048)
            bcfg.mansize = 2048;
          break;

        case 55:
          bcfg.rescan = 1;
          break;

        case 56:
          gettoken(level);
          tokencpy(logout, DirSize);
          addhome(bcfg.mantmpl, logout);
          break;

        case 57:
          gettoken(level);
          tokencpy(logout, DirSize);
          addhome(bcfg.reptmpl, logout);
          break;

        case 58:
          ccprintf("Keyword \"SwapLib\" no longer supported\r\n");
          break;

        case 59:
          gettoken(level);
          if(strnicmp(token, "Packet", 6) == 0)
            bcfg.bpack = 1;
          break;

        case 60:
          gettoken(level);
          bcfg.defarea.days = (short)atoi(token);
          break;

        case 61:
          gettoken(level);
          bcfg.defarea.messages = (short)atoi(token);
          break;

        case 62:
          gettoken(level);
          bcfg.defarea.skipmsg = (short)atoi(token);
          break;

        case 63:
        case 64:
          gettoken(level);
          tokencpy(bcfg.hides, 26);
          break;

        case 65:
          gettoken(level);
          bcfg.grof = (short)atoi(token);
          gran = (short)(1 << bcfg.grof);
          break;

        case 66:
          gettoken(level);
          tokencpy(bcfg.killtempl, DirSize);
          break;

        case 68:
          bcfg.defarea.passthr = 1;
          break;

        case 69:
          gettoken(level);
          bcfg.guard = token[0];
          break;

        case 70:
          gettoken(level);
          tokencpy(bcfg.netin, arealength - 1);
          break;

        case 71:
          gettoken(level);
          tokencpy(bcfg.netout, arealength - 1);
          break;

        case 72:
          gettoken(level);
          if(memicmp(token, "No", 2) == 0)
            bcfg.delkl = 1;
          break;

        case 73:
          gettoken(level);
          if(memicmp(token, "Memory", 6) == 0)
            bcfg.video = 1;
          break;

        case 74:
          gettoken(level);
          parseaddr(token, &(tuplink.upaddr), toklen);
          if(tuplink.upaddr.zone)
          {
            gettoken(level);
            tokencpy(tuplink.upname, 35);
            gettoken(level);
            tokencpy(tuplink.uppass, 71);
            gettoken(level);
            tokencpy(logout, DirSize);
            addhome(tuplink.echolist, logout);
            if(bcfg.uplname == NULL)
            {
              bcfg.uplname = (struct uplname *)myalloc(sizeof(struct uplname), __FILE__, __LINE__);
              tupl = bcfg.uplname;
            }
            else
            {
              tupl = bcfg.uplname;
              while(tupl->next)
                tupl = tupl->next;
              tupl->next = (struct uplname *)myalloc(sizeof(struct uplname), __FILE__, __LINE__);
              tupl = tupl->next;
            }
            memcpy(tupl, &tuplink, sizeof(struct uplname));
            tupl->next = NULL;
            bcfg.numupl++;
          }
          break;

        case 75:
          bcfg.killorph = 1;
          break;

        case 76:
          bcfg.hiderestr = 1;
          break;

        case 77:
          bcfg.sort = 1;
          if(!endstring[level])
          {
            gettoken(level);
            if(strnicmp(token, "Name", 4) == 0)
              bcfg.sort = 2;
            else if(strnicmp(token, "Group", 5) == 0)
              bcfg.sort = 4;
          }
          break;

        case 78:
          gettoken(level);
          bcfg.manlen = (short)atoi(token);
          if(bcfg.manlen < 60)
            bcfg.manlen = 60;
          if(bcfg.manlen > 78)
            bcfg.manlen = 78;
          break;

        case 79:
          gettoken(level);
          if(strnicmp(token, "Safe", 4) == 0)
            bcfg.safe = 1;
          else
            bcfg.safe = (short)atoi(token);
          // bcfg.safe=0;
          break;

        case 80:
          if(!level)
          {
            if(bcfg.incl == NULL)
            {
              bcfg.incl = (struct incl *)myalloc(szincl, __FILE__, __LINE__);
              tincl = bcfg.incl;
            }
            else
            {
              tincl = bcfg.incl;
              while(tincl->next)
                tincl = tincl->next;
              tincl->next = (struct incl *)myalloc(szincl, __FILE__, __LINE__);
              tincl = tincl->next;
            }
            tincl->next = NULL;
            gettoken(level);
            tokencpy(logout, DirSize);
            addhome(tincl->name, logout);
            bcfg.numincl++;
            sbuffer[1] = (char *)myalloc(4096, __FILE__, __LINE__);
            parser(tincl->name, level + 1);
            mystrncpy(confile, hfile, DirSize);
            myfree((void **)&(sbuffer[1]), __FILE__, __LINE__);
          }
          else
            ccprintf("Include in included file (%s, line %u) isn't allowed\r\n", file, lineno[level]);
          break;

        case 81:
          gettoken(level);
          tokencpy(logout, DirSize);
          addhome(bcfg.creatfile, logout);
          break;

        case 83:
          bcfg.nofresh = 1;
          break;

        case 84:
          gettoken(level);
          tokencpy(bcfg.busy, DirSize);
          if(bcfg.busy[toklen - 1] != DIRSEP[0])
            bcfg.busy[toklen] = DIRSEP[0];
          break;

        case 85:
          bcfg.scanall = 1;
          break;

        case 86:
          gettoken(level);
          if(*(token - 1) == '"')
            tokencpy(bcfg.fwdstr, BufSize);
          else
          {
            mystrncpy(bcfg.fwdstr, token, (short)(maxstr[level] - (token -::string)));
            temp = strchr(bcfg.fwdstr, '\r');
            if(temp)
              *temp = 0;
            temp = strchr(bcfg.fwdstr, '\n');
            if(temp)
              *temp = 0;
          }
          break;

        case 87:
          gettoken(level);
          bcfg.arcsize = atol(token);
          temp = token;
          while(isdigit(*temp++));
          temp--;
          if(toupper(*temp) == 'K')
            bcfg.arcsize <<= 10;
          break;

        case 88:
          gettoken(level);
          tokencpy(logout, DirSize);
          addhome(bcfg.edlist, logout);
          if((edlist =
              (short)sopen(bcfg.edlist, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
          {
            ccprintf("\r\nWARNING! Can't create AreaList %s\r\n", bcfg.edlist);
            edlist = 0;
          }
          else
          {
            chsize(edlist, 0);
            gettoken(level);
            tokencpy(bcfg.shablon, DirSize);
          }
          break;

        case 89:
          if(bcfg.dgate == NULL)
          {
            bcfg.dgate = (struct dngate *)myalloc(sizeof(struct dngate), __FILE__, __LINE__);
            tdn = bcfg.dgate;
          }
          else
          {
            tdn = bcfg.dgate;
            while(tdn->next)
              tdn = tdn->next;
            tdn->next = (struct dngate *)myalloc(sizeof(struct dngate), __FILE__, __LINE__);
            tdn = tdn->next;
          }
          tdn->next = NULL;
          memset(tdn, 0, sizeof(struct dngate));
          bcfg.numdg++;
          while(!endstring[level])
          {
            gettoken(level);
            switch (token[0])
            {
            case '<':
              parseaddr(token + 1, &(tdn->from), (short)(toklen - 1));
              break;
            case '>':
              parseaddr(token + 1, &(tdn->to), (short)(toklen - 1));
              break;
            case '=':
              parseaddr(token + 1, &(tdn->aka), (short)(toklen - 1));
              break;
            case '&':
              if(strnicmp(token + 1, "%Group", 6) == 0)
              {
                tdn->group = 1;
                gettoken(level);
                tokencpy(tdn->where, (short)(toklen > 52 ? 52 : toklen));
              }
              else
              {
                tdn->group = 0;
                if(strnicmp(token + 1, "%All", 4) == 0)
                  mystrncpy(tdn->where, "*", 39);
                else
                  mystrncpy(tdn->where, token + 1, (short)((toklen > arealength ? arealength : toklen) - 1));
              }
              break;
            case '$':
              mystrncpy(tdn->origin, token + 2, (short)((toklen > 72 ? 72 : toklen) - 2));
              break;
            case '%':
              for(i = 1; i < toklen; i++)
              {
                switch (toupper(token[i]))
                {
                case 'H':
                  tdn->changes |= 1;
                  break;
                case 'M':
                  tdn->changes |= 2;
                  break;
                case 'O':
                  tdn->changes |= 4;
                  break;
                case 'S':
                  tdn->changes |= 8;
                  break;
                }
              }
              break;
            }
          }
          break;

        case 90:
          gettoken(level);
          if(memicmp(token, "No", 2) == 0)
            bcfg.lookpath = 0;
          break;

        case 92:
          bcfg.analyse = 1;
          if(!endstring[level])
          {
            gettoken(level);
            if(memicmp(token, "Improved", 8) == 0)
              bcfg.analyse = 2;
          }
          break;

        case 93:
          bcfg.ktrash = 1;
          break;

        case 94:
          bcfg.netdupes = 1;
          break;

        case 95:
          bcfg.vsleep = 1;
          break;

        case 96:
          bcfg.passpurge = 1;
          break;

        case 97:
          bcfg.locked = 2;
          break;

        case 98:
          bcfg.delfiles = 1;
          break;

        case 99:
          bcfg.locked = 1;
          break;

        case 100:
          gettoken(level);
          tokencpy(bcfg.manfrom, 35);
          break;

        case 101:
          gettoken(level);
          tokencpy(logout, DirSize);
          addhome(bcfg.badtmpl, logout);
          break;

        case 102:
          while(!endstring[level])
          {
            gettoken(level);
            if(memicmp(token, "NoLock", 4) == 0)
              bcfg.locked = 1;
            else if(memicmp(token, "ToBad", 5) == 0)
              bcfg.locked = 2;
            else if(memicmp(token, "BackUp", 6) == 0)
              bcfg.locked = 4;
          }
          break;

        case 103:
          bcfg.savelog = 1;
          break;

        case 104:
          gettoken(level);
          if(memicmp(token, "Truncate", 8) == 0)
            bcfg.trunc = 1;
          break;

        case 105:
          gettoken(level);
          tokencpy(bcfg.netserv, arealength - 1);
          break;

        case 106:
          gettoken(level);
          tokencpy(bcfg.manffrom, 35);
          break;

        case 107:
          bcfg.fintl = 1;
          break;

        case 108:
          bcfg.kamikadze = 1;
          break;

        case 109:
          bcfg.sortarc = 1;
          break;

        case 110:
          bcfg.netlink = 1;
          if(!endstring[level])
          {
            gettoken(level);
            bcfg.maxnet = (short)atoi(token);
            if(bcfg.maxnet == 0)
              bcfg.maxnet = 1024;
          }
          else
            bcfg.maxnet = 1024;
          break;

        case 111:
          memset(&bladv, 0, sizeof(struct uplname));
          gettoken(level);
          parseaddr(token, &(bladv.upaddr), toklen);
          while(!endstring[level])
          {
            gettoken(level);
            switch (token[0])
            {
            case '#':
              mystrncpy(bladv.persarea, token + 1, (short)(toklen - 1));
              break;
            case '$':
              mystrncpy(bladv.echolist, token + 1, (short)(toklen - 1));
              k = (short)strlen(bladv.echolist);
              if(bladv.echolist[k - 1] != DIRSEP[0])
              {
                bladv.echolist[k] = DIRSEP[0];
                bladv.echolist[k + 1] = 0;
              }
              break;
            case '=':
              parseaddr(token + 1, &(bladv.myaka), (short)(toklen - 1));
              break;
            }
          }
          if(bcfg.bladv == NULL)
          {
            bcfg.bladv = (struct uplname *)myalloc(sizeof(struct uplname), __FILE__, __LINE__);
            tupl = bcfg.bladv;
          }
          else
          {
            tupl = bcfg.bladv;
            while(tupl->next)
              tupl = tupl->next;
            tupl->next = (struct uplname *)myalloc(sizeof(struct uplname), __FILE__, __LINE__);
            tupl = tupl->next;
          }
          memcpy(tupl, &bladv, sizeof(struct uplname));
          bcfg.numbladv++;
          break;

        case 112:
          bcfg.killadd = 1;
          break;

        case 113:
          bcfg.fixaddr = 1;
          break;

        case 114:
          bcfg.binkdlo = 1;
          break;

        case 115:
          gettoken(level);
          bcfg.minunp = atoi(token);
          temp = token;
          while(isdigit(*temp++));
          temp--;
          if(toupper(*temp) == 'K')
            bcfg.minunp <<= 10;
          break;

        case 116:
          gettoken(level);
          bcfg.mintoss = atoi(token);
          temp = token;
          while(isdigit(*temp++));
          temp--;
          if(toupper(*temp) == 'K')
            bcfg.mintoss <<= 10;
          break;

        case 117:
          gettoken(level);
          tokencpy(logout, DirSize);
          addhome(bcfg.badlog, logout);
          gettoken(level);
          tokencpy(bcfg.bshablon, DirSize);
          break;

        case 118:
          gettoken(level);
          tokencpy(bcfg.unname, DirSize);
          if(bcfg.unname[toklen - 1] != DIRSEP[0])
          {
            bcfg.unname[toklen] = DIRSEP[0];
            bcfg.unname[toklen + 1] = 0;
          }
          if(!endstring[level])
          {
            gettoken(level);
            if(strnicmp(token, "Kill", 4) == 0)
              bcfg.untkill = 1;
          }
          break;

        case 119:
          gettoken(level);
          bcfg.delproc = (short)atoi(token);
          if(bcfg.delproc > 100)
            bcfg.delproc = 100;
          if(bcfg.delproc)
            bcfg.analyse = 3;
          break;

        case 120:
          bcfg.gric = 1;
          break;

        case 121:
          bcfg.tossstat = 1;
          break;

        case 122:
          bcfg.sendstat = 1;
          break;

        case 124:
          if(bcfg.tgroup == NULL)
          {
            bcfg.tgroup = (struct incl *)myalloc(szincl, __FILE__, __LINE__);
            tgroup = bcfg.tgroup;
          }
          else
          {
            tgroup = bcfg.tgroup;
            while(tgroup->next)
              tgroup = tgroup->next;
            tgroup->next = (struct incl *)myalloc(szincl, __FILE__, __LINE__);
            tgroup = tgroup->next;
          }
          gettoken(level);
          tgroup->group = token[0];
          gettoken(level);
          tokencpy(tgroup->name, DirSize);
          tgroup->next = NULL;
          bcfg.numgr++;
          break;

        case 125:
          bcfg.showall = 1;
          break;

        case 126:
          bcfg.createbad = 1;
          break;

        case 127:
          bcfg.savepath = 1;
          break;

        case 131:
          gettoken(level);
          tokencpy(bcfg.workout, DirSize);
          break;

        case 132:
          gettoken(level);
          parseaddr(token, &tsnd, toklen);
          if(tsnd.zone)
          {
            bcfg.delseen.net = tsnd.net;
            bcfg.delseen.node = tsnd.node;
          }
          break;

        case 133:
          if(bcfg.names2 == NULL)
          {
            bcfg.names2 = (struct manname *)myalloc(sizeof(struct manname), __FILE__, __LINE__);
            tmname = bcfg.names2;
          }
          else
          {
            tmname = bcfg.names2;
            while(tmname->next)
              tmname = tmname->next;
            tmname->next = (struct manname *)myalloc(sizeof(struct manname), __FILE__, __LINE__);
            tmname = tmname->next;
          }
          tmname->next = NULL;
          bcfg.nummans2++;
          gettoken(level);
          tokencpy(tmname->name, 35);
          break;

        case 134:
          bcfg.selfaka = 1;
          break;

        case 135:
          bcfg.asavail = 1;
          break;

        case 136:
          bcfg.carbnet = 1;
          break;

        case 137:
          bcfg.stripext = 1;
          break;

        case 138:
          gettoken(level);
          tokencpy(bcfg.netsem, DirSize);
          break;

        case 139:
          bcfg.kamikadze = 0;
          break;

        case 140:
          bcfg.echoonly = 1;
          break;

        case 141:
          bcfg.single = 1;
          break;

        case 142:
          gettoken(level);
          bcfg.linkverb = (short)atoi(token);
          break;

        case 143:
          bcfg.transl = 1;
          break;

        case 144:
          gettoken(level);
          bcfg.levels = (short)atoi(token);
          break;

        case 145:
          gettoken(level);
          bcfg.rescdays = (short)atoi(token);
          break;

        case 146:
          bcfg.longfp = 1;
          break;

        case 147:
          gettoken(level);
          tokencpy(bcfg.echosem, DirSize);
          break;

        case 148:
          bcfg.setloc = 1;
          break;

        case 149:
          bcfg.asfull = 1;
          break;

        case 150:
          bcfg.dnccsy = 1;
          break;

        case 151:
          gettoken(level);
          tokencpy(bcfg.sbu, DirSize);
          break;

        case 152:
          gettoken(level);
          tokencpy(bcfg.sbp, DirSize);
          break;

        case 153:
          gettoken(level);
          tokencpy(bcfg.saua, DirSize);
          break;

        case 154:
          gettoken(level);
          tokencpy(bcfg.sau, DirSize);
          break;

        case 155:
          gettoken(level);
          tokencpy(bcfg.sap, DirSize);
          break;

        case 156:
          bcfg.logoutl = 1;
          break;

        case 157:
          gettoken(level);
          bcfg.boxstyle = (short)atoi(token);
          if(bcfg.boxstyle == 2)
            memcpy(bcfg.defdomain, token + 1, (((toklen - 1) > 8) ? 8 : (toklen - 1)));
          break;

        case 158:
          bcfg.test = 1;
          break;

        case 159:
          bcfg.dncbsy = 1;
          bcfg.dnccsy = 1;
          break;

        case 160:
          bcfg.dropbad = 1;
          break;

        case 161:
          bcfg.setdir = 1;
          break;

        case 162:
          bcfg.passci = 1;
          break;

        case 163:
          bcfg.rulesent = 1;
          break;

        case 164:
          bcfg.nocarbon = 1;
          break;

        case 166:
          gettoken(level);
          bcfg.deldays = (short)atoi(token);
          break;

        case 169: //"AreaAlias"
          {
            areaalias al;

            gettoken(level);
            parseaddr(token, &(al.linkaddr), toklen);
            gettoken(level);
            tokencpy(al.sarea, arealength);
            gettoken(level);
            tokencpy(al.darea, arealength);
            areaaliaslist.add_el(al);
          }
          break;

        case 170:
          bcfg.nrenum = 1;
          break;
        case 172:
          bcfg.dnsipkt = 1;
          break;
        case 173:
        case 176:
          bcfg.dncloselog = 1;
          break;
        case 174:
          bcfg.strip2fts = 1;
          break;
        case 175:
          bcfg.purgelr = 1;
          break;
        case 177:
          bcfg.dncfd = 1;
          break;
        case 178:
          bcfg.fixro = 1;
          break;
        case 179:
          gettoken(level);
          if(strnicmp(token, "NA", 2) == 0)
          {
            gettoken(level);
            tokencpy(bcfg.dalist, DirSize);
          };
          break;
        case 180:
          gettoken(level);
          if(strnicmp(token, "No", 2) == 0)
            bcfg.dnutid = 1;
          break;
        }
      }
      lineno[level] += numcr[level];
    }
    while(!endblock[level]);
  }
  cclose(&tsetf, __FILE__, __LINE__);
}
