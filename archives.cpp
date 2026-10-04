// MaxiM: Ported

#include "partoss.h"
#include "globext.h"

#include "archives.h"
#include "lowlevel.h"
#include "morfiles.h"
#include "errors.h"

#if defined(__DOS__) && !defined(M_I386)

// #include <spawno.h>
#include "swapexec.hhh"

extern "C" unsigned pascal SwapExec(char *FileNameToSwap,
                                    char *ProgramToExecute, char *CommandString, unsigned Actions, unsigned EnvSeg);

#endif

#ifdef __DOS__
#define SHELL "COMMAND.COM"
#else
#if (defined(__linux__) && !defined(__EMX__)) || defined(__FreeBSD__)
#define SHELL "/bin/sh"
#else
#define SHELL "CMD.EXE"
#endif
#endif

int archiver(char *arcname, char *packname, short type)
// type = 1 - unpack
// type = 2 - pack
{
  short i = 0, arch = 0, numofarc = 0, types = 0;
  int retcode = 0;

#ifdef __NT__
  int childid;
#endif
  char sign[10], fulname[(DirSize + 1)], badname[(DirSize + 1)], packf[(DirSize + 1)];
  char *temp = NULL, *temp2 = NULL, *comtail = NULL;
  char *param[20];
  short j = 0, k = 0, numf = 0, ouf;
  struct packer arcdef;

#if HAVE_UNISTD_H
  int child_pid;
#endif
  if(type == 2 && arclen <= 0)
    return -1;
  numofarc = (short)(filelength(compset) / szpacker);
  lseek(compset, 0, SEEK_SET);
  if(type == 1)
  {
    mystrncpy(fulname, arcname, DirSize);
    arch = mysopen(fulname, 0, __FILE__, __LINE__);
  }
  for(i = 0; i < numofarc; i++)
  {
    rread(compset, &arcdef, szpacker, __FILE__, __LINE__);
    if(type == 1) // определяем архиватор по сигнатуре
    {
      if(arcdef.signoffs >= 0)
        lseek(arch, arcdef.signoffs, SEEK_SET);
      else
        lseek(arch, arcdef.signoffs - 1, SEEK_END);
      rread(arch, sign, 10, __FILE__, __LINE__);
      if(memcmp(arcdef.sign, sign, strlen(arcdef.sign)) == 0)
        break;
    }
    else
    {
      retcode = (strlen(arcdef.name) > strlen(defarc)) ? strlen(arcdef.name) : strlen(defarc);
      if(strnicmp(arcdef.name, defarc, retcode) == 0)
        break;
    }
  }
  if(type == 1)
    cclose(&arch, __FILE__, __LINE__);
  if(i < numofarc)
  {
    j = 0;
    if(type == 1 ? arcdef.extrbat : arcdef.addbat)
    {
      param[0] = (char *)myalloc((DirSize + 1), __FILE__, __LINE__);
      temp = getenv(SHELL_VAR);
      if(temp)
        mystrncpy(param[0], temp, DirSize);
      else
        mystrncpy(param[0], SHELL, sizeof(SHELL));
      param[1] = (char *)myalloc((CSSize + 1), __FILE__, __LINE__);
      mystrncpy(param[1], SHELL_OPT, 4);
      j = 2;
    }
    temp = (type == 1 ? arcdef.extr : arcdef.add);
    while(temp && *temp)
    {
      temp2 = temp;
      while((*temp2) && !isspace(*temp2) && ((*temp2) != '%'))
        temp2++;
      param[j] = (char *)myalloc((DirSize + 1), __FILE__, __LINE__);
      if((*temp2) == '%')
      {
        mystrncpy(param[j], temp, ((temp2 - temp) > DirSize) ? (short)DirSize : (short)(temp2 - temp));
        if(toupper(*(temp2 + 1)) == 'A')
        {
          mystrncat(param[j], (char *)(type == 1 ? fulname : arcname), DirSize, DirSize);
          temp2 += 2;
        }
        else
        {
          if(toupper(*(temp2 + 1)) == 'F')
          {
            mystrncat(param[j], packname, DirSize, DirSize);
            temp2 += 2;
            numf = j;
          }
          else
          {
            if(toupper(*(temp2 + 1)) == 'P')
            {
              mystrncat(param[j], bcfg.workdir, DirSize, DirSize);
              temp2 += 2;
            }
            else
            {
              mystrncat(param[j], temp2, 2, DirSize);
              temp2 += 2;
            }
          }
        }
      }
      else
      {
        if(*temp && ((*temp) == '%'))
        {
          if(toupper(*(temp + 1)) == 'A')
          {
            mystrncpy(param[j], type == 1 ? fulname : arcname, DirSize);
            temp2 += 2;
          }
          else
          {
            if(toupper(*(temp + 1)) == 'F')
            {
              mystrncpy(param[j], packname, DirSize);
              temp2 += 2;
              numf = j;
            }
            else
            {
              if(toupper(*(temp + 1)) == 'P')
              {
                mystrncpy(param[j], bcfg.workdir, DirSize);
                temp2 += 2;
              }
              else
                mystrncpy(param[j], temp, ((temp2 - temp) > DirSize) ? (short)DirSize : (short)(temp2 - temp));
            }
          }
        }
        else
          mystrncpy(param[j], temp, ((temp2 - temp) > DirSize) ? (short)DirSize : (short)(temp2 - temp));
      }
      while((*temp2) && isspace(*temp2))
        temp2++;
      temp = temp2;
      j++;
      if(j > 19)
        break;
    }
    for(k = j; k < 20; k++)
      param[k] = NULL;
    if(bcfg.quiet || quiet)
    {
      if(type == 1)
        ccprintf("Decompressing archive %s\r\n", arcname);
      else
        ccprintf("Compressing %lu bytes for %u:%u/%u.%u\r\n", arclen,
                 tpack->outaddr.zone, tpack->outaddr.net, tpack->outaddr.node, tpack->outaddr.point);

      hideout();

// #ifdef __DOS__
//
//       lpselect(1);
//       illpselect(0);
//
// #endif

    }
    if(type == 1)
      logprintf("Un%sing %s", arcdef.name, arcname);
    else
      logprintf("%sing %lu bytes for %u:%u/%u.%u", arcdef.name,
              arclen, tpack->outaddr.zone, tpack->outaddr.net, tpack->outaddr.node, tpack->outaddr.point);
    logwrite(1, 2);

#if HAVE_UNISTD_H
/*
        switch ( ( child_pid = vfork())) {
            case 0:
                {
#error You have a lot of job here!
                    execv( param[ 0], param);
                    exit( errno);
                }
            case -1:
                retcode = errno;
                break;
            default:
                {
                    // Due to complicated way of determining a reason
                    // for child termination and a lot of possible
                    // results we must think about a way to report
                    // all this information...
                    int status, rc;
                    do {
                        rc = waitpid( child_pid, &status, 0);
                    } while ( ( rc >= 0) && ( ! WIFSTOPPED( status)));
                    if ( rc == -1) {
                        retcode = errno;
                    }
                    else {
                        if ( WIFEXITED( status)) {
                            retcode = WEXITSTATUS( status);
                        }
                        else {
                            retcode = 255;
                        }
                    }
                }
        }
*/
#else /* HAVE_UNISTD_H */

#ifdef __DOS__
#ifndef M_I386

    if(bcfg.swapping)
    {
      disableHandles();
      comtail = (char *)myalloc((CSSize + 1), __FILE__, __LINE__);
      mystrncpy(comtail, " ", CSSize);
      for(k = 1; k < j; k++)
      {
        mystrncat(comtail, param[k], CSSize, CSSize);
        mystrncat(comtail, " ", 2, CSSize);
      }
      types = Ac_Dsk + Ac_Path + Ac_Used + Ac_SPrm + Ac_CoEx;
      if(bcfg.swaptype & 1)
        types |= Ac_Xms;
      if(bcfg.swaptype & 2)
        types |= Ac_Ems;
      retcode = SwapExec(bcfg.swapfile, param[0], comtail, types, 0);
      mystrncpy(packf, param[numf], DirSize);
      temp = strrchr(packf, '.');
      if(temp)
        temp[1] = 0;
      mystrncat(packf, "ouf", 6, DirSize);
      if(access(packf, 0) == 0)
      {
        ouf = open(packf, O_RDONLY | O_BINARY);
        endinput[0] = 0;
        while(!endinput[0])
        {
          readblock(ouf, 0);
          endblock[0] = 0;
          do
          {
            getstring(0);
            gettoken(0);
            tokencpy(packf, DirSize);
            mystrncpy(param[numf], packf, DirSize);
            mystrncpy(comtail, " ", CSSize);
            for(k = 1; k < j; k++)
            {
              mystrncat(comtail, param[k], CSSize, CSSize);
              mystrncat(comtail, " ", 2, CSSize);
            }
            SwapExec(bcfg.swapfile, param[0], comtail, types, 0);
          }
          while(!endblock[0]);
        }
        cclose(&ouf, __FILE__, __LINE__);
      }
      myfree((void **)&comtail, __FILE__, __LINE__);
      enableHandles();
    }
    else
#endif
#endif
/***ash `param` casting added ***/
#ifdef __NT__
/*      if(bcfg.test)
       {
        childid=spawnvp(P_NOWAIT,param[0],(char const * const *)param);
        cwait(&retcode,childid,WAIT_CHILD);
       }
      else*/
    {
      GetConsoleTitle(logout, BufSize);
#ifdef __BORLANDC__
      retcode = spawnvp(P_WAIT, param[0], (char *const *)param);
#else
      retcode = spawnvp(P_WAIT, param[0], (char const *const *)param);
#endif
      SetConsoleTitle(logout);
    }
#else
#if defined (__linux__) || defined (__FreeBSD__)
      retcode = spawnvp(P_WAIT, param[0], (char *const *)param);
#else
#ifdef __DOS__
      retcode = spawnvp(P_WAIT, param[0], (char const *const *)param);
#else
      retcode = spawnvp(P_WAIT, param[0], (char const *const *)param);
#endif
#endif
#endif
    mystrncpy(packf, param[numf], DirSize);
    temp = strrchr(packf, '.');
    if(temp)
      temp[1] = 0;
    mystrncat(packf, "ouf", 6, DirSize);
    if(access(packf, 0) == 0)
    {
      ouf = (short)open(packf, O_RDONLY | O_BINARY);
      if(filelength(ouf))
      {
        endinput[0] = 0;
        while(!endinput[0])
        {
          readblock(ouf, 0);
          endblock[0] = 0;
          do
          {
            getstring(0);
            gettoken(0);
            tokencpy(packf, DirSize);
            mystrncpy(param[numf], packf, DirSize);
#if defined (__linux__) || defined (__FreeBSD__)
            spawnvp(P_WAIT, param[0], (char *const *)param);
#else
#ifdef __DOS__
            spawnvp(P_WAIT, param[0], (char const *const *)param);
#else
#ifdef __NT__
            GetConsoleTitle(logout, BufSize);
#ifdef __BORLANDC__
            spawnvp(P_WAIT, param[0], (char *const *)param);
#else
            spawnvp(P_WAIT, param[0], (char const *const *)param);
#endif
            SetConsoleTitle(logout);
#endif
#endif
#endif
          }
          while(!endblock[0]);
        }
      }
      cclose(&ouf, __FILE__, __LINE__);
    }
#endif /* HAVE_UNISTD_H */

    if(bcfg.quiet || quiet)
      unhideout();

// #ifdef __DOS__
//
//     if(bcfg.quiet)
//       lpselect(0);
//
//
// #endif

    mystrncpy(packf, param[numf], DirSize);
    for(k = 0; k < j; k++)
      myfree((void **)&param[k], __FILE__, __LINE__);
    if(retcode == 0)
    {
      unlink(type == 1 ? fulname : packname);
      temp = strrchr(packf, '.');
      if(temp)
        temp[1] = 0;
      mystrncat(packf, "ouf", 6, DirSize);
      unlink(packf);
    }
    else
    {
      if(errno == ENOMEM)
        errexit(3, __FILE__, __LINE__);
      if(bcfg.renbad || (type != 1))
      {
        mystrncpy(badname, (type == 1) ? fulname : packname, DirSize);
        temp = strrchr(badname, '.');
        if(temp)
        {
          if(type == 1)
            temp[1] = 'b';
          else
          {
            temp[1] = 'o';
            temp[2] = 'u';
            temp[3] = 't';
          }
        }
        logprintf("??? Rename of file %s (Archiver's error %X)", (type == 1 ? fulname : packname), retcode);
        if(rrename((type == 1 ? fulname : packname), badname))
          strcat(logout, " fails");
        if(logfileok)
          logwrite(1, 1);
        if(!quiet)
          ccprintf("\r\n%s\r\n", logout);
      }
    }
  }
  else
  {
    logprintf("??? Unknown archive type - %s\r\n", type == 1 ? arcname : defarc);
    if(logfileok)
      logwrite(1, 1);
    ccprintf("\r\n%s\r\n", logout);
  }
//  cclose(&compset,__FILE__,__LINE__);
  return retcode;
}

void hideout(void)
{
  hdst = open(NULL_DEV, O_CREAT, S_IREAD | S_IWRITE);
  holdh = dup(1 /*stdout */ );
  dup2(hdst, 1);
  close(hdst);
  hdst2 = open(NULL_DEV, O_CREAT, S_IREAD | S_IWRITE);
  holdh2 = dup(2 /*stderr */ );
  dup2(hdst2, 2);
  close(hdst2);
}

void unhideout(void)
{
  dup2(holdh, 1);
  close(holdh);
  dup2(holdh2, 2);
  close(holdh2);
}
