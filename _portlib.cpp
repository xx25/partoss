//by SB 2:469/141

#ifndef __PORTLIB_C_
#define __PORTLIB_C_
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fnmatch.h>
#include <fcntl.h>
#include <time.h>

#include "lowlevel.h"
#include "partoss.h"
#include "globext.h"

#include "_dos.h"

#ifdef __DEBUG__
#define ccprintf printf
#endif

//#define DIR_MODE 0666
#define DIR_MODE 0777

#ifndef __EMX__
char *strupr(char *__string)
{
  int i, len;

  len = strlen(__string);
  for(i = 0; i < len; i++)
    __string[i] = toupper(__string[i]);
  return __string;
}

char *strlwr(char *__string)
{
  int i, len;

  len = strlen(__string);
  for(i = 0; i < len; i++)
    __string[i] = tolower(__string[i]);
  return __string;
}
#endif

long filelength(int __handle)
{
  off_t cur_pos = lseek(__handle, 0, SEEK_CUR);
  off_t len = lseek(__handle, 0, SEEK_END);

  lseek(__handle, cur_pos, SEEK_SET);
  return (long)len;
}

int spawnvp(int __mode, const char *__path, char *const *__argv)
{
  int pid, status;

#ifdef __DEBUG__
  ccprintf("spawnvp: %s\n", __path);
#endif
  pid = fork();
  if(pid == -1)
    return -1;
  if(pid == 0)
  {
    execvp(__path, __argv);
    _exit(127);                 // exec failed: do not go on as a second tosser
  }
  do
  {
    if(waitpid(pid, &status, 0) == -1)
    {
      if(errno != EINTR)
        return -10;
      else
        return -11;
    }
    else if(WIFEXITED(status))
    {
      return WEXITSTATUS(status);
    }
    else
      return -1;
  }
  while(1);
}

void _time2dos(time_t __dos_time, unsigned short *__date, unsigned short *__time)
{
/*
 struct tm *ftime;

 ftime=localtime(&__dos_time);

 *__date=((unsigned short)ftime->tm_mday & 0x001f)+((unsigned short)ftime->tm_mon & 0x01e0)+
         ((unsigned short)ftime->tm_year & 0xfe00);

 *__time=((unsigned short)ftime->tm_sec/2 & 0x001f)+((unsigned short)ftime->tm_min & 0x07e0)+
         ((unsigned short)ftime->tm_hour & 0xf800);
*/
  struct tm ftime;

  mylocaltime(&__dos_time, &ftime);

  *__date =
    ((unsigned short)ftime.tm_mday) +
    ((unsigned short)(ftime.tm_mon + 1) << 5) + ((unsigned short)(ftime.tm_year - 80) << 9);

  *__time =
    ((unsigned short)ftime.tm_sec >> 1) + ((unsigned short)ftime.tm_min << 5) + ((unsigned short)ftime.tm_hour << 11);
}

unsigned _dos_findfirst(const char *__path, unsigned __attr, struct find_t *__buf)
{
  int len = strlen(__path);
  int __handle;
  char __full_path[1024];
  struct dirent *__entry;
  struct stat __stat;
  unsigned ret = 0;
  char *char_format = "[%c%c]";
  int i;

  __buf->__entry = NULL;
  __buf->__pattern = NULL;
  __buf->__path_only = NULL;

  while((len > 0) && (__path[len - 1] != '/'))
    len--;
  if((len > 0) && (__path[len - 1] == '/'))
  {
    __buf->__path_only = (char *)calloc(len, 1);
    strncpy(__buf->__path_only, __path, len - 1);
  }
  else
    return 1;
#ifdef __DEBUG__
  ccprintf("d_pth1:'%s'\n", __buf->__path_only ? __buf->__path_only : "NULL");
#endif
  __buf->__entry = opendir(__buf->__path_only);
#ifdef __FreeBSD__
  __buf->dir_pos = 0;
#endif
  if(__buf->__entry == NULL)
  {
    if(errno != ENOENT)
      perror("opendir/_dos_findfirst error");
#ifdef __DEBUG__
    ccprintf("open(_src path): %s\n", __path);
    ccprintf("open: %s\n", __buf->__path_only);
#endif
    return 2;
  }
  __entry = readdir(__buf->__entry);
#ifdef __FreeBSD__
  __buf->dir_pos++;
#endif
#ifdef __DEBUG__
  ccprintf("d_name:'%s'\n", __entry ? __entry->d_name : "NULL");
#endif
  if(__entry == NULL)
  {
    return 3;
  }

  __buf->__pattern = (char *)calloc(4 * (strlen(__path) - strlen(__buf->__path_only)), 1);
  for(i = len; i < strlen(__path); i++)
  {
    if(isalpha(__path[i]))
    {
      sprintf(__buf->__pattern + strlen(__buf->__pattern), char_format, tolower(__path[i]), toupper(__path[i]));
    }
    else
    {
      __buf->__pattern[strlen(__buf->__pattern)] = __path[i];
    }
  }

//  __buf->__pattern =
//    (char *)calloc (strlen (__path) - strlen (__buf->__path_only), 1);
//  strncpy (__buf->__pattern, __path + (strlen (__buf->__path_only) + 1),
//         strlen (__path) - strlen (__buf->__path_only));
  memset(__full_path, 0, sizeof(__full_path));
  while(__entry != NULL)
  {
    ret = fnmatch(__buf->__pattern, __entry->d_name, 0);
#ifdef __DEBUG__
    ccprintf("d_rslt:%d '%s' '%s'\n", ret, __buf->__pattern, __entry->d_name);
#endif
    if(!ret)
    {
      strcpy(__buf->name, __entry->d_name);
      /*
         fill struct stat __stat 
       */
      snprintf(__full_path, sizeof(__full_path), "%s/%s", __buf->__path_only, __entry->d_name);
      __handle = open(__full_path, O_RDONLY);
      if(__handle == -1)
      {
        perror("open/_dos_findfirst error");
#ifdef __DEBUG__
        ccprintf("open(src path): %s\n", __buf->__path_only);
        ccprintf("open: %s\n", __full_path);
#endif
        ret = 3;
        break;
      }
      if(fstat(__handle, &__stat) == -1)
        perror("fstat error/_dos_findfirst");
      __buf->size = __stat.st_size;
      __buf->attrib = 0;
      _time2dos(__stat.st_mtime, &__buf->wr_date, &__buf->wr_time);
      if(__stat.st_mode & S_IFDIR)
        __buf->attrib &= 0x10;
      if(__stat.st_mode & S_IFDIR)
      {
        __entry = readdir(__buf->__entry);
#ifdef __FreeBSD__
        __buf->dir_pos++;
#endif
#ifdef __DEBUG__
        ccprintf("d_name:'%s'\n", __entry ? __entry->d_name : "NULL");
#endif
        continue;
      }
      if(close(__handle) == -1)
        perror("close/_dos_findfirst error");
#ifdef __DEBUG__
      ccprintf("Path: %s\n", __buf->__path_only);
      ccprintf("FullPath: %s\n", __full_path);
      ccprintf("Pattern: %s\n", __buf->__pattern);
      ccprintf("Found name: %s\n", __buf->name);
      ccprintf("Filesize: %u\n", __buf->size);
#endif
      memset(__full_path, 0, sizeof(__full_path));
#ifndef __FreeBSD__
      __buf->dir_pos = telldir(__buf->__entry);
#endif
      break;
    }
    if(ret)
    {
      __entry = readdir(__buf->__entry);
#ifdef __FreeBSD__
      __buf->dir_pos++;
#endif
#ifdef __DEBUG__
      ccprintf("d_name:'%s'\n", __entry ? __entry->d_name : "NULL");
#endif
      if(__entry == NULL)
      {
        ret = 3;
        break;
      }
    }
  }
#ifdef __DEBUG__
  ccprintf("Ret: %d\n", ret);
#endif
  if(__buf->__entry != NULL)
  {
    if(closedir(__buf->__entry))
      perror("closedir/_dos_findfirst error");
    else
      __buf->__entry = NULL;
  };
  return ret;
}

unsigned _dos_findnext(struct find_t *__buf)
{
  struct dirent *__entry;
  struct stat __stat;
  unsigned ret = 0;
  char __full_path[1024];
  int __handle;

#ifdef __FreeBSD__
  off_t __pos;
#endif

#ifdef __DEBUG__
  ccprintf("d_pth2:'%s'\n", __buf->__path_only ? __buf->__path_only : "NULL");
#endif
  __buf->__entry = opendir(__buf->__path_only);
  if(__buf->__entry == NULL)
  {
    if(errno != ENOENT)
      perror("opendir/_dos_findnext error");
    return 2;
  }
  memset(__full_path, 0, sizeof(__full_path));

#ifndef __FreeBSD__
  seekdir(__buf->__entry, __buf->dir_pos);
#else
  for(__pos = 0; __pos < __buf->dir_pos; __pos++)
    readdir(__buf->__entry);
#endif

  __entry = readdir(__buf->__entry);
#ifdef __FreeBSD__
  __buf->dir_pos++;
#endif

#ifdef __DEBUG__
  ccprintf("d_name:'%s'\n", __entry ? __entry->d_name : "NULL");
#endif
  if(__entry == NULL)
    ret = 3;
  while(__entry != NULL)
  {
    ret = fnmatch(__buf->__pattern, __entry->d_name, 0);
#ifdef __DEBUG__
    ccprintf("d_rslt:%d '%s' '%s'\n", ret, __buf->__pattern, __entry->d_name);
#endif
    if(!ret)
    {
      strcpy(__buf->name, __entry->d_name);
      /*
         fill struct stat __stat 
       */
      snprintf(__full_path, sizeof(__full_path), "%s/%s", __buf->__path_only, __entry->d_name);
      __handle = open(__full_path, O_RDONLY);
      if(__handle == -1)
      {
        perror("open/_dos_findnext error");
#ifdef __DEBUG__
        ccprintf("open(src path): %s\n", __buf->__path_only);
        ccprintf("open: %s\n", __full_path);
#endif
        ret = 3;
        break;
      }
      if(fstat(__handle, &__stat) == -1)
        perror("fstat error/_dos_findnext");
      __buf->size = __stat.st_size;
      __buf->attrib = 0;
      _time2dos(__stat.st_mtime, &__buf->wr_date, &__buf->wr_time);
      if(__stat.st_mode & S_IFDIR)
        __buf->attrib &= 0x10;
      if(__stat.st_mode & S_IFDIR)
      {
        __entry = readdir(__buf->__entry);
#ifdef __FreeBSD__
        __buf->dir_pos++;
#endif
#ifdef __DEBUG__
        ccprintf("d_name:'%s'\n", __entry ? __entry->d_name : "NULL");
#endif
        continue;
      }
      if(close(__handle) == -1)
        perror("close/_dos_findnext error");
      memset(__full_path, 0, sizeof(__full_path));
#ifndef __FreeBSD__
      __buf->dir_pos = telldir(__buf->__entry);
#endif
      break;
    }
    if(ret)
    {
      __entry = readdir(__buf->__entry);
#ifdef __FreeBSD__
      __buf->dir_pos++;
#endif
#ifdef __DEBUG__
      ccprintf("d_name:'%s'\n", __entry ? __entry->d_name : "NULL");
#endif
      if(__entry == NULL)
      {
        ret = 3;
        break;
      }
    }
  }
  if(__buf->__entry != NULL)
  {
    if(closedir(__buf->__entry))
      perror("closedir/_dos_findnext error");
    else
      __buf->__entry = NULL;
  }
  return ret;
}

unsigned _dos_findclose(struct find_t *__buf)
{
#ifdef __DEBUG__
  ccprintf("d_pth3:'%s'\n", __buf->__path_only ? __buf->__path_only : "NULL");
#endif
  if(__buf->__path_only != NULL)
  {
    free(__buf->__path_only);
    __buf->__path_only = NULL;
  };
  if(__buf->__pattern != NULL)
  {
    free(__buf->__pattern);
    __buf->__pattern = NULL;
  };
  if(__buf->__entry != NULL)
  {
    if(closedir(__buf->__entry))
      perror("closedir/_dos_findclose error");
    else
      __buf->__entry = NULL;
  }
  return errno;
}

char *itoa(int __value, char *__buf, int __radix)
{
  switch (__radix)
  {
  case 2:
    sprintf(__buf, "%o%c", __value, 0);
    break;
  case 10:
    sprintf(__buf, "%u%c", __value, 0);
    break;
  case 16:
    sprintf(__buf, "%x%c", __value, 0);
    break;
  default:
    printf("itoa: Unknown __radix: %d", __radix);
  }
#ifdef __DEBUG__
  ccprintf("(%s,%d) itoa: %s\n", __FILE__, __LINE__, __buf);
#endif
  return __buf;
}

void _dos_getdrive(unsigned *__drive)
{
}

void _dos_setdrive(unsigned __drivenum, unsigned *__drives)
{
}

int mkdir(const char *__path)
{
  if((mkdir(__path, DIR_MODE & ~umask_val)) == -1 && (errno != EEXIST))
    return -1;
  chmod(__path, DIR_MODE & ~umask_val);
  return 0;
}

int chsize(int __handle, long __size)
{
  return ftruncate(__handle, __size);
}

unsigned _dos_getftime(int __handle, unsigned short *__date, unsigned short *__time)
{
  struct stat __stat;

  if(fstat(__handle, &__stat) == -1)
  {
    perror("fstat/_dos_getftime error");
    return 1;
  }
  else
    _time2dos(__stat.st_mtime, __date, __time);
  return 0;
}

#endif
