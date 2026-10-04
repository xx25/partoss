// MaxiM: Slegka portirovana

#include "partoss.h"
#include "globext.h"

#include "morfiles.h"
#include "lowlevel.h"
#include "errors.h"
#include "environ.h"

#ifdef __DOS__
unsigned int far *psp = NULL;
#endif

void moreHandles (void)
{
#if defined( __OS2__ )
  long nulinc = 0;
  unsigned long curfh;
  DosSetRelMaxFH (&nulinc, &curfh);
  if (curfh < 50)
    {
      DosSetMaxFH (50);
      curfh = 50;
    }
  _grow_handles (curfh);
#elif defined( __NT__ )
  _grow_handles (50);
#elif defined( M_I386 )
  _grow_handles (50);
#elif defined(__linux__) || defined (__FreeBSD__)
#else
  int h[MAX_HANDLES], i /*,hcnta */ ;
  _grow_handles (MAX_HANDLES);
  memset (_openfd, 0xff, MAX_HANDLES * sizeof (unsigned short));
  _openfd[0] = O_RDONLY | O_TEXT;
  _openfd[1] = O_WRONLY | O_TEXT;
  _openfd[2] = O_WRONLY | O_TEXT;
  _openfd[3] = O_RDWR | O_BINARY;
  _openfd[4] = O_WRONLY | O_BINARY;
  memset (newHandleArray, 0xff, MAX_HANDLES);
  psp = (unsigned int *)MK_FP (_psp, 0x32);
  oldArray = (unsigned char far *)MK_FP (psp[2], psp[1]);
  memcpy (newHandleArray, oldArray, 5);
  oldcnt = psp[0];
  psp[0] = MAX_HANDLES;
  psp[1] = FP_OFF (newHandleArray);
  psp[2] = FP_SEG (newHandleArray);
  for (hcnt = 5; (h[hcnt] = open (NULL_DEV, O_RDONLY)) != -1; hcnt++) ;
  for (i = 5; i < hcnt; Close (h[i++])) ;
  psp[0] = hcnt;
  _grow_handles (hcnt);
#endif
}

void disableHandles (void)
{
#if defined(__DOS__) && !defined(M_I386)
  psp = (unsigned int *)MK_FP (_psp, 0x32);
  psp[1] = FP_OFF (oldArray);
  psp[2] = FP_SEG (oldArray);
  psp[0] = oldcnt;
#endif
}

void enableHandles (void)
{
#if defined(__DOS__) && !defined(M_I386)
  psp = (unsigned int *)MK_FP (_psp, 0x32);
  psp[1] = FP_OFF (newHandleArray);
  psp[2] = FP_SEG (newHandleArray);
  psp[0] = hcnt;
#endif
}

short closeHandles (void)
{
  short i, j = 0;
  for (i = 5; i < hcnt; i++)
    {
      if (newHandleArray[i] && newHandleArray[i] != 0xff)
	{
	  Close (newHandleArray[i]);
	  Close (i);
	  newHandleArray[i] = 0xff;
	  j++;
	}
    }
  return j;
}

unsigned rread (short handle, void *buf, unsigned len, char *file, short line)
{
  unsigned result;
  // ccprintf("* Read, source file %s, source line %u\r\n",file,line);
  if (handle == 0)
    errexit (4, file, line);
  result = read (handle, buf, len);
  // -1 is 65535 on 16-bit targets and 0xffffffff on 32-bit ones
  if (result == 65535u || result == (unsigned)-1 || result > len)
    errexit (7, file, line);
  return result;
}

// rread into a text buffer that has room for len + 2 bytes; two NULs
// follow the data, so string functions stop inside the buffer
unsigned rreadz (short handle, void *buf, unsigned len, char *file, short line)
{
  unsigned result = rread (handle, buf, len, file, line);
  ((char *)buf)[result] = 0;
  ((char *)buf)[result + 1] = 0;
  return result;
}

unsigned wwrite (short handle, void *buf, unsigned len, char *file,
		 short line)
{
  unsigned result;
  // ccprintf("* Write, source file %s, source line %u\r\n",file,line);
  if (handle == 0)
    errexit (4, file, line);
  result = write (handle, buf, len);
  if (result == 65535u)
    {
      if (errno != 6)
	errexit (7, file, line);
    }
  if (result < len)
    {
      if (diskfull == 0)
	{
	  diskfull = 1;
	  errexit (11, file, line);
	}
    }
  return result;
}

void cclose (short *handle, char *file, unsigned short line)
{
  // ccprintf("* Close, source file %s, source line %u\r\n",file,line);
  if (*handle)
    {
      Close (*handle);
      *handle = 0;
    }
  else
    errexit (4, file, line);
}

short mysopen (char *fname, short type, char *file, short line)
{
  short finish = 0, retfile;
  // ccprintf("* Sopen, source file %s, source line %u\r\n",file,line);
  while (!finish)
    {
      switch (type)
	{
	case 0:
	case 2:
	  retfile = (short)sopen (fname, O_RDONLY | O_BINARY, SH_DENYNO);
	  break;
	case 1:
	  retfile = (short)sopen (fname, O_RDWR | O_BINARY, SH_DENYWR);
	  break;
	}
      if (retfile == -1)
	switch (errno)
	  {
	  case ENOENT:
	    if (type == 0)
	      {
		mystrncpy (errname, fname, DirSize);
		errexit (6, file, line);
	      }
	    else
	      return -1;
	  case EMFILE:
	    mystrncpy (errname, fname, DirSize);
	    errexit (2, file, line);
	  case EACCES:
	    if (lich)
	      {
		logprintf ("Waiting for open %s", fname);
		logwrite (1, 1);
	      }
	    mtsleep (5);
	    break;
	  default:
	    mystrncpy (errname, fname, DirSize);
	    errexit (2, file, line);
	  }
      else
	finish = 1;
    }
//  ccprintf("Opened handle is %d\r\n",retfile);
  return retfile;
}
