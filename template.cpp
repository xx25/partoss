// MaxiM: Ported, not changed.

#include "partoss.h"
#include "globext.h"

#include "template.h"
#include "lowlevel.h"
#include "morfiles.h"
#include "errors.h"
#include "times.h"

short templat (short fhandle, short thandle)
{
  short retfile, i, numalias = 16, thnd;
  unsigned short j;
  char *alias[] = { "tfname", "tlname", "tname", "ffname", "flname",
                    "fname", "taddr", "faddr", "date", "time",
                    "text", "subj", "area", "version", "return",
                    "file:"
  };
  char *temp = NULL, *temp2 = NULL, *temp3 = NULL;
  retfile = (short)sopen (pttmpl, O_RDWR | O_BINARY | O_CREAT, SH_DENYWR,
                                  S_IRWXU| S_IRWXG | S_IRWXO);
  if (retfile == -1)
    {
      mystrncpy (errname, pttmpl, DirSize);
      errexit (2, __FILE__, __LINE__);
    }
  chsize (retfile, 0);
  lseek (thandle, 0, SEEK_SET);
  sbuffer[1] = (char *)myalloc (4097, __FILE__, __LINE__);
  endinput[1] = 0;
  while (!endinput[1])
    {
      readblock (thandle, 1);
      temp = strchr (sbuffer[1], 'ç');
      while (temp && (temp - sbuffer[1] < maxlen[1]))
	{
	  *temp = 'H';
	  temp = strchr (sbuffer[1], 'ç');
	}
      endblock[1] = 0;
      do
	{
	  getstring (1);
	  temp2 = ::string;
	  temp = (char *)memchr (temp2, 0x40, maxstr2[1]);
	  while ((temp2 - ::string) < maxstr2[1])
	    {
	      if (temp)
		{
		  wwrite (retfile, temp2, (unsigned short)(temp - temp2),
			  __FILE__, __LINE__);
		  for (i = 0; i < numalias; i++)
		    if (strnicmp (temp + 1, alias[i], strlen (alias[i])) == 0)
		      break;
		  switch (i)
		    {
		    case 0:
		      temp3 = strchr (bufpkt.toname, ' ');
		      if (temp3)
			wwrite (retfile, bufpkt.toname,
				(unsigned short)(temp3 - bufpkt.toname),
				__FILE__, __LINE__);
		      else
			mywrite (retfile, bufpkt.toname, __FILE__, __LINE__);
		      break;

		    case 1:
		      temp3 = strchr (bufpkt.toname, ' ');
		      if (temp3)
			{
			  while (isspace (*temp3))
			    temp3++;
			  mywrite (retfile, temp3, __FILE__, __LINE__);
			}
		      else
			mywrite (retfile, bufpkt.toname, __FILE__, __LINE__);
		      break;

		    case 2:
		      mywrite (retfile, bufpkt.toname, __FILE__, __LINE__);
		      break;

		    case 3:
		      temp3 = strchr (bufpkt.fromname, ' ');
		      if (temp3)
			wwrite (retfile, bufpkt.fromname,
				(unsigned short)(temp3 - bufpkt.fromname),
				__FILE__, __LINE__);
		      else
			mywrite (retfile, bufpkt.fromname, __FILE__,
				 __LINE__);
		      break;

		    case 4:
		      temp3 = strchr (bufpkt.fromname, ' ');
		      if (temp3)
			{
			  while (isspace (*temp3))
			    temp3++;
			  mywrite (retfile, temp3, __FILE__, __LINE__);
			}
		      else
			mywrite (retfile, bufpkt.fromname, __FILE__,
				 __LINE__);
		      break;

		    case 5:
		      mywrite (retfile, bufpkt.fromname, __FILE__, __LINE__);
		      break;

		    case 6:
		      logprintf ("%u:%u/%u.%u", bufpkt.tozone,
			       bufpkt.tonet, bufpkt.tonode, bufpkt.topoint);
		      mywrite (retfile, logout, __FILE__, __LINE__);
		      break;

		    case 7:
		      logprintf ("%u:%u/%u.%u", bufpkt.fromzone,
			       bufpkt.fromnet, bufpkt.fromnode,
			       bufpkt.frompoint);
		      mywrite (retfile, logout, __FILE__, __LINE__);
		      break;

		    case 8:
		      sftime = time (NULL);
		      mylocaltime (&sftime, &tmt);
		      mystrncpy (tstrtime, asctime (&tmt), 39);
		      converttime (tstrtime);
		      wwrite (retfile, ftstime, 9, __FILE__, __LINE__);
		      break;

		    case 9:
		      sftime = time (NULL);
		      mylocaltime (&sftime, &tmt);
		      mystrncpy (tstrtime, asctime (&tmt), 39);
		      converttime (tstrtime);
		      wwrite (retfile, ftstime + 11, 8, __FILE__, __LINE__);
		      break;

		    case 10:
		      if (fhandle)
			{
			  lseek (fhandle, 0, SEEK_SET);
			  while ((fmax =
				  (unsigned short)rreadz (fhandle, pktbuf,
							 buflen, __FILE__,
							 __LINE__)) != 0)
			    {
			      if (bcfg.transl)
				{
				  for (j = 0; j < fmax; j++)
				    {
				      if (pktbuf[j] == 'ç')
					pktbuf[j] = 'H';
				      if (pktbuf[j] == '‡')
					pktbuf[j] = 'p';
				    }
				}
			      wwrite (retfile, pktbuf, fmax, __FILE__,
				      __LINE__);
			    }
			}
		      break;

		    case 11:
		      mywrite (retfile, bufpkt.subj, __FILE__, __LINE__);
		      break;

		    case 12:
		      mywrite (retfile, newarea->areaname, __FILE__,
			       __LINE__);
		      break;

		    case 13:
		      mywrite (retfile, version, __FILE__, __LINE__);
		      break;

		    case 14:
		      mywrite (retfile, "\r", __FILE__, __LINE__);
		      break;

		    case 15:
		      temp2 = temp;
		      while (!isspace (*temp2))
			temp2++;
		      mystrncpy (logout, temp + 6, (short)(temp2 - temp - 6));
		      if ((thnd =
			   (short)sopen (logout, O_RDONLY | O_BINARY,
					 SH_DENYWR)) != -1)
			{
			  lseek (thnd, 0, SEEK_SET);
			  while ((fmax =
				  (unsigned short)rreadz (thnd, pktbuf, buflen,
							 __FILE__,
							 __LINE__)) != 0)
			    {
			      for (j = 0; j < fmax; j++)
				{
				  if (pktbuf[j] < 0x20 && pktbuf[j] != '\r'
				      && pktbuf[j] != '\n')
				    pktbuf[j] = 0x20;
				  if (bcfg.transl)
				    {
				      if (pktbuf[j] == 'ç')
					pktbuf[j] = 'H';
				      if (pktbuf[j] == '‡')
					pktbuf[j] = 'p';
				    }
				}
			      wwrite (retfile, pktbuf, fmax, __FILE__,
				      __LINE__);
			    }
			  cclose (&thnd, __FILE__, __LINE__);
			}
		      break;

		    default:
		      wwrite (retfile, temp, 1, __FILE__, __LINE__);
		      temp2 = temp;
		      break;
		    }
		  if (i < 15)
		    temp2 = temp + strlen (alias[i]);
		  temp2++;
		  temp =
		    (char *)memchr (temp2, 0x40,
				    (unsigned)(maxstr2[1] -
					       (temp2 - ::string)));
		}
	      else
		{
		  wwrite (retfile, temp2,
			  (unsigned short)(maxstr2[1] - (temp2 - ::string)),
			  __FILE__, __LINE__);
		  temp2 = ::string + maxstr2[1];
		}
	    }
	}
      while (!endblock[1]);
    }
  myfree ((void **)&sbuffer[1], __FILE__, __LINE__);
  lseek (retfile, 0, SEEK_SET);
  return retfile;
}
