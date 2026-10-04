// NetMailForward: copy of netmail to own addresses sent to another address

#include "partoss.h"
#include "globext.h"

#include "netfwd.h"
#include "buftomsg.h"
#include "chains.h"
#include "lowlevel.h"
#include "morfiles.h"

short fwdcopy = 0;              // set while the forwarded copy is written
short netstored = 0;            // set by buftomsg() when a message was stored

static struct addrchain fwdtargets = { NULL, NULL, 0 };
static struct kludge *fwdkludge = NULL;
static struct kludge **fwdintl = NULL;  // link where the new INTL goes
static char fwdtoname[36];

// Flags cleared on the copy: Crash, Received, Sent, File Attach, Orphan,
// Hold, Direct, FReq, RRQ, Update Request
#define FWDCLEAR (0x2 | 0x4 | 0x8 | 0x10 | 0x40 | 0x200 | 0x400 | 0x800 | 0x1000 | 0x8000)

static void fwdwarn (const char *what, short level)
{
  ccprintf ("NetMailForward: %s in %s (line %d)\r\n", what, confile,
	    lineno[level]);
}

static short iswild (struct myaddr *addr)
{
  return (short)(addr->zone == 65535u || addr->net == 65535u ||
		 addr->node == 65535u || addr->point == 65535u);
}

// Address match with wildcards on the rule side (as CarbonCopy)
static short matchaddr (struct myaddr *mask, struct myaddr *addr)
{
  return (short)((addr->zone == mask->zone || mask->zone == 65535u) &&
		 (addr->net == mask->net || mask->net == 65535u) &&
		 (addr->node == mask->node || mask->node == 65535u) &&
		 (addr->point == mask->point || mask->point == 65535u));
}

static void freekludges (struct kludge **chain)
{
  struct kludge *tkludge = *chain, *ttkludge = NULL;
  while (tkludge)
    {
      ttkludge = tkludge->next;
      myfree ((void **)&tkludge->str, __FILE__, __LINE__);
      myfree ((void **)&tkludge, __FILE__, __LINE__);
      tkludge = ttkludge;
    }
  *chain = NULL;
}

static struct kludge *newkludge (const char *str, short left)
{
  struct kludge *tkludge;
  tkludge = (struct kludge *)myalloc (szkludge, __FILE__, __LINE__);
  tkludge->str = (char *)myalloc ((unsigned)(strlen (str) + 1), __FILE__,
				  __LINE__);
  strcpy (tkludge->str, str);
  tkludge->left = left;
  tkludge->next = NULL;
  return tkludge;
}

static short iskludge (const char *str, const char *name)
{
  unsigned short len = (unsigned short)strlen (name);
  return (short)(strncmp (str, name, len) == 0 &&
		 (str[len] == 0 || str[len] == ' ' || str[len] == ':' ||
		  str[len] == '\r'));
}

static void fwdclear (void)
{
  fwdintl = NULL;
  deladdr (&fwdtargets);
  memset (&fwdtargets, 0, sizeof (fwdtargets));
  freekludges (&fwdkludge);
}

// NetMailForward[Exact] <name | %address> <target>
void fwdparse (short level, short exact)
{
  struct fwdrule rule, *trule = NULL;
  memset (&rule, 0, sizeof (rule));
  gettoken (level);
  tokencpy (logout, BufSize);
  if (logout[0] == '%')
    {
      parseaddr (logout + 1, &rule.match, (short)(toklen - 1));
      if (!rule.match.zone)
	{
	  fwdwarn ("bad address", level);
	  return;
	}
      rule.byaddr = 1;
    }
  else
    {
      if (strlen (logout) > 35)
	logout[35] = 0;
      mystrncpy (rule.name, logout, 35);
      if (!rule.name[0])
	{
	  fwdwarn ("missing name", level);
	  return;
	}
    }
  if (endstring[level])
    {
      fwdwarn ("missing target address", level);
      return;
    }
  gettoken (level);
  parseaddr (token, &rule.target, toklen);
  if (!rule.target.zone || iswild (&rule.target))
    {
      fwdwarn ("bad target address", level);
      return;
    }
  rule.exact = exact;
  rule.next = NULL;
  if (bcfg.fwdrules == NULL)
    {
      bcfg.fwdrules =
	(struct fwdrule *)myalloc (sizeof (struct fwdrule), __FILE__,
				   __LINE__);
      trule = bcfg.fwdrules;
    }
  else
    {
      trule = bcfg.fwdrules;
      while (trule->next)
	trule = trule->next;
      trule->next =
	(struct fwdrule *)myalloc (sizeof (struct fwdrule), __FILE__,
				   __LINE__);
      trule = trule->next;
    }
  memcpy (trule, &rule, sizeof (struct fwdrule));
}

// NetMailForwardSkip <name>
void fwdskipparse (short level)
{
  struct manname *tmname = NULL;
  if (bcfg.fwdskip == NULL)
    {
      bcfg.fwdskip =
	(struct manname *)myalloc (sizeof (struct manname), __FILE__,
				   __LINE__);
      tmname = bcfg.fwdskip;
    }
  else
    {
      tmname = bcfg.fwdskip;
      while (tmname->next)
	tmname = tmname->next;
      tmname->next =
	(struct manname *)myalloc (sizeof (struct manname), __FILE__,
				   __LINE__);
      tmname = tmname->next;
    }
  tmname->next = NULL;
  gettoken (level);
  tokencpy (tmname->name, 35);
}

// After the whole config is parsed: drop rules pointing to own addresses
void fwdcheck (void)
{
  struct fwdrule **prule = &bcfg.fwdrules, *trule = NULL;
  struct myaddr *taddr = NULL;
  while (*prule)
    {
      trule = *prule;
      taddr = bcfg.address.chain;
      while (taddr)
	{
	  if (cmpaddr (taddr, &trule->target) == 0)
	    break;
	  taddr = taddr->next;
	}
      if (taddr)
	{
	  ccprintf
	    ("NetMailForward: target %u:%u/%u.%u is our own address, rule ignored\r\n",
	     trule->target.zone, trule->target.net, trule->target.node,
	     trule->target.point);
	  *prule = trule->next;
	  myfree ((void **)&trule, __FILE__, __LINE__);
	}
      else
	prule = &trule->next;
    }
}

void fwdfree (void)
{
  struct fwdrule *trule = NULL, *ttrule = NULL;
  struct manname *tmname = NULL, *ttmname = NULL;
  fwdclear ();
  trule = bcfg.fwdrules;
  while (trule)
    {
      ttrule = trule->next;
      myfree ((void **)&trule, __FILE__, __LINE__);
      trule = ttrule;
    }
  bcfg.fwdrules = NULL;
  tmname = bcfg.fwdskip;
  while (tmname)
    {
      ttmname = tmname->next;
      myfree ((void **)&tmname, __FILE__, __LINE__);
      tmname = ttmname;
    }
  bcfg.fwdskip = NULL;
}

// Body is empty or whitespace only (the scanner would never pack the copy)
static short fwdempty (void)
{
  char buf[512];
  unsigned n, j;
  long l;
  if (!mbigmess)
    {
      for (l = 0; l < mtextlen && bufmess.text[l]; l++)
	if (!isspace (bufmess.text[l]))
	  return 0;
      return 1;
    }
  // big message: text follows the three names in tempmsg (buftomsg
  // rewinds tempmsg itself)
  lseek (tempmsg, mtolen + mfromlen + msubjlen + 3, SEEK_SET);
  while ((n = rread (tempmsg, buf, sizeof (buf), __FILE__, __LINE__)) != 0)
    for (j = 0; j < n; j++)
      {
	if (!buf[j])
	  return 1;
	if (!isspace (buf[j]))
	  return 0;
      }
  return 1;
}

// Called before buftomsg(2) for inbound netmail to an own address.
// Decides the targets while names and body are still intact and clones
// the kludge chain (without INTL/TOPT/FLAGS) for the copies.  The new INTL
// goes where the original one was (or to the end), so that MSGID/INTL/FMPT
// are seen by the scanner in the original order.
void fwdprepare (void)
{
  struct fwdrule *trule = NULL;
  struct manname *tmname = NULL;
  struct kludge *tkludge = NULL, **tail = NULL;
  struct myaddr from, to;
  char uto[36], uname[36];
  short match, i;
  netstored = 0;
  fwdclear ();
  if (bcfg.fwdrules == NULL)
    return;
  mystrncpy (fwdtoname, gltoname, 35);
  for (i = 0; i < 2; i++)
    {
      tmname = i ? bcfg.fwdskip : bcfg.names;
      while (tmname)
	{
	  if (stricmp (tmname->name, fwdtoname) == 0)
	    return;
	  tmname = tmname->next;
	}
    }
  memset (&from, 0, szmyaddr);
  from.zone = bufmess.fromzone;
  from.net = bufmess.fromnet;
  from.node = bufmess.fromnode;
  from.point = bufmess.frompoint;
  memset (&to, 0, szmyaddr);
  to.zone = bufmess.tozone;
  to.net = bufmess.tonet;
  to.node = bufmess.tonode;
  to.point = bufmess.topoint;
  mystrncpy (uto, fwdtoname, 35);
  strupr (uto);
  for (trule = bcfg.fwdrules; trule; trule = trule->next)
    {
      if (trule->byaddr)
	match = matchaddr (&trule->match, &to);
      else if (trule->exact)
	match = (short)(strcmp (trule->name, fwdtoname) == 0);
      else
	{
	  mystrncpy (uname, trule->name, 35);
	  strupr (uname);
	  match = (short)(strstr (uto, uname) != NULL);
	}
      if (match && cmpaddr (&trule->target, &from) != 0)
	addaddr (&fwdtargets, &trule->target);
    }
  if (!fwdtargets.numelem)
    return;
  if (fwdempty ())
    {
      logprintf ("Netmail for %s not forwarded: empty message",
	       fwdtoname);
      logwrite (1, 3);
      fwdclear ();
      return;
    }
  tail = &fwdkludge;
  for (tkludge = mckludge; tkludge; tkludge = tkludge->next)
    {
      if (iskludge (tkludge->str, "\1INTL") ||
	  iskludge (tkludge->str, "\1TOPT") ||
	  iskludge (tkludge->str, "\1FLAGS"))
	{
	  if (!fwdintl && iskludge (tkludge->str, "\1INTL"))
	    fwdintl = tail;
	  continue;
	}
      *tail = newkludge (tkludge->str, tkludge->left);
      tail = &(*tail)->next;
    }
  if (!fwdintl)
    fwdintl = tail;
}

// Called after buftomsg(2): writes one copy per target into NetMailOutbound
void fwdsend (void)
{
  struct myaddr *target = NULL;
  struct kludge *head = NULL, *rest = NULL;
  struct alists *flist = NULL;
  unsigned short tozone, tonet, tonode, topoint, flags, i;
  char kl[64];
  if (!fwdtargets.numelem)
    return;
  if (!netstored)
    {
      fwdclear ();
      return;
    }
  tozone = bufmess.tozone;
  tonet = bufmess.tonet;
  tonode = bufmess.tonode;
  topoint = bufmess.topoint;
  flags = bufmess.flags;
  for (target = fwdtargets.chain; target; target = target->next)
    {
      bufmess.tozone = target->zone;
      bufmess.tonet = target->net;
      bufmess.tonode = target->node;
      bufmess.topoint = target->point;
      bufmess.flags =
	(unsigned short)((flags & ~FWDCLEAR) | 0x80 | 0x20);
      // private chain: new INTL [+ TOPT] spliced into the cloned kludges
      sprintf (kl, "\1INTL %u:%u/%u %u:%u/%u", target->zone, target->net,
	       target->node, bufmess.fromzone, bufmess.fromnet,
	       bufmess.fromnode);
      rest = *fwdintl;
      head = newkludge (kl, 0);
      head->next = rest;
      if (target->point)
	{
	  sprintf (kl, "\1TOPT %u", target->point);
	  head->next = newkludge (kl, 0);
	  head->next->next = rest;
	}
      *fwdintl = head;
      mckludge = fwdkludge;
      fwdcopy = 1;
      buftomsg (2);
      fwdcopy = 0;
      *fwdintl = rest;
      if (head->next != rest)
	{
	  myfree ((void **)&head->next->str, __FILE__, __LINE__);
	  myfree ((void **)&head->next, __FILE__, __LINE__);
	}
      myfree ((void **)&head->str, __FILE__, __LINE__);
      myfree ((void **)&head, __FILE__, __LINE__);
      logprintf ("Netmail for %s forwarded to %u:%u/%u.%u", fwdtoname,
	       target->zone, target->net, target->node, target->point);
      logwrite (1, 3);
      if (!quiet)
	ccprintf ("%s\r\n", logout);
    }
  mckludge = pckludge;
  bufmess.tozone = tozone;
  bufmess.tonet = tonet;
  bufmess.tonode = tonode;
  bufmess.topoint = topoint;
  bufmess.flags = flags;
  // each area is scanned once per run - let the scan pick up the copies
  for (flist = rlist; flist; flist = flist->next)
    for (i = 0; i < flist->numlists; i++)
      if (flist->alist[i].type == 0 &&
	  stricmp (flist->alist[i].areaname, bcfg.netout) == 0)
	flist->alist[i].scanned = 0;
  needout = 1;
  fwdclear ();
}
