// MaxiM: Slegka portirovana

/**************************************************************************
 * File: linkarea.cpp
 *
 * Copyright (C) 1998 by Vadim Belman (voland@plab.ku.dk)
 * Licensed for use in The Parma Tosser by Serge Koghin.
 *
 * Links a Squish(TM)-style message base in four different ways with the
 * highest possible speed.
 *
 **************************************************************************/

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
// #include <math.h>
#include <ctype.h>
#include <fcntl.h>
#if ! ((defined(__linux__) && !defined(__EMX__)) || defined (__FreeBSD__))
#include <io.h>
#else
#include <sys/param.h>
#endif
#include <sys/timeb.h>
#include <signal.h>

#include "partoss.h"
#include "globext.h"

#include "lowlevel.h"
#include "crc32.h"

//#define MALLOC_DEBUG
// LINK_PROFILE включает пpофилиpование по вpемени исполнения.
//#define LINK_PROFILE
//#define STANDALONE_VERSION
// TRAP_CATCHING есть смысл включать, если пpоисходит обвал по пpичине
// любого pода падений, пpиводящих к генеpиpованию сигналов. Hапpимеp -
// пpи вылете по SIGSEGV.
//#define TRAP_CATCHING
#if defined( STANDALONE_VERSION) && !defined( MALLOC_DEBUG)
#define USE_SYSALLOC
#endif

#define LINKTYPE_REPLY          1
#define LINKTYPE_SUBJ           2
#define LINKTYPE_FLAT           3
#define LINKTYPE_TIMED          4
#define LINKTYPE_NONE           5

// Здесь число заменяется на значение из конфига при встраивании в
// Портоса. bcfg.linklength, так кажется.
#define LINK_LENGTH             bcfg.linklength
// Если subj в заголовке может не оканчиваться 0, то здесь надо вписать 72
// Hо тогда - менять кучу мест в коде.
#define SUBJ_MAXLEN             71

#if defined( __DOS__) && !defined( __386__)
// Для 16bit pазмеpы хэшей будут поменьше, что пpиведет к небольшой потеpе скоpости,
// но память сэкономится.
#define HASH_MULTIPLIER 1
#else
#define HASH_MULTIPLIER 3
#endif

// myalloc и myfree - временные заглушки, чтобы не привязываться к главным сырцам.
// USE_SYSALLOC полезен, чтобы не комментаpить каждый pаз эти define'ы.
// В pабочем пpоекте его можно пpосто не опpеделять.
#if defined( MALLOC_DEBUG)
#define myalloc( sz, f, l)  dbg_malloc( ( sz), ( f), ( l))
#define myfree( pptr, f, l) dbg_free( ( pptr), ( f), ( l))
#define myrealloc( ptr, sz, f, l) dbg_realloc( ( ptr), ( sz), ( f), ( l))
#elif defined( USE_SYSALLOC)
#define myalloc( sz, f, l)  malloc( sz)
#define myfree( pptr, f, l) free( *( pptr))
#define myrealloc( ptr, sz, f, l) realloc( ( ptr), ( sz))
#endif

#ifdef STANDALONE_VERSION

#define LINKFVERBOSESTEP    0
#define AREANAME            "UNKNOWN.NAME.FOR.DEBUG"

#ifdef TRAP_CATCHING
int last_line_passed = -1;
#define SETLINE         { last_line_passed = __LINE__;}
#else
#define SETLINE
#endif

#else

#define LINKFVERBOSESTEP    bcfg.linkverb
#define AREANAME            newarea->areaname

#define SETLINE

#endif

//#ifdef __WATCOM10_6__
//#define ccprintf              cprintf
//#else
//#define ccprintf              printf
//#endif

// O_BINARY может быть не определен для не-DOS-derived библиотек (гарантированно -
// в libc BSD-семейства, например). Чтобы не пудрить себе мозги потом - определим
// как пустышку.
#ifndef O_BINARY
#define O_BINARY            0x0000
#endif

// Та же фигня - с _MAX_PATH. Пока берем определения из BSD'шного libc.
// Там видно будет.
#ifndef _MAX_PATH
#define _MAX_PATH           MAXPATHLEN
#endif

// Используется для проверки целостности заголовка фрейма в .SQD
#define SQHDRID       0xafae4453L

// Кое-какие локальные пеpеменные...
static unsigned long changed_count = 0;

#ifdef MALLOC_DEBUG

static unsigned long mem_alloced = 0, max_alloced = 0;

#pragma pack( 1)
typedef struct
{
  unsigned long size;
  char blk[];
}
dbg_memblk;
#pragma pack()

void dbg_prtstat ()
{
  fprintf (stderr, "Memory: %-8lu / %-8lu\r", mem_alloced, max_alloced);
}

void *dbg_malloc (size_t blksize, const char *file_name, unsigned file_line)
{
  dbg_memblk *p = (dbg_memblk *) malloc (blksize + sizeof (unsigned long));

  if (p == NULL)
    {
      fprintf (stderr, "Allocation of %ld bytes failed at line %u of %s\n",
	       blksize, file_line, file_name);
      exit (1);
    }

  mem_alloced += blksize;
  if (max_alloced < mem_alloced)
    {
      max_alloced = mem_alloced;
    }
  p->size = blksize;

  dbg_prtstat ();

  return (void *)p->blk;
}

void *dbg_realloc (void *ptr, size_t blksize, const char *file_name,
		   unsigned file_line)
{
  dbg_memblk *p = NULL;

  if (ptr != NULL)
    {
      p = (dbg_memblk *) ((char *)ptr - sizeof (unsigned long));
      mem_alloced -= p->size;
    }

  p = (dbg_memblk *) realloc (p, blksize + sizeof (unsigned long));
  if (p == NULL)
    {
      fprintf (stderr, "Reallocation failed (%ld bytes) at line %u of %s\n",
	       blksize, file_line, file_name);
      exit (1);
    }

  mem_alloced += blksize;
  if (max_alloced < mem_alloced)
    {
      max_alloced = mem_alloced;
    }
  p->size = blksize;

  dbg_prtstat ();

  return (void *)p->blk;
}

void dbg_free (void **ptr, const char *file_name, unsigned file_line)
{
  dbg_memblk *p;

  if (ptr == NULL)
    {
      fprintf (stderr,
	       "Can't free NULL pointer to pointer at line %u of %s\n",
	       file_line, file_name);
      exit (1);
    }
  if (*ptr == NULL)
    {
      fprintf (stderr, "Can't free NULL pointer at line %u of %s\n",
	       file_line, file_name);
      exit (1);
    }

  p = (dbg_memblk *) ((char *)(*ptr) - sizeof (unsigned long));
  mem_alloced -= p->size;

  dbg_prtstat ();

  free (p);

  *ptr = NULL;
}

#endif

#ifdef LINK_PROFILE
// time_diff и time_point могут быть использованы для профилирования
// кусков кода, когда счет времени идет на миллисекунды.
float timeb_diff (struct timeb &t1, struct timeb &t2)
{
  float tfm, tft;
  tfm = (((float)t1.millitm) - ((float)t2.millitm)) / 1000.;
  tft = ((float)t1.time) - ((float)t2.time);
  return tfm + tft;
}

float time_point ()
{
  static struct timeb pt;
  struct timeb curt;
  float diff;

  ftime (&curt);

  diff = timeb_diff (curt, pt);

  memcpy (&pt, &curt, sizeof (struct timeb));

  return diff;
}

void PROFILE (const char *comment = NULL)
{
  if (comment == NULL)
    {
      time_point ();
    }
  else
    {
      fprintf (stderr, "%-8.4f: %s", time_point (), comment);
    }
}

#else

// Будет вставлять комментаpии в код там, где в случае пpофилиpования
// нужны check-point'ы.
#define PROFILE( x)

#endif

//=========================================================================
// Working code
//=========================================================================

// Для заполнения хэша в качестве ключа достаточно использовать MSGID сам
// по себе - он достаточно случаен.

#pragma pack( 1)
typedef struct MsgInfo
{
  // Собственно заголовок мессаги, точнее - необходимые его куски
  char *subj;
  unsigned long replyto, nextreply[10];

  // Нижеследующее берется из индекса - чтоб мозги себе потом не пудрить
  // с увязкой индексов.
  long offset;
  unsigned long umsgid;
  // Теперь то, что просто может пригодиться.
  unsigned long msgid, reply_id;
  char changed;
  char processed;
  // Далее поля для типов линковки Flat/Reply и Subj. В общем - для
  // линейных, где нужны списки.
  MsgInfo *next, *prev;		// Указатели на следующее и предыдущее письма в
  // цепочке.
  MsgInfo *head;		// Указатель на голову списка.
  MsgInfo *last;		// Указатель на последний элемент в списке.
  // Действителен только у головного элемента списка.
  inline void mark_changed ()
  {
    if (!changed)
      {
	changed = 1;
	changed_count++;
      }
  }
}
 *PMsgInfo;

typedef struct HashElem
{
  PMsgInfo msg_info;
  HashElem *next;
}
 *PHashElem;

typedef struct Hash
{
  unsigned long size;		// Размер таблицы.
  unsigned long used;		// Число использованных слотов.
  unsigned long dupcount;	// Число слотов с более чем одним элементом.
  unsigned long elements;	// Число занесенных элементов.
  // Последние два поля - чисто для статистики.
  PHashElem *table;		// Собственно хэш-таблица, она же - массив
  // указателей на списки элементов.
  unsigned long (*hashFunc) (unsigned long, PMsgInfo);
  int (*cmpFunc) (PMsgInfo, PMsgInfo);
}
 *PHash;
#pragma pack()

//-------------------------------------------------------------------------
// Куски работы с хэшем
//-------------------------------------------------------------------------

// Генерация простого числа для размера хэша.
unsigned long gen_prime (unsigned long base)
{
  unsigned long i;
  // Нет смысла искать среди четных чисел, поэтому подгоняем минимум
  // под следующее нечетное или оставляем как есть.
  unsigned long atLeast = base + (base % 2 ? 0 : 1);

  // Перебираем кандидатов. Редко когда доведется перебрать больше
  // десяти чисел. Собственно, прямой подсчет для все простых меньше
  // 100000 дает среднюю разницу между двумя соседними ~10.4.
  // Правда для миллиона это значение уже ~12.7, но покажите мне такую
  // базу! 8)
  for (i = atLeast;; i += 2)
    {
      if ((i % 3) == 0)
	{
	  // Пpовеpяемое число делится на 3 - нет смысла в пеpебоpе делителей.
	  continue;
	}
      // Если число и имеет делитель - то он явно меньше корня квадратного
      // этого числа.
//        unsigned long divisor = ( unsigned long)sqrt( i);
      unsigned long divisor = (unsigned long)i / 2;
      // Подгоняем делитель под ближайшее сверху значение, которое допустимо
      // для перебора делителей. Допустимо - значит не кратно ни 3, ни 2.
      // Поизгалявшись можно было бы еще и кратные 5 отфутболивать, но "и
      // так неплохо". Как результат divisor может стать чуть больше корня
      // квадратного проверяемого числа, но это уже не страшно.
      divisor = (divisor / 3) * 3 + 2;
      // Шаг подобран как раз такой, чтобы пропускать все, что кратно 2 и 3.
      // Другими словами, для любого не кратного 2 и 3 числа D число меньшее
      // D на произведение на 2 остатка от деления D на 3 - число не кратное
      // 2 и 3. Доказательство оставляется в качестве упражнения. 8)
      for (; divisor > 3; divisor -= 2 * (divisor % 3))
	{
	  // Если вдруг проверяемое число разделилось без остатка, значит
	  // оно нам не подходит.
	  if ((i % divisor) == 0)
	    {
	      break;
	    }
	}
      // Все делители перебраны, а число не разделилось нацело; значит -
      // простое.
      if (divisor < 3)
	{
	  break;
	}
    }
  return i;
}

PHash createHash (unsigned long expectedElements,
		  unsigned long (*hashFunc) (unsigned long, PMsgInfo),
		  int (*cmpFunc) (PMsgInfo, PMsgInfo))
{
  PHash newHash;
  // Ориентировочно число элементов в хэш-таблице втрое большее чем
  // ожидаемое число элементов дает ~20% дубликатов (считая _все_ элементы).
  // Теория сообщает, что наивысшая эффективность хэша достигается при
  // его размере равном какому-либо простому числу.
  unsigned long hashSize = gen_prime (expectedElements * HASH_MULTIPLIER);

  if (expectedElements < 1)
    {
      expectedElements = 1;
    }

  newHash = (PHash) myalloc (sizeof (Hash), __FILE__, __LINE__);
#ifdef MALLOC_DEBUG
  fprintf (stderr, "\nAllocated new hash\n");
#endif
  newHash->size = hashSize;
  newHash->dupcount = newHash->used = newHash->elements = 0;
  newHash->table =
    (PHashElem *) myalloc (hashSize * sizeof (PHashElem), __FILE__, __LINE__);
#ifdef MALLOC_DEBUG
  fprintf (stderr, "\nAllocated new hash table for %d elements\n", hashSize);
#endif
  newHash->hashFunc = hashFunc;
  newHash->cmpFunc = cmpFunc;
  memset (newHash->table, 0, hashSize * sizeof (PHashElem));

  return newHash;
}

void destroyHash (PHash hash)
{
  int i;

  for (i = 0; i < hash->size; i++)
    {
      PHashElem curelem = hash->table[i];
      if (curelem != NULL)
	{
	  PHashElem next;
	  do
	    {
	      next = curelem->next;
	      myfree ((void **)&curelem, __FILE__, __LINE__);
	      curelem = next;
	    }
	  while (curelem);
	}
    }

  myfree ((void **)&hash->table, __FILE__, __LINE__);
  myfree ((void **)&hash, __FILE__, __LINE__);
}

void insertElement (PHash hash, PMsgInfo msgInfo)
{
  PHashElem hashElem;
  unsigned long offset;

  hashElem = (PHashElem) myalloc (sizeof (HashElem), __FILE__, __LINE__);
  hashElem->msg_info = msgInfo;

  // Смещение в хэш-таблице принимаем равным остатку от деления MSGID на
  // размер таблицы. С учетом уникальности MSGID, его, вообще говоря,
  // независимости от остальных MSGID в базе и вообще в идеале - полной
  // случайности, такой вариант хэш-функции дает весьма неплохие результаты,
  // которые вполне нас устраивают с точки зрения как эффективности
  // распределения элементов, так и скорости работы.
  offset = hash->hashFunc (hash->size, msgInfo);

  if (hash->table[offset] == NULL)
    {
      // Отмечаем, что число исползованных слотов сейчас увеличится.
      hash->used++;
    }
  else
    {
      hash->dupcount++;
    }
  // Либо у нас ячейка свободна - и тогда next просто обнуляется. Либо
  // она кем-то уже занята - и тогда это дает нам вставку нового элемента
  // в голову списка.
  hashElem->next = hash->table[offset];
  hash->table[offset] = hashElem;
  hash->elements++;
}

// Поиск нужного элемента по MSGID.
PMsgInfo findElement (PHash hash, PMsgInfo msgInfo)
{
  unsigned long offset = hash->hashFunc (hash->size, msgInfo);

  PHashElem elem = hash->table[offset];

  while (elem && (!hash->cmpFunc (elem->msg_info, msgInfo)))
    {
      elem = elem->next;
    }

  // На левые вопросы даем левые ответы: если такого msgid в слоте нет,
  // так ему и взяться там неоткуда. Разве только в результате баги разные
  // хэш-функции были заюзаны.
  return (elem == NULL ? NULL : elem->msg_info);
}

// Hash-функции для pаботы по MSGID
unsigned long hfMSGID (unsigned long hashSize, PMsgInfo msgInfo)
{
  return msgInfo->msgid % hashSize;
}

int cmpMSGID (PMsgInfo m1, PMsgInfo m2)
{
  return m1->msgid == m2->msgid;
}

// Hash-функции для работы с umsgid
// Особенность: вообще говоря, я так понимаю, что umsgid == смещение
// в массиве индексов + 1. Однако, поскольку уверенности в этом нет,
// то лучше иметь хэш для поиска по ним, хотя практически наверняка
// они в этом хэше расположатся линейно.
unsigned long hfumsgid (unsigned long hashSize, PMsgInfo msgInfo)
{
  return msgInfo->umsgid % hashSize;
}

int cmpumsgid (PMsgInfo m1, PMsgInfo m2)
{
  return m1->umsgid == m2->umsgid;
}

// Hash-функции для работы с Subj.

// Функция возвращает позицию в subj, на которой заканчиваются лидирующие
// пробелы и 'Re:', т.е. позицию, в которой собственно subj и сидит.
int cleanSubjPos (const char *subj)
{
  int i = 0;
  // Если subj должен заканчиваться 0, то оный 0 можно просто скипать.
  // Поэтому i < 71 а не 72. Впрочем, это ж какой subj должен быть, чтобы
  // условие сработало???
  while (i < SUBJ_MAXLEN && isspace (subj[i])
	 || (strnicmp (subj + i, "RE:", 3) == 0))
    {
      if (isspace (subj[i]))
	{
	  i++;
	}
      else
	{
	  i += 3;
	}
    }

  return i;
}

short subjLen (const char *subj, int *pos)
{
  *pos = cleanSubjPos (subj);
  int slen = strlen (subj + *pos);
  return (short)(slen < LINK_LENGTH ? slen : LINK_LENGTH);
}

unsigned long hfSubj (unsigned long hashSize, PMsgInfo msgInfo)
{
  int pos, blen;
  unsigned long crc;

  blen = subjLen (msgInfo->subj, &pos);
  crc = crc32block (msgInfo->subj + pos, (short)blen, (unsigned long)-1);

  return crc % hashSize;
}

int cmpSubj (PMsgInfo m1, PMsgInfo m2)
{
  int len1, pos1, len2, pos2;

  len1 = subjLen (m1->subj, &pos1);
  len2 = subjLen (m2->subj, &pos2);

  return (len1 == len2)
    && (strncmp (m1->subj + pos1, m2->subj + pos2, len1) == 0);
}

//-------------------------------------------------------------------------
// Куски работы с базой
//-------------------------------------------------------------------------

// str2MSGID - взамен strtoul. Быстpее получается.
unsigned long str2MSGID (char *str)
{
  unsigned long idval = 0, m;
  int i;
  char *p = (str[0] == '\001' ? str + 1 : str);
  char *p1 = strchr (p, '\001'), *p2 = strchr (p, '\000');
  // p1 и p2 кажут на ближайший следующий кладж - если такой есть, и конец
  // стpоки, соотв. p кажет на последний символ кладжа.
  p = ((p1 != NULL) && (p1 < p2) ? p1 : p2) - 1;
  for (i = (p - str), m = 1; (i >= 0) && isalnum (*p); i--, p--, m *= 16)
    {
      idval += m * (isalpha (*p) ? toupper (*p) - 'A' + 10 : *p - '0');
    }
  return idval;
}

// Вытаскиваем MSGID из кладжей.
unsigned long getMSGID (char *ctrl)
{
  char *p = strstr (ctrl, "\001MSGID:");
  if (!p)
    {
      return (unsigned int)0;
    }
  return str2MSGID (p);
}

// Вытаскиваем REPLY из кладжей.
unsigned long get_reply_id (char *ctrl)
{
  char *p = strstr (ctrl, "\001REPLY:");
  if (!p)
    {
      return (unsigned int)0;
    }
  return str2MSGID (p);
}

//-------------------------------------------------------------------------
// Реализация TimEd-стиля.
//-------------------------------------------------------------------------

void linkTimEd (PHash msghash, PHash umsghash, PMsgInfo msgs,
		unsigned long frames)
{
  unsigned long i, j;
  int firstempty, linked;
  MsgInfo tmpmsg;

  changed_count = 0;

  for (i = 0; i < frames; i++)
    {
      PMsgInfo rmsg;		// Сюда буем искать письмо, на которое текущее - ответ.

      if ((LINKFVERBOSESTEP > 0) && (((i /*+ 1 */ ) % LINKFVERBOSESTEP) == 0))
	ccprintf ("%s: linked %-6lu of %-6lu, changed %-6lu\r", AREANAME, i,
		  frames, changed_count);

      if (msgs[i].nextreply[0] != 0)
	{
	  // На всякий случай проверим - корректна ли первая ссылка
	  // в nextreply с точки зрения TimEd-типа. Она может оказаться
	  // некорректной если ранее использовался другой тип. Остальные
	  // nextreply не проверяем исходя из следующих предположений:
	  // а) древовидная линковка одна;
	  // б) мы ее делаем правильно (надеюсь 8);
	  // в) возможные некорректности - результат чьей-то кривости,
	  //    гонятся за которой не будем;
	  // г) главное: это может заметно присадить скорость работы.
	  tmpmsg.umsgid = msgs[i].nextreply[0];
	  PMsgInfo nextmsg = findElement (umsghash, &tmpmsg);
	  if ((!nextmsg) || (nextmsg->reply_id != msgs[i].msgid))
	    {
	      msgs[i].nextreply[0] = 0;
	      msgs[i].mark_changed ();
	    }
	}
      if (msgs[i].reply_id == 0)
	{
	  // Это вообще не ответ - так чего с ним возится?
	  continue;
	}
      tmpmsg.msgid = msgs[i].reply_id;
      rmsg = findElement (msghash, &tmpmsg);
      if (rmsg == NULL)
	{
	  // Нужной мессаги в базе нет - отваливаем.
	  if (msgs[i].replyto != 0)
	    {
	      // А раньше, похоже, была - replyto сохранился. Значит -
	      // сбрасываем в 0 и делаем пометку.
	      msgs[i].replyto = 0;
	      msgs[i].mark_changed ();
	    }
	  continue;
	}
      // А теперь одно из двух: либо эти две мессаги уже были слинкованы,
      // либо это еще предстоит сделать - и тогда нужно место в nextreply
      // чтобы в него прописать ссылку.
      firstempty = -1;
      linked = 0;
      if (msgs[i].replyto != rmsg->umsgid)
	{
	  // Кажется, мессага еще не линковалась. Или кто-то побил
	  // заголовок. Или ранее линковалось иначе. В любом случае -
	  // выставляем replyto.
	  msgs[i].replyto = rmsg->umsgid;
	  msgs[i].mark_changed ();
	}
      // Теперь выясняем или факт слинкованности мессаг, или местоположение
      // для ссылки в nextreply. По-пpежнему возможна ситуация несоpтиpованных
      // nextreply, но в обычной pаботе, похоже, это будет некpитично. В кpайнем
      // случае - можно будет "вpисовать" соpтиpовку пpи записи. Поскольку
      // в обычном случае менятся будет совсем небольшое число мессаг,
      // то этот оверхед не должен быть велик. Делать сортировку ранее записи
      // не стоит по соображениям скорости (чем меньше циклов гоняем - тем
      // оно лучше 8).
      for (j = 0; j < 10; j++)
	{
	  if (msgs[i].umsgid == rmsg->nextreply[j])
	    {
	      // Дальше продолжать нет смысла - тут "связисты уже были", и
	      // линки навели...
	      linked = 1;
	      break;
	    }
	  if (firstempty < 0 && rmsg->nextreply[j] == 0)
	    {
	      firstempty = j;
	    }
	}
      if (!linked && firstempty >= 0)
	{
	  rmsg->nextreply[firstempty] = msgs[i].umsgid;
	  rmsg->mark_changed ();
	}
      // Готово. К этому моменту все повязаны...
    }
  if (LINKFVERBOSESTEP > 0)
    ccprintf ("%s: linked %-6lu of %-6lu, changed %-6lu\r", AREANAME, i,
	      frames, changed_count);
}

//-------------------------------------------------------------------------
// Реализация линейных типов линковки для @MSGID/@REPLY.
//-------------------------------------------------------------------------

// Пробежка от заданного письма по линкам и связывание мессаг в список ответов.
// Предполагается, что заданное письмо является головой списка.
void markList (PHash umsghash, PMsgInfo msg)
{
  PMsgInfo curMsg = msg;
  MsgInfo tmpmsg;
  msg->head = msg;
  msg->last = msg;
  while (curMsg && (curMsg->nextreply[0] != 0))
    {
      tmpmsg.umsgid = curMsg->nextreply[0];
      curMsg->next = findElement (umsghash, &tmpmsg);
      if (curMsg->next)
	{
	  if (curMsg->next->reply_id == 0)
	    {
	      // Однако - выйти по списку на голову цепочки ответов! Явно
	      // нелады - рубить такую ссылку к чертям.
	      curMsg->nextreply[0] = 0;
	      curMsg->mark_changed ();
	      continue;
	    }
	  if (curMsg->next->prev == NULL)
	    {
	      curMsg->next->prev = curMsg;
	    }
	  else
	    {
	      // Не то в цикл влетели, не то на другой список наткнулись.
	      //
	      // Три возможных ситуации: В первом случае prev у найденного
	      // элемента не кажет на curMsg. Если кажет, то это может
	      // быть результатом прохода от какой-то мессаги вверх до упора
	      // и сборки всех писем по пути в список. Тогда будет позван
	      // markList для найденной головы списка, когда собсвенно сам
	      // список уже есть.
	      // Если prev кажет не на curMsg, то это может быть как
	      // цикл так и другой список. Выяснить можно по содержимому
	      // head: если совпадает с curMsg->head, то цикл.
	      //
	      // Во втором случае next найденного письма кажет на curMsg.
	      // Это значит, что две мессаги одна на другую ссылаются.
	      // Явный цикл, конечно же. 8)
	      //
	      // В третьем случае и вовсе ссылка на себя же.

	      if (curMsg->next->next == curMsg)
		{
		  curMsg->next->nextreply[0] = 0;
		}
	      if ((curMsg->next->prev != curMsg) ||
		  (curMsg->next->next == curMsg) || (curMsg->next == curMsg))
		{
		  curMsg->nextreply[0] = 0;
		  curMsg->mark_changed ();
		  continue;
		}
	    }
	  curMsg->next->head = msg;
	  curMsg->next->processed = 1;
	  // Еще неизвестно - есть ли продолжение у списка, так что на
	  // всякий случай - запомним найденное письмо как последнее в
	  // списке. Если вдруг его nextreply[ 0] не пуст, а поиск
	  // такого umsgid обломался - значит в базе непорядок, и лучше
	  // просто закрыть на это глаза. Если список вдруг будет продолжаться -
	  // некорректность автоматом перетрется.
	  msg->last = curMsg->next;
	}
      curMsg = curMsg->next;
    }
}

void linkLinear (PHash msghash, PHash umsghash, PMsgInfo msgs,
		 unsigned long frames, int linkType)
{
  PMsgInfo *fakemsgs;		// Сюда будем забрасывать фиктивные мессаги для случая,
  // когда reply есть, а оргинал ушел. Вместо оригинала
  // будет создаваться фиктив и запихиваться в хэш.
  // Для экономии памяти держать будем массив укзателей,
  // а фиктивы распределять по необходимости.
  unsigned long fakesize, fakechunk;
  unsigned long fakecount = 0;	// Количество реально имеющихся фиктивных мессаг.
  unsigned long i;
  MsgInfo tmpmsg;

  changed_count = 0;

  // Не думаю, чтобы число убитых писем, на которые есть ответы, было больше
  // четверти имеющихся в базе. Скорее всего - не наберется и 10-й части.
  // Но если все же даже такого массива не хватит - перераспределим по необходимости.
  // fakechunk введен для возможности перераспределения чтобы меньше морочить
  // себе голову - какими кусками наращивать массив фейков.
  if (linkType == LINKTYPE_REPLY)
    {
      fakesize = fakechunk = frames < 4 ? frames : frames / 4;
      fakemsgs =
	(PMsgInfo *) myalloc (sizeof (PMsgInfo) * fakesize, __FILE__,
			      __LINE__);
    }

  for (i = 0; i < frames; i++)
    {
      PMsgInfo rmsg, curMsg;

      if ((LINKFVERBOSESTEP > 0)
	  && (((i /* + 1 */ ) % LINKFVERBOSESTEP) == 0))
	ccprintf ("%s: linked %-6lu of %-6lu, changed %-6lu\r", AREANAME, i,
		  frames, changed_count);

      if (msgs[i].processed)
	{
	  // С этой мессагой уже поработали - нет смысла повторять.
	  continue;
	}
      msgs[i].processed = 1;
      if (msgs[i].reply_id == 0)
	{
	  // Имеем заведомую потенциальную голову списка. Имеет смысл
	  // проверить - а не слинкована ли она уже и быстренько пробежаться
	  // по линкам, промаркировать их и сформировать список.
	  // Заодно отбросится куча уже пролинкованных писем.
	  // Если пpи этом выясняется, что replyto непуст, то делаем вывод
	  // о том, что он остался от стаpых типов линковки и чистим.
	  if (msgs[i].replyto != 0)
	    {
	      msgs[i].replyto = 0;
	      msgs[i].mark_changed ();
	    }
	  markList (umsghash, msgs + i);
	  continue;
	}
      // Письмо является ответом, поэтому надо пробежаться вверх по
      // reply-цепочке, пока не найдем голову или не наткнемся на уже имеющийся
      // список. В общем случе. Частности - за if'ом. 8)
      curMsg = msgs + i;
      tmpmsg.msgid = curMsg->reply_id;
      rmsg = findElement (msghash, &tmpmsg);
      if (rmsg != NULL)
	{
	  while (rmsg)
	    {
	      if (rmsg->processed)
		{
		  // Оппа - а ведь это уже имющийся список.
		  // Будем привязываться к его хвосту. curMsg сейчас указывает
		  // на первый элемент в новой подцепочке.
		  PMsgInfo head = rmsg->head;
		  PMsgInfo last = head->last;
		  last->next = curMsg;
		  curMsg->prev = last;
		  last->nextreply[0] = curMsg->umsgid;
		  last->mark_changed ();
		  curMsg->replyto = last->umsgid;
		  curMsg->mark_changed ();

		  // Отметим в голове списка, что последний элемент теперь
		  // другой.
		  head->last = msgs + i;

		  // А теперь прийдется пробежаться от curMsg вниз по новому
		  // подсписку и прописать везде head.
		  while (curMsg)
		    {
		      curMsg->head = head;
		      curMsg = curMsg->next;
		    }

		  // И хватит с этим. Пора двигать к следующей мессаге.
		  break;
		}

	      if (curMsg->replyto != rmsg->umsgid)
		{
		  // Письмо еще не линковалось или было слинковано некорректно.
		  // Это надо фиксить.
		  curMsg->replyto = rmsg->umsgid;
		  curMsg->mark_changed ();
		}
	      if (rmsg->nextreply[0] != curMsg->umsgid)
		{
		  // Почти та же фигня: либо в nextreply сидят остатки
		  // ранее использовавшегося типа линковки, либо письмо
		  // вообще еще не подвергалось обработке.
		  rmsg->nextreply[0] = curMsg->umsgid;
		  rmsg->mark_changed ();
		}

	      // Увязываем пару писем и топаем дальше вверх.
	      curMsg->prev = rmsg;
	      rmsg->next = curMsg;

	      curMsg = rmsg;
	      curMsg->processed = 1;
	      if (curMsg->reply_id != 0)
		{
		  // Это все еще ответ на какое-то другое письмо. Попробуем
		  // его найти.
		  tmpmsg.msgid = curMsg->reply_id;
		  rmsg = findElement (msghash, &tmpmsg);
		}
	      else
		{
		  // А вот теперь добрались до головы нового списка.
		  rmsg = NULL;
		}
	    }
	  // Здесь у нас возможны два случая. Либо rmsg не NULL - значит
	  // новый подсписок уже подлинковали к хвосту имеющегося. Значит
	  // пора переходить к следующей мессаге.
	  // Если же rmsg == NULL, то нашли новый список и curMsg сейчас
	  // является его головой. Значит далее ведем себя как если бы
	  // сразу не нашли оригинал для msgs[ i].
	  if (rmsg != NULL)
	    {
	      continue;
	    }
	}
      // Здесь curMsg - ответ без оригинала или голова нового списка.
      // В первом случае зависим от типа линковки.
      if (curMsg->replyto != 0)
	{
	  // Чистим возможные остатки после смены типа линковки.
	  // В самом деле: какой может быть replyto у головы списка?
	  curMsg->replyto = 0;
	  curMsg->mark_changed ();
	}
      if (linkType == LINKTYPE_FLAT || curMsg->reply_id == 0)
	{
	  // Если Flat - то принимаем мессагу за голову и строим от этой
	  // головы новый список.
	  markList (umsghash, curMsg);
	}
      else
	{
	  // Если REPLY - то создаем fake-письмо для оригинала и
	  // оно выполнит роль головы нового списка.
	  if (fakecount == fakesize)
	    {
	      // Список fake'ов полон. Надо поднарастить storage.
	      fakesize += fakechunk;
	      fakemsgs =
		(PMsgInfo *) myrealloc (fakemsgs,
					sizeof (PMsgInfo) * fakesize,
					__FILE__, __LINE__);
	    }
	  fakemsgs[fakecount] =
	    (PMsgInfo) myalloc (sizeof (MsgInfo), __FILE__, __LINE__);
	  memset (fakemsgs[fakecount], 0, sizeof (MsgInfo));

	  fakemsgs[fakecount]->processed = 1;
	  fakemsgs[fakecount]->msgid = curMsg->reply_id;

	  fakemsgs[fakecount]->nextreply[0] = curMsg->umsgid;

	  // Теперь этот фиктив нужен нам в хэше. Точнее - может понадобится
	  // позже, для увязки и по @REPLY.
	  insertElement (msghash, fakemsgs[fakecount]);

	  markList (umsghash, fakemsgs[fakecount]);

	  fakecount++;
	}
    }
  if (LINKFVERBOSESTEP > 0)
    ccprintf ("%s: linked %-6lu of %-6lu, changed %-6lu\r", AREANAME, i,
	      frames, changed_count);

  // Подчищаем за собой память...
  if (linkType == LINKTYPE_REPLY)
    {
      for (i = 0; i < fakecount; i++)
	{
	  myfree ((void **)&(fakemsgs[i]), __FILE__, __LINE__);
	}
      myfree ((void **)&fakemsgs, __FILE__, __LINE__);
    }
}

//-------------------------------------------------------------------------
// Реализация линковки по Subj
//-------------------------------------------------------------------------

void linkSubj (PMsgInfo msgs, unsigned long frames)
{
  unsigned long i;
  // Хэш для голов списков линковки по Subj.
  PHash smsghash;

  changed_count = 0;

  // Расчитываем, что списков линков по Subj будет не больше, чем треть от
  // общего числа писем.
  smsghash = createHash (frames / 3, hfSubj, cmpSubj);

  for (i = 0; i < frames; i++)
    {
      PMsgInfo hmsg, curMsg;

      if ((LINKFVERBOSESTEP > 0)
	  && (((i /* + 1 */ ) % LINKFVERBOSESTEP) == 0))
	ccprintf ("%s: linked %-6lu of %-6lu, changed %-6lu\r", AREANAME, i,
		  frames, changed_count);

      if (msgs[i].processed)
	{
	  // Тут мы уже побывали - можно и не проверять.
	  continue;
	}

      // Пытаемся найти голову списка писем для subj текущего письма.
      // Если облом - значит есть повод начать новый список. Нет - значит
      // вставляем новое письмо в хвост.
      curMsg = msgs + i;
      curMsg->processed = 1;
      // Стpанная для Subj линковка - назад. Видимо остаток pанее использовавшейся.
      if ((curMsg->nextreply[0] != 0)
	  && (curMsg->nextreply[0] <= curMsg->umsgid))
	{
	  curMsg->nextreply[0] = 0;
	  curMsg->mark_changed ();
	}
      hmsg = findElement (smsghash, curMsg);
      if (hmsg != NULL)
	{
	  PMsgInfo last = hmsg->last;

	  curMsg->head = hmsg;
	  curMsg->prev = last;
	  last->next = curMsg;

	  if (curMsg->replyto != last->umsgid)
	    {
	      // Письмо еще не линковалось или было слинковано некорректно.
	      // Это надо фиксить.
	      curMsg->replyto = last->umsgid;
	      curMsg->mark_changed ();
	    }
	  if (last->nextreply[0] != curMsg->umsgid)
	    {
	      // Почти та же фигня: либо в nextreply сидят остатки
	      // ранее использовавшегося типа линковки, либо письмо
	      // вообще еще не подвергалось обработке.
	      last->nextreply[0] = curMsg->umsgid;
	      last->mark_changed ();
	    }

	  hmsg->last = curMsg;
	}
      else
	{
	  // Списка с таким subj похоже нет. Значит будем начинать новый.

	  insertElement (smsghash, curMsg);

	  curMsg->head = curMsg;
	  curMsg->last = curMsg;
	  if ((curMsg->replyto != 0))
	    {
	      curMsg->replyto = 0;
	      curMsg->mark_changed ();
	    }

	  // Hафиг я это делал? Чистятся же и ноpмальные ссылки впеpед,
	  // если они есть... 8-\ Пpавда, если этого не делать, то могут
	  // оставаться некоppектные ссылки впеpед пpи смене типов линковок.
	  // Hо лучше так, чем каждый pаз пpактически все пеpезаписывать.
	  //curMsg->nextreply[ 0] = 0;

	  // Вообще говоря, инициализация head для линковки по subj излишня,
	  // но лучше ее иметь, если понадобится в будущем.
	}
    }
  if (LINKFVERBOSESTEP > 0)
    ccprintf ("%s: linked %-6lu of %-6lu, changed %-6lu\r", AREANAME, i,
	      frames, changed_count);

  destroyHash (smsghash);
}

//-------------------------------------------------------------------------
// Реализация линковки вообще... 8)
//-------------------------------------------------------------------------
// Собственно функция для линковки. Принимает имя файла с базой без расширения
// и тип линковки.
// Например: \fido\sqbase\A0001112
// Тогда ожидаем наличия файлов \fido\sqbase\A0001112.sqd и
// \fido\sqbase\A0001112.sqi.
// Функция возвращает 0 если все прошло успешно или код ошибки. Другой
// обработки ошибок предусматриваться не будет до момента встраивания
// в partoss.
int linkArea (const char *areaFile, int linkType)
{
  sqifile *index;		// Storage для индекса.
  long i;
  int hi, hd;			// Хендлы для файловых операций.
  // hi - для индекса, hd - для базы.
  char index_file[_MAX_PATH], base_file[_MAX_PATH];
  struct stat idxst;		// Сюда положим информацию о файле индексов.
  int rd;			// Сюда будем запихивать результат read'а.
  unsigned long frames;		// Число фреймов в базе
  PMsgInfo msgs;		// Массив данных о мессагах.
  PHash msghash, umsghash;	// Хэши с индексированием по MSGID и umsgid соотв.
  unsigned long zero_array[10] = { 0 };
  // Этого будем использовать при проверке наличия
  // чего-либо в последних 9 элементах nextreply[]
  // вычитанного заголовка.

  int ctrlsize = 1024;		// Размер буффера для кладжей
  char *ctrl;			// Собственно буффер. Пока не распределенный. 8)

  snprintf (index_file, sizeof (index_file), "%s.sqi", areaFile);
  snprintf (base_file, sizeof (base_file), "%s.sqd", areaFile);

  // Доступ на чтение не запрещаем - менять ничего в файле не будем.
  hi = sopen (index_file, O_RDONLY | O_BINARY, SH_DENYWR);
  if (hi == -1)
    {
      return 1;
    }
  // А здесь, от греха подальше, чтение рубим нафиг, поскольку позже сюда же
  // будем писать.
  hd = sopen (base_file, O_RDWR | O_BINARY, SH_DENYRW);
  if (hd == -1)
    {
      close (hi);
      return 2;
    }

  PROFILE (NULL);

  // Читаем индексы и получаем число pабочих фpеймов.
  fstat (hi, &idxst);
  if (idxst.st_size == 0)
    {
      close (hi);
      close (hd);
      return 0;
    }
  index = (sqifile *) myalloc (idxst.st_size, __FILE__, __LINE__);
  rd = read (hi, index, idxst.st_size);
  // Все, начиная с этого момента файл индексов нас больше не интересует.
  close (hi);
  if (rd != idxst.st_size)
    {
      // Ну я же просил 400 капель, а здесь - 398! 8( 8)
      close (hd);
      return 3;
    }
  frames = idxst.st_size / sizeof (sqifile);

  // Соотв. и pаспpеделяем под инфоpмашку о мессагах ...
  msgs = (PMsgInfo) myalloc (sizeof (MsgInfo) * frames, __FILE__, __LINE__);
#ifdef MALLOC_DEBUG
  fprintf (stderr, "\nAllocated msgs for %lu frames\n", frames);
#endif

  // Теперь на нужен буффер для кладжей...
  // Здесь и далее ( ctrlsize + 1) поскольку ctrlsize - это _чистый_ размер
  // кладжей без учета концевого 0.
  ctrl = (char *)myalloc (ctrlsize + 1, __FILE__, __LINE__);
  // ... и хэши для работы, ...
  msghash = createHash (frames, hfMSGID, cmpMSGID);
  umsghash = createHash (frames, hfumsgid, cmpumsgid);

  // ... и погнали вычитку из базы.
  int zero = 0;
  sqdmshead hdr;
  int subjoffs = (int)(hdr.subj - (char *)&hdr);
  int replyoffs = (int)((char *)&hdr.replyto - (char *)&hdr);
  int replysize = sizeof (unsigned long) * 11;
  unsigned long ident, clen;

  PROFILE ("reading of SQD started\n");

  for (i = 0; i < frames; i++)
    {

      if ((LINKFVERBOSESTEP > 0)
	  && (((i /* + 1 */ ) % LINKFVERBOSESTEP) == 0))
	{
	  ccprintf ("%s: read %-6lu of %-6lu\r", AREANAME, i, frames);
	}

      // Вычитываем необходимые куски заголовков.
      lseek (hd, index[i].offset, SEEK_SET);
      rd = read (hd, &ident, sizeof (unsigned long));
      if ((rd != sizeof (unsigned long)) || (ident != SQHDRID))
	{
	  close (hd);
	  return 4;
	}
      lseek (hd, 16, SEEK_CUR);	// Сдвигаемся к clen
      rd = read (hd, &clen, sizeof (unsigned long));
      if (rd != sizeof (unsigned long))
	{
	  close (hd);
	  return 4;
	}
      if (linkType == LINKTYPE_SUBJ)
	{
	  char buf[SUBJ_MAXLEN + 1];
	  lseek (hd, 80, SEEK_CUR);	// Сдвигаемся к subj если тип линковки его тpебует.
	  // Выделяем место под subj.
	  rd = read (hd, buf, SUBJ_MAXLEN + 1);
	  if (rd != (SUBJ_MAXLEN + 1))
	    {
	      close (hd);
	      return 4;
	    }
	  buf[SUBJ_MAXLEN] = 0;
	  int slen = strlen (buf) + 1;
	  // Здесь можно было бы воспользоваться strdup, но это не всегда
	  // безопасно, когда используются не стандаpтные сpедства pаспpеделения
	  // памяти. Поэтому лучше сделать все вpучную, да и dbg_* не будут
	  // вpать пpи pаспpеделении. 8)
	  msgs[i].subj = (char *)myalloc (slen, __FILE__, __LINE__);
	  memcpy (msgs[i].subj, buf, slen);
	  lseek (hd, 26, SEEK_CUR);	// Сдвигаемся к replyto
	}
      else
	{
	  // По subj линковать не нужно - пpосто пpопускаем соотв. куски в
	  // заголовке.
	  lseek (hd, 178, SEEK_CUR);
	  msgs[i].subj = NULL;
	}
      rd = read (hd, &msgs[i].replyto, replysize);
      if (rd != replysize)
	{
	  close (hd);
	  return 4;
	}
      lseek (hd, 20, SEEK_CUR);
      // Если вдруг размер кладжей в письме больше, чем ожидалось, то
      // нарастим буффер.
      if (clen > ctrlsize)
	{
	  ctrlsize = clen;
	  ctrl = (char *)myrealloc (ctrl, ctrlsize + 1, __FILE__, __LINE__);
	}
      rd = read (hd, ctrl, clen);
      if (rd != clen)
	{
	  close (hd);
	  return 6;
	}
      ctrl[clen] = 0;
      msgs[i].msgid = getMSGID (ctrl);
      msgs[i].reply_id = get_reply_id (ctrl);
      if ((msgs[i].reply_id != 0) && (msgs[i].reply_id == msgs[i].msgid))
	{
	  // Крайне странная ситуация, когда письмо является ответом на самое себя.
	  // Чистимся, чтобы не влететь в глупые циклы.
	  msgs[i].reply_id = 0;
	}
      // Здесь не используем никаких memcpy и т.п., поскольку только
      // медленнее будет.
      msgs[i].offset = index[i].offset;
      msgs[i].umsgid = index[i].umsgid;
      msgs[i].processed = msgs[i].changed = 0;
      msgs[i].next = msgs[i].prev = msgs[i].head = msgs[i].last = NULL;

      // На случай если вдруг тип линковки для базы был изменен с TimEd
      // на любой линейный - чистим все netxreply кроме первого. Чтобы
      // не лить потом все назад в базу сначала проверим - а есть ли
      // ненулевой nextreply в 9 последних.
      if ((linkType != LINKTYPE_TIMED)
	  &&
	  (memcmp
	   (msgs[i].nextreply + 1, zero_array,
	    9 * sizeof (unsigned long)) != 0))
	{
	  memset (msgs[i].nextreply + 1, 0, sizeof (unsigned long) * 9);
	  msgs[i].mark_changed ();
	  zero++;
	}
      // И финальный аккорд вычитки - загоняем в хэши.
      insertElement (msghash, &msgs[i]);
      insertElement (umsghash, &msgs[i]);
    }
  if (LINKFVERBOSESTEP > 0)
    {
      ccprintf ("%s: read %-6lu of %-6lu\r", AREANAME, i, frames);
    }

  PROFILE ("reading of SQD finished\n");

  // С кладжами больше не возимся - "плиз буффер нафиг".
  myfree ((void **)&ctrl, __FILE__, __LINE__);
  // Индексы тоже больше не понадобятся.
  myfree ((void **)&index, __FILE__, __LINE__);

  // Итого, к этому моменту имеем массив информации о мессагах msgs, коего
  // должно хватить для линковки за глаза, и хэш, забитый указателями на
  // на элементы этого массива.

  PROFILE (NULL);

  switch (linkType)
    {
    case LINKTYPE_SUBJ:
      linkSubj (msgs, frames);
      break;
    case LINKTYPE_REPLY:
    case LINKTYPE_FLAT:
      linkLinear (msghash, umsghash, msgs, frames, linkType);
      break;
    case LINKTYPE_TIMED:
      linkTimEd (msghash, umsghash, msgs, frames);
      break;
    case LINKTYPE_NONE:
      // Не понял, а что мы тогда здесь делаем??? 8)
      break;
    }

  PROFILE ("linking finished\n");

  // Отлинковались. Пора сваливать все назад в базу.
  for (i = 0; i < frames; i++)
    {
      if (msgs[i].changed)
	{
	  lseek (hd, msgs[i].offset + replyoffs, SEEK_SET);
	  // Пишем назад 11 unsigned long'ов: replyto и 10 nextreply'ев.
	  write (hd, &msgs[i].replyto, sizeof (unsigned long) * 11);
	}
    }

  PROFILE ("wrote changes back to SQD\n");

  destroyHash (msghash);
  destroyHash (umsghash);
  for (i = 0; i < frames; i++)
    {
      if (msgs[i].subj)
	{
	  myfree ((void **)&msgs[i].subj, __FILE__, __LINE__);
	}
    }
  myfree ((void **)&msgs, __FILE__, __LINE__);
  close (hd);

  PROFILE ("finished linking\n");

//    if ( LINKFVERBOSESTEP > 0) ccprintf( "%-78s\r%s: %lu of %lu\r", "", AREANAME, changed_count, frames);
  //if ( LINKFVERBOSESTEP > 0)
  if (!quiet || LINKFVERBOSESTEP > 0)
    ccprintf ("%-78s\r%s: %lu of %lu\r\n", "", AREANAME, changed_count,
	      frames);
  if (changed_count)
    {
      logprintf ("Linking %s: %lu of %lu", AREANAME, changed_count,
	       frames);
      logwrite (1, 1);
    }

  return 0;
}

#ifdef STANDALONE_VERSION

#ifdef TRAP_CATCHING
void sigh (int sig)
{
  sig = sig;
  fprintf (stderr, "\nfailed at line %d...\n", last_line_passed);
  abort ();
}
#endif

int main (int argc, char *argv[])
{
  int linkType = LINKTYPE_TIMED;

#ifdef TRAP_CATCHING
  signal (SIGSEGV, sigh);
#endif

  if (argc < 2)
    {
      return 1;
    }
  if (argc > 2)
    {
      linkType = atoi (argv[2]);
    }
  return linkArea (argv[1], linkType);
}
#endif	/* STANDALONE_VERSION */
