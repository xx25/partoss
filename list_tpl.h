/*  Template of linked list (?)
    Copyright (C) 1999  Sergey Fadeyev, 2:5020/877

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef _LIST_TPL
#define _LIST_TPL

#include <iosfwd>

template < class type > class list_el
{
public:
  type data;
  list_el *next;
  list_el *prev;

  list_el()
  {                             // default constructor
    prev = NULL;
    next = NULL;
  }
  list_el(type & c)
  {
    data = c;
    prev = NULL;
    next = NULL;
  }
  list_el(list_el < type > &c)
  {                             // copy constructor
    data = c.data;
    prev = c.prev;
    next = c.prev;
  }
  list_el(list_el < type > *previous)
  {
    prev = previous;
    next = NULL;
  }
  list_el(list_el < type > *previous, type & c)
  {
    data = c;
    prev = previous;
    next = NULL;
  }
  list_el(list_el < type > *previous, list_el < type > *next_el)
  {
    prev = previous;
    next = next_el;
  }
  list_el(list_el < type > *previous, list_el < type > *next_el, type & c)
  {
    data = c;
    prev = previous;
    next = next_el;
  }
  list_el < type > &operator =(list_el < type > &el)
  {
    data = el.data;
    return *this;
  }
  int operator ==(list_el < type > &el) {
    return data == el.data;
  }
};

template < class type > class list
{
protected:
  list_el < type > *head;
  list_el < type > *current;
public:
  list()
  {                             // default constructor
    head = NULL;
    current = NULL;
  }
  list(list & c)
  {                             // copy constructor
    if(c.head == NULL)
    {
      head = NULL;
      current = NULL;
      return;
    }
    list_el < type > *sav_current;
    sav_current = c.current;
    head = new list_el < type > (c.head->data);
    if(c.current == c.head)
      current = head;
    list_el < type > *temp = c.head->next;
    list_el < type > *temp2;
    int i = 1;

    while(i)
    {
      if(temp == NULL)
        i = 0;
      else
      {
        temp2 = add_el(temp->data);
        if(temp == c.current)
          current = temp2;
        temp = temp->next;
      }
    }
  }
  list(int num) {
    list_el < type > *c_el;

    head = new list_el < type >;
    current = head;
    c_el = head;
    for(int i = 1; i < num; i++)
    {
      c_el->next = new list_el < type > (c_el);
      //c_el->next->prev=c_el;
      c_el = c_el->next;
    }
  }

  list & operator =(list & c)
  {
    while(size() != 0)
      rem_el(head);
    if(c.head == NULL)
    {
      head = NULL;
      current = NULL;
      return *this;
    }
    list_el < type > *sav_current;
    sav_current = c.current;
    head = new list_el < type > (c.head->data);
    if(c.current == c.head)
      current = head;
    list_el < type > *temp = c.head->next;
    list_el < type > *temp2;
    int i = 1;

    while(i)
    {
      if(temp == NULL)
        i = 0;
      else
      {
        temp2 = add_el(temp->data);
        if(temp == c.current)
          current = temp2;
        temp = temp->next;
      }
    }
    return *this;
  }
  list_el < type > *next()
  {
    if((current->next) == NULL)
      return NULL;
    return current = (current->next);
  }
  list_el < type > *prev()
  {
    if((current->prev) == NULL)
      return NULL;
    return current = (current->prev);
  }
  list_el < type > *curr()
  {
    return current;
  }
  list_el < type > *curr(list_el < type > *c)
  {
    return current = c;
  }
  list_el < type > *goto_head()
  {
    return current = head;
  }
  list_el < type > *add_el(type & inf)
  {
    list_el < type > *c_el;

    if(head != NULL)
    {
      c_el = head;
      while(c_el->next != NULL)
      {
        if(inf < c_el->data)
        {
          c_el = new list_el < type > (c_el->prev, c_el);
          c_el->next->prev = c_el;
          if(c_el->prev == NULL)
            head = c_el;
          else
            c_el->prev->next = c_el;
          c_el->data = inf;
          return c_el;
        }
        else
          c_el = c_el->next;
      }
      if(inf < c_el->data)
      {
        c_el = new list_el < type > (c_el->prev, c_el);
        c_el->next->prev = c_el;
        if(c_el->prev == NULL)
          head = c_el;
        else
          c_el->prev->next = c_el;
        c_el->data = inf;
        return c_el;
      }
      else
      {
        c_el->next = new list_el < type > (c_el);
        c_el = c_el->next;
        c_el->data = inf;
        return c_el;
      }
    }
    else
    {
      head = new list_el < type >;
      current = head;
      c_el = head;
    }
    c_el->data = inf;
    return c_el;
  }
  void rem_el(list_el < type > *c) {
    if(c == head)
    {
      head = c->next;
    }
    else
    {
      c->prev->next = c->next;
    }
    c->next->prev = c->prev;
    delete c;
  }
  list_el < type > *whichis(type c)
  {
    list_el < type > *temp = head;
    while(1)
    {
      if(temp == NULL)
        return NULL;
      if((temp->data) == c)
        return temp;
      temp = temp->next;
    }
  }
  int size() {
    int n = 0;

    list_el < type > *temp = head;
    //list_el<type>* savedcurr=current;
    while(1)
    {
      if(temp == NULL)
      {
        //current=savedcurr;
        return n;
      }
      n++;
      temp = temp->next;
    }
  }
};

template < class type > std::ostream & operator <<(std::ostream & o, list < type > &l)
{
  list_el < type > *temp = l.head;
  while(1)
  {
    if(temp == NULL)
      return o;
    o << temp->data;
    temp = temp->next;
  }
}

#endif //define _LIST_TPL
