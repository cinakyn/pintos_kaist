#include "vm/suppage.h"
#include "vm/swap.h"
#include "vm/frame.h"
#include <debug.h>
#include "threads/malloc.h"
#include "threads/thread.h"
#include <stdio.h>

static unsigned suppage_hash_func(const struct hash_elem *, void *);
static bool suppage_less_func(const struct hash_elem *, const struct hash_elem *, void *);
static void suppage_action_func (struct hash_elem *e, void *aux);

void
suppage_init (struct suppage *sp, uint32_t *pagedir)
{
  lock_init (&sp->sp_lock);
  hash_init (&sp->sp_map, suppage_hash_func, suppage_less_func, NULL);
  sp->pagedir = pagedir;
}

void
suppage_clear (struct suppage *sp)
{
  lock_acquire (&sp->sp_lock);
    {
      struct hash_iterator i;
      hash_first (&i, &sp->sp_map);
      while (hash_next (&i))
        {
          struct suppage_info *info
            = hash_entry (hash_cur (&i), struct suppage_info, helem);
          ASSERT (info->mt != MEM_TYPE_INVALID);
          if (info->mt == MEM_TYPE_FRAME)
            {
              frame_return (sp->pagedir, info->page, info->frame);
            }
          else if (info->mt == MEM_TYPE_SWAP)
            {
              swap_clear (info->index);
            }
        }
    }
  hash_clear (&sp->sp_map, suppage_action_func);
  lock_release (&sp->sp_lock);
}

void
suppage_set_swap (struct suppage *sp, void *upage, bool writable, size_t index)
{
  lock_acquire (&sp->sp_lock);
    {
      struct suppage_info temp;
      struct suppage_info *info;
      temp.page = upage;
      struct hash_elem *elem = hash_find (&sp->sp_map, &temp.helem);
      if (elem == NULL)
        {
          info = malloc (sizeof (struct suppage_info));
          info->page = upage;
          ASSERT (hash_insert (&sp->sp_map, &info->helem) == NULL);
        }
      else
        {
          info = hash_entry (elem, struct suppage_info, helem);
          ASSERT (info->page == upage);
        }
      info->mt = MEM_TYPE_SWAP;
      info->index = index;
      info->writable = writable;
    }
  lock_release (&sp->sp_lock);
}

void
suppage_set_frame (struct suppage *sp, void *upage, bool writable, void *frame)
{
  lock_acquire (&sp->sp_lock);
    {
      struct suppage_info temp;
      struct suppage_info *info;
      temp.page = upage;
      struct hash_elem *elem = hash_find (&sp->sp_map, &temp.helem);
      if (elem == NULL)
        {
          info = malloc (sizeof (struct suppage_info));
          info->page = upage;
          ASSERT (hash_insert (&sp->sp_map, &info->helem) == NULL);
        }
      else
        {
          info = hash_entry (elem, struct suppage_info, helem);
          ASSERT (info->page == upage);
        }
      info->mt = MEM_TYPE_FRAME;
      info->frame = frame;
      info->writable = writable;
    }
  lock_release (&sp->sp_lock);
}

struct suppage_info *
suppage_get_info (struct suppage *sp, void *upage)
{
  struct suppage_info *info;
  lock_acquire (&sp->sp_lock);
    {
      struct suppage_info temp;
      temp.page = upage;
      struct hash_elem *elem = hash_find (&sp->sp_map, &temp.helem);
      if (elem == NULL)
        {
          info = NULL;
        }
      else
        {
          info = hash_entry (elem, struct suppage_info, helem);
        }
    }
  lock_release (&sp->sp_lock);
  return info;
}

static unsigned
suppage_hash_func (const struct hash_elem *elem, void *aux UNUSED)
{
  struct suppage_info *entry = hash_entry (elem, struct suppage_info, helem);
  return hash_bytes( &entry->page, sizeof (entry->page) );
}

static bool
suppage_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  struct suppage_info *a_entry = hash_entry(a, struct suppage_info, helem);
  struct suppage_info *b_entry = hash_entry(b, struct suppage_info, helem);
  return a_entry->page < b_entry->page;
}

static void 
suppage_action_func (struct hash_elem *e, void *aux)
{
  struct suppage_info *info = hash_entry(e, struct suppage_info, helem);
  free (info);
}
