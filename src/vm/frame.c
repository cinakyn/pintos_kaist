#include "vm/frame.h"
#include "vm/suppage.h"
#include "vm/swap.h"
#include "vm/mmap-file.h"
#include "lib/kernel/list.h"
#include "lib/kernel/hash.h"
#include "userprog/pagedir.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include <stdio.h>

struct frame_info
{
  struct suppage_info *owner; /* key */
  void *frame;
  struct list_elem elem;
  struct hash_elem helem;
};

static struct list frame_info_queue; /* struct frame_info */
static struct hash frame_info_hash; /* struct frame_info */

static struct frame_info *take_away_frame (void);
static unsigned frame_info_hash_func(const struct hash_elem *, void *);
static bool frame_info_less_func(const struct hash_elem *, const struct hash_elem *, void *);

void
frame_init (void)
{
  list_init (&frame_info_queue);
  hash_init (&frame_info_hash, frame_info_hash_func, frame_info_less_func, NULL);
  lock_init (&frame_magic_lock);
}

void *
frame_get (struct suppage_info *owner)
{
  ASSERT (owner != NULL);
  void *frame = NULL;
    {
      frame = palloc_get_page (PAL_USER | PAL_ZERO);
      struct frame_info *f_info;
      if (frame == NULL)
        {
          f_info = take_away_frame ();
          frame = f_info->frame;
        }
      else
        {
          /* make frame info */
          f_info = malloc (sizeof (struct frame_info));
          f_info->frame = frame;
          /* insert into queue tail */
          list_push_back (&frame_info_queue, &f_info->elem);
        }
      f_info->owner = owner;
      hash_insert (&frame_info_hash, &f_info->helem);
      owner->mt = MEM_TYPE_FRAME;
      pagedir_set_page (owner->pagedir, owner->page, frame, owner->writable);
    }
  return frame;
}

void *
frame_with_owner (struct suppage_info *owner)
{
    /* find frame info */
    ASSERT (owner != NULL);
    struct frame_info temp;
    temp.owner = owner;
    struct hash_elem *elem = hash_find (&frame_info_hash, &temp.helem);
    ASSERT (elem != NULL);
    struct frame_info *f_info = hash_entry (elem, struct frame_info, helem);
    return f_info->frame;
}

void
frame_return (struct suppage_info *owner)
{
    {
      /* find frame info */
      ASSERT (owner != NULL);
      struct frame_info temp;
      temp.owner = owner;
      struct hash_elem *elem = hash_find (&frame_info_hash, &temp.helem);
      ASSERT (elem != NULL);
      struct frame_info *f_info = hash_entry (elem, struct frame_info, helem);

      /* remove */
      pagedir_clear_page (owner->pagedir, owner->page);
      palloc_free_page (f_info->frame);
      list_remove (&f_info->elem);
      hash_delete (&frame_info_hash, &f_info->helem);
      free (f_info);
    }
}

void
frame_exit (void)
{
  ASSERT (list_empty (&frame_info_queue));
  ASSERT (hash_empty (&frame_info_hash));
}

static struct frame_info *
take_away_frame (void)
{
  struct frame_info *selected = NULL;
  struct list_elem *e = list_begin (&frame_info_queue);
  size_t frame_size = list_size (&frame_info_queue);
  size_t i;
  static size_t clock = 0;
  clock %= frame_size;

  // go to clock index.
  for (i = 0; i < clock; ++i)
    {
      e = list_next (e);
    }

  for (i = 0; i < frame_size; ++i)
    {
      struct frame_info *info = list_entry (e, struct frame_info, elem);
      ASSERT (info->owner != NULL);
      clock += 1;
      clock %= frame_size;
      if (pagedir_is_accessed (info->owner->pagedir, info->owner->page))
        {
          pagedir_set_accessed (info->owner->pagedir, info->owner->page, false);
          e = list_next (e);
          if (e == list_end (&frame_info_queue))
            {
              e = list_begin (&frame_info_queue);
            }
        }
      else
        {
          selected = info;
          break;
        }
    }
  if (selected == NULL)
    {
      selected = list_entry (e, struct frame_info, elem);
      clock += 1;
      clock %= frame_size;
    }
  hash_delete (&frame_info_hash, &selected->helem);
  pagedir_clear_page (selected->owner->pagedir, selected->owner->page);

  /* first check mmap */
  lock_acquire (selected->owner->proc_info_lock);
  struct mmap_info *map_info = selected->owner->mmap_info;
  if (map_info != NULL)
    {
      if (pagedir_is_dirty (selected->owner->pagedir, selected->owner->page))
      {
        size_t index = mmap_swap_out (selected->frame, selected->owner->page, map_info);
        selected->owner->index = index;
      }
      selected->owner->mt = MEM_TYPE_MMAP_FILE;
    }
  else
    {
      size_t index = swap_out (selected->frame);
      selected->owner->index = index;
      selected->owner->mt = MEM_TYPE_SWAP;
    }
  lock_release (selected->owner->proc_info_lock);
  ASSERT (selected->owner->mt != MEM_TYPE_FRAME);
  selected->owner = NULL;
  return selected;
}

static unsigned
frame_info_hash_func (const struct hash_elem *elem, void *aux UNUSED)
{
  struct frame_info *entry = hash_entry (elem, struct frame_info, helem);
  return hash_bytes( &entry->owner, sizeof (entry->owner) );
}
static bool
frame_info_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  struct frame_info *a_entry = hash_entry(a, struct frame_info, helem);
  struct frame_info *b_entry = hash_entry(b, struct frame_info, helem);
  return ((uint32_t)(a_entry->owner)) < ((uint32_t)b_entry->owner);
}
