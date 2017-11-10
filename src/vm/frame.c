#include "vm/frame.h"
#include "vm/suppage.h"
#include "vm/swap.h"
#include "lib/kernel/list.h"
#include "lib/kernel/hash.h"
#include "userprog/pagedir.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include <stdio.h>

struct frame_info
{
  void *frame;
  uint32_t *pd;
  void *page;
  struct list_elem elem;
  struct hash_elem helem;
};

static struct list frame_info_queue; /* struct frame */
static struct hash frame_info_hash; /* struct frame */
static struct lock frame_lock;

static struct frame_info *take_away_frame (struct suppage* sp);
static unsigned frame_info_hash_func(const struct hash_elem *, void *);
static bool frame_info_less_func(const struct hash_elem *, const struct hash_elem *, void *);

void
frame_init (void)
{
  list_init (&frame_info_queue);
  hash_init (&frame_info_hash, frame_info_hash_func, frame_info_less_func, NULL);
  lock_init (&frame_lock);
}

void *
frame_get (uint32_t *pd, void *page, struct suppage *sp, bool writable)
{
  void *frame = NULL;
  lock_acquire (&frame_lock);
    {
      frame = palloc_get_page (PAL_USER | PAL_ZERO);
      struct frame_info *f_info;
      if (frame == NULL)
        {
          f_info = take_away_frame (sp);
          frame = f_info->frame;
        }
      else
        {
          /* make frame info */
          f_info = malloc (sizeof (struct frame_info));
          f_info->frame = frame;
          hash_insert (&frame_info_hash, &f_info->helem);
        }
      f_info->pd = pd;
      f_info->page = page;

      /* insert into queue tail */
      list_push_back (&frame_info_queue, &f_info->elem);

      /* set page table */
      ASSERT (pagedir_get_page (pd, page) == NULL);
      pagedir_set_page (pd, page, frame, writable);
      suppage_set_frame (sp, page, writable, frame);
    }
  lock_release (&frame_lock);
  return frame;
}

void
frame_return (uint32_t *pd, void *page, void *frame)
{
  lock_acquire (&frame_lock);
    {
      /* find frame info */
      struct frame_info temp;
      temp.frame = frame;
      struct hash_elem *elem = hash_find (&frame_info_hash, &temp.helem);
      ASSERT (elem != NULL);
      struct frame_info *f_info = hash_entry (elem, struct frame_info, helem);
      ASSERT (f_info->pd == pd && f_info->page == page);

      /* remove */
      pagedir_clear_page (pd, page);
      palloc_free_page (f_info->frame);
      list_remove (&f_info->elem);
      hash_delete (&frame_info_hash, &f_info->helem);
      free (f_info);
    }
  lock_release (&frame_lock);
}

void
frame_exit (void)
{
  ASSERT (list_empty (&frame_info_queue));
  ASSERT (hash_empty (&frame_info_hash));
}


static struct frame_info *
take_away_frame (struct suppage *sp)
{
  struct frame_info *selected = NULL;
  struct list_elem *e = list_begin (&frame_info_queue);
  size_t frame_size = list_size (&frame_info_queue);
  size_t i;
  for (i = 0; i < frame_size; ++i)
    {
      struct frame_info *info = list_entry (e, struct frame_info, elem);
      if (pagedir_is_accessed (info->pd, info->page))
        {
          pagedir_set_accessed (info->pd, info->page, false);
          struct list_elem *next = list_remove (e);
          list_push_back (&frame_info_queue, e);
          e = next;
        }
      else
        {
          selected = info;
          break;
        }
    }
  if (selected == NULL)
    {
      selected = list_entry (list_begin (&frame_info_queue), struct frame_info, elem);
    }
  list_remove (&selected->elem);
  size_t index = swap_out (selected->frame);
  struct suppage_info *sp_info = suppage_get_info (sp, selected->page);
  sp_info->mt = MEM_TYPE_SWAP;
  sp_info->index = index;
  pagedir_clear_page (selected->pd, selected->page);
  suppage_set_swap (sp, selected->page, sp_info->writable, index);

  return selected;
}

static unsigned
frame_info_hash_func (const struct hash_elem *elem, void *aux UNUSED)
{
  struct frame_info *entry = hash_entry (elem, struct frame_info, helem);
  return hash_bytes( &entry->frame, sizeof (entry->frame) );
}
static bool
frame_info_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  struct frame_info *a_entry = hash_entry(a, struct frame_info, helem);
  struct frame_info *b_entry = hash_entry(b, struct frame_info, helem);
  return a_entry->frame < b_entry->frame;
}
