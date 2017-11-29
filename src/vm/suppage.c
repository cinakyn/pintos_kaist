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
suppage_init (struct suppage *sp)
{
  lock_init (&sp->sp_lock);
  hash_init (&sp->sp_map, suppage_hash_func, suppage_less_func, NULL);
}

void
suppage_clear (struct suppage *sp)
{
    {
      struct hash_iterator i;
      hash_first (&i, &sp->sp_map);
      while (hash_next (&i))
        {
          struct suppage_info *info
            = hash_entry (hash_cur (&i), struct suppage_info, helem);
          ASSERT (info->mt == MEM_TYPE_FRAME || info->mt == MEM_TYPE_SWAP);
          if (info->mt == MEM_TYPE_FRAME)
            {
              frame_return (info);
            }
          else if (info->mt == MEM_TYPE_SWAP)
            {
              swap_clear (info->index);
            }
        }
    }
  hash_clear (&sp->sp_map, suppage_action_func);
}

void
suppage_remove_info (struct suppage *sp, struct suppage_info *info)
{
  ASSERT (info->mmap_info != NULL);
  if (info->mt == MEM_TYPE_FRAME)
  {
    frame_return (info);
  }
  hash_delete (&sp->sp_map, &info->helem);
  free (info);
}

struct suppage_info *
suppage_create_info (struct suppage *sp, struct lock* proc_info_lock, uint32_t *pagedir, void *upage, bool writable)
{
  ASSERT (upage != NULL);
  struct suppage_info *info = malloc (sizeof (struct suppage_info));
  info->mt = MEM_TYPE_INVALID;
  info->index = 0;
  info->pagedir = pagedir;
  info->page = upage;
  info->writable = writable;
  info->mmap_info = NULL;
  info->proc_info_lock = proc_info_lock;
  ASSERT (hash_insert (&sp->sp_map, &info->helem) == NULL);
  return info;
}

void
suppage_set_mmap_info (struct suppage_info *sp, struct mmap_info *mmap_info, size_t index)
{
  sp->mmap_info = mmap_info;
  sp->index = index;
}

struct suppage_info *
suppage_get_info (struct suppage *sp, void *upage)
{
  struct suppage_info *info;
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
suppage_action_func (struct hash_elem *e, void *aux UNUSED)
{
  struct suppage_info *info = hash_entry(e, struct suppage_info, helem);
  free (info);
}
