#include "vm/mmap-file.h"
#include "vm/frame.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/syscall.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "lib/stdio.h"

struct mmap_info *
mmap_get_info (
    struct mmap_info** info_list,
    size_t size,
    void *addr)
{
  size_t i;
  for (i = 0; i < size; ++i)
    {
      struct mmap_info* info = info_list[i];
      if (info == NULL)
        {
          continue;
        }
      if ((uintptr_t) addr >= info->mapped_addr &&
          (uintptr_t) addr < info->mapped_addr + info->total_size)
        {
          return info;
        }
    }
  return NULL;
}

mapid_t
mmap_add_info (
    struct mmap_info** info_list,
    size_t size,
    struct file *mapped_file,
    uintptr_t mapped_addr,
    off_t ofs,
    size_t file_size,
    size_t total_size,
    bool read_one_time,
    bool writable)
{
  struct file *copied_file = file_reopen (mapped_file);
  size_t i;
  uintptr_t current = mapped_addr;
  struct suppage *sp = &thread_current ()->sp;
  while (current < mapped_addr + total_size)
    {
      struct suppage_info *sp_info = suppage_get_info (sp, (void *)current);
      if (sp_info != NULL)
        {
          return MAP_FAILED;
        }
      for (i = 0; i < size; ++i)
        {
          struct mmap_info* info = info_list[i];
          if (info == NULL)
            {
              continue;
            }
          if (current >= info->mapped_addr &&
              current < info->mapped_addr + info->total_size)
            {
              return MAP_FAILED;
            }
        }
      current += PGSIZE;
    }

  for (i = 0; i < size; ++i)
    {
      struct mmap_info* info = info_list[i];
      if (info != NULL)
        {
          continue;
        }
      break;
    }
  ASSERT (i < size);
  struct mmap_info *info = malloc (sizeof (struct mmap_info));
  info->id = i;
  info->mapped_file = copied_file;
  info->mapped_addr = mapped_addr;
  info->file_size = file_size;
  info->total_size = total_size;
  info->ofs = ofs;
  info->writable = writable;
  info->read_one_time = read_one_time;
  info_list[i] = info;
  return i;
}

void
mmap_remove_info (struct mmap_info** info_list, mapid_t id)
{
  ASSERT (info_list[id] != NULL);
  struct mmap_info *info = info_list[id];
  if (!info->read_one_time)
    {
      uintptr_t current = info->mapped_addr;
      while (current < info->mapped_addr + info->file_size)
        {
          struct suppage *sp = &thread_current ()->sp;
          struct suppage_info *sp_info = suppage_get_info (sp, (void *)current);
          if (sp_info != NULL )
            {
              ASSERT (sp_info->mmap_info == info);
              if (sp_info->mt == MEM_TYPE_FRAME && pagedir_is_dirty (sp_info->pagedir, sp_info->page))
                {
                  mmap_swap_out (frame_with_owner (sp_info), sp_info->page, info);
                }
              suppage_remove_info (sp, sp_info);
            }
          current += PGSIZE;
        }
    }
  file_close (info->mapped_file);
  free (info);
  info_list[id] = NULL;
}

size_t
mmap_swap_in (void *frame, void *vaddr, struct mmap_info *minfo)
{
  size_t content_size;
  if (minfo->file_size < ((uintptr_t)vaddr - minfo->mapped_addr))
    {
      content_size = 0;
    }
  else
    {
      content_size = minfo->file_size - ((uintptr_t)vaddr - minfo->mapped_addr);
    }
  if (content_size > PGSIZE)
    {
      content_size = PGSIZE;
    }
  if (content_size > 0)
    {
      file_read_at (minfo->mapped_file, frame, content_size, (uintptr_t)vaddr - minfo->mapped_addr + minfo->ofs);
    }
  if (content_size < PGSIZE)
    {
      int i;
      for (i = 0; i < PGSIZE - content_size; ++i)
        {
          *(((char *)frame) + content_size + i) = 0;
        }
    }
  return mmap_calc_index (minfo->mapped_addr, (uintptr_t)vaddr);
}

size_t
mmap_swap_out (void *frame, void *vaddr, struct mmap_info *minfo)
{
  size_t content_size;
  if (minfo->file_size < ((uintptr_t)vaddr - minfo->mapped_addr))
    {
      content_size = 0;
    }
  else
    {
      content_size = minfo->file_size - ((uintptr_t)vaddr - minfo->mapped_addr);
    }
  if (content_size > PGSIZE)
    {
      content_size = PGSIZE;
    }
  if (content_size > 0)
  {
    file_write_at (minfo->mapped_file, frame, content_size, (uintptr_t)vaddr - minfo->mapped_addr + minfo->ofs);
  }
  return mmap_calc_index (minfo->mapped_addr, (uintptr_t)vaddr);
}

size_t mmap_calc_index (uintptr_t mapped_addr, uintptr_t vaddr)
{
  return (vaddr - mapped_addr) / PGSIZE;
}
