#include "vm/swap.h"
#include <bitmap.h>
#include "devices/disk.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"

static struct lock swap_lock;
static struct disk *swap_disk;
static struct bitmap *swap_map;
static disk_sector_t SECTOR_PER_PAGE;

void swap_init (void)
{
  lock_init (&swap_lock);
  swap_disk = disk_get (1, 1);
  SECTOR_PER_PAGE = PGSIZE / DISK_SECTOR_SIZE;
  swap_map = bitmap_create (disk_size (swap_disk) / SECTOR_PER_PAGE);
}

void swap_exit (void)
{
  bitmap_destroy (swap_map);
}

void swap_in (size_t index, void *frame)
{
  lock_acquire (&swap_lock);
    {
      ASSERT (bitmap_test (swap_map, index) == 1);
      bitmap_flip (swap_map, index);
      size_t i;
      for (i = 0; i < SECTOR_PER_PAGE; ++i)
        {
          disk_read (swap_disk, index * SECTOR_PER_PAGE + i, (uint8_t *) frame + i * DISK_SECTOR_SIZE);
        }
    }
  lock_release (&swap_lock);
}

size_t swap_out (void* frame)
{
  size_t index;
  lock_acquire (&swap_lock);
    {
      index = bitmap_scan_and_flip (swap_map, 0, 1, 0);
      ASSERT (index != BITMAP_ERROR);
      size_t i;
      for (i = 0; i < SECTOR_PER_PAGE; ++i)
        {
          disk_write (swap_disk, index * SECTOR_PER_PAGE + i, (uint8_t *) frame + i * DISK_SECTOR_SIZE);
        }
    }
  lock_release (&swap_lock);
  return index;
}

void swap_clear (size_t index)
{
  lock_acquire (&swap_lock);
    {
      ASSERT (bitmap_test (swap_map, index) == 1);
      bitmap_flip (swap_map, index);
    }
  lock_release (&swap_lock);
}
