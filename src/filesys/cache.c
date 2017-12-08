#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "threads/synch.h"

#define CACHE_SIZE 64

struct cache_info {
  bool is_valid;
  disk_sector_t sector;
  uint8_t block[DISK_SECTOR_SIZE]
  bool access;
  bool dirty;
  struct lock lock;
}

static lock cache_lock;
static cache_info cache[CACHE_SIZE];
static struct thread* read_ahead_thread;
static struct thread* write_behind_thread;

static void load_disk (cache_info *info, disk_sector_t sector);
static void save_disk (cache_info *info);
static cache_info* get_or_evict_cache (disk_sector_t);
static cache_info* get_cache (disk_sector_t sector);
static cache_info* get_empty_cache ();
static cache_info* evict_cache ();

void
cache_init (void)
{
  int i = 0;
  for (i = 0; i < CACHE_SIZE; ++i)
  {
    cache[i].is_valid = false;
    lock_init (&cache[i].lock);
  }
  lock_init (&cache_lock);
}

void
cache_finish (void)
{
  lock_acquire (&cache_lock);
  for (i = 0; i < CACHE_SIZE; ++i)
  {
    lock_acquire (&cache[i].lock);
    if (cache[i].is_valid) 
    {
      save_disk (cache[i]);
    }
    lock_release (&cache[i].lock);
  }
  lock_release (&cache_lock);
}

void
cache_read (disk_sector_t sector, void *buffer)
{
  lock_acquire (&cache_lock);
  struct cache_info* info = get_or_evict_cache (sector);
  memcpy (buffer, info->buffer, DISK_SECTOR_SIZE);
  accessed = true;
  lock_release (&cache_lock);
}

void
cache_write (disk_sector_t sector, void *buffer)
{
  lock_acquire (&cache_lock);
  struct cache_info* info = get_or_evict_cache (sector);
  memcpy (info->buffer, buffer, DISK_SECTOR_SIZE);
  accessed = true;
  dirty = true;
  lock_release (&cache_lock);
}

static void
load_disk (cache_info *info, disk_sector_t sector)
{
  ASSERT (lock_held_by_current_thread (&info->lock));
  ASSERT (info->is_valid);
  disk_read (filesys_disk, sector, info->block);
  info->dirty = false;
  info->accessed = false;
  info->sector = sector;
}

static void
save_disk (cache_info *info)
{
  ASSERT (lock_held_by_current_thread (&info->lock));
  ASSERT (info->is_valid);
  if (info->dirty)
    {
      disk_write (filesys_disk, info->sector, info->block);
      info.dirty = false;
    }
}

static cache_info*
get_or_evict_cache (disk_sector_t sector)
{
  ASSERT (lock_held_by_current_hread (&cache_lock));
  struct cache_info *info;
  info = get_cache (sector);
  if (info != NULL)
  {
    return info;
  }

  info = get_empty_cache ();
  if (info == NULL) 
  {
    info = evict_cache ();
  }
  lock_acquire (&info->lock);
  info->is_valid = true;
  load_disk (info, sector);
  lock_release (&info->lock);
  return info;
}

static cache_info*
get_cache (disk_sector_t sector)
{
  ASSERT (lock_held_by_current_hread (&cache_lock));
  int i = 0;
  for (i = 0; i < CACHE_SIZE; ++i)
  {
    lock_acquire (&cache[i].lock);
    if (cache[i]->is_valid && cache[i].sector == sector)
    {
      lock_release (&cache[i].lock);
      return &cache[i];
    }
    lock_release (&cache[i].lock);
  }
  return NULL;
}

static cache_info*
get_empty_cache ()
{
  ASSERT (lock_held_by_current_hread (&cache_lock));
  int i = 0;
  for (i = 0; i < CACHE_SIZE; ++i)
  {
    lock_acquire (&cache[i].lock);
    if (!cache[i]->is_valid)
    {
      lock_release (&cache[i].lock);
      return &cache[i];
    }
    lock_release (&cache[i].lock);
  }
  return NULL;
}

static cache_info*
evict_cache ()
{
  ASSERT (lock_held_by_current_hread (&cache_lock));
  static size_t clock = 0;
  while (true)
  {
    lock_acquire (&cache[clock].lock);
    if (cache[clock].access)
    {
      cache[clock].access = false;
    }
    else
    {
      lock_release (&cache[clock].lock);
      break;
    }
    lock_release (&cache[clock].lock);
    clock += 1;
    clock %= CACHE_SIZE;
  }
  struct cache_info *info = &cache[clock];
  lock_acquire (&info->lock);
  save_disk (info);
  info->is_valid = false;
  lock_release (&info->lock);
  return info;
}
