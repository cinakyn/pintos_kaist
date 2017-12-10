#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "devices/timer.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "lib/string.h"

#define CACHE_SIZE 32
#define WRITE_BEIND_PERIOD_MS 1000

struct cache_info {
  bool is_valid;
  disk_sector_t sector;
  uint8_t buffer[DISK_SECTOR_SIZE];
  bool access;
  bool dirty;
  struct lock lock;
  struct hash_elem helem;
};

struct read_ahead_entry {
  disk_sector_t sector;
  struct list_elem elem;
};

static struct lock cache_lock;
static struct cache_info cache[CACHE_SIZE];
static struct hash cache_hash UNUSED;
static struct list read_ahead_queue;
static struct lock read_ahead_lock;
static struct condition read_ahead_cond;
static bool finished;
static struct lock finished_lock;
static uint32_t access_count;
static struct lock access_count_lock;
static struct condition access_count_cond;

static void add_access_count (void);
static void sub_access_count (void);
static void load_disk (struct cache_info *info, disk_sector_t sector);
static void save_disk (struct cache_info *info);
static struct cache_info* get_or_evict_cache (disk_sector_t);
static struct cache_info* get_cache (disk_sector_t sector);
static struct cache_info* get_empty_cache (void);
static struct cache_info* evict_cache (void);
static void read_ahead_func (void *aux);
static void write_behind_func (void *aux);
static unsigned cache_hash_func(const struct hash_elem *, void *) UNUSED;
static bool cache_less_func(const struct hash_elem *, const struct hash_elem *, void *) UNUSED;

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
  lock_init (&read_ahead_lock);
  lock_init (&finished_lock);
  lock_init (&access_count_lock);
  cond_init (&read_ahead_cond);
  cond_init (&access_count_cond);
  list_init (&read_ahead_queue);
  finished = false;
  access_count = 0;
  thread_create ("cache_read_ahead", 0, read_ahead_func, NULL);
  thread_create ("cache_write_behind", 0, write_behind_func, NULL);
}

void
cache_finish (void)
{
  lock_acquire (&finished_lock);
  finished = true;
  lock_release (&finished_lock);
  add_access_count ();
  lock_acquire (&cache_lock);
  int i = 0;
  for (i = 0; i < CACHE_SIZE; ++i)
  {
    lock_acquire (&cache[i].lock);
    if (cache[i].is_valid) 
    {
      save_disk (&cache[i]);
    }
    lock_release (&cache[i].lock);
  }
  lock_release (&cache_lock);
  sub_access_count ();
}

void
cache_read (disk_sector_t sector, void *buffer)
{
  cache_read_len (sector, buffer, 0, DISK_SECTOR_SIZE);
}

void
cache_write (disk_sector_t sector, const void *buffer)
{
  cache_write_len (sector, buffer, 0, DISK_SECTOR_SIZE);
}

void
cache_read_len (disk_sector_t sector, void *buffer, off_t offset, off_t len)
{
  add_access_count ();
  ASSERT (offset + len <= DISK_SECTOR_SIZE);
  struct cache_info* info = get_or_evict_cache (sector);
  memcpy (buffer, info->buffer + offset, len);
  info->access = true;
  sub_access_count ();

  struct read_ahead_entry* entry = malloc (sizeof (struct read_ahead_entry));
  entry->sector = sector + 1;
  lock_acquire (&read_ahead_lock);
  list_push_back (&read_ahead_queue, &entry->elem);
  cond_signal (&read_ahead_cond, &read_ahead_lock);
  lock_release (&read_ahead_lock);
}

void
cache_write_len (disk_sector_t sector, const void *buffer, off_t offset, off_t len)
{
  add_access_count ();
  ASSERT (offset + len <= DISK_SECTOR_SIZE);
  struct cache_info* info = get_or_evict_cache (sector);
  memcpy (info->buffer + offset, buffer, len);
  info->access = true;
  info->dirty = true;
  sub_access_count ();
}

static void
add_access_count (void)
{
  lock_acquire (&access_count_lock);
  access_count++;
  lock_release (&access_count_lock);
}

static void
sub_access_count (void)
{
  lock_acquire (&access_count_lock);
  ASSERT (access_count > 0);
  access_count--;
  if (access_count == 0)
  {
    cond_signal (&access_count_cond, &access_count_lock);
  }
  lock_release (&access_count_lock);
}

static void
load_disk (struct cache_info *info, disk_sector_t sector)
{
  ASSERT (lock_held_by_current_thread (&info->lock));
  ASSERT (info->is_valid);
  ASSERT (access_count > 0);
  disk_read (filesys_disk, sector, info->buffer);
  info->dirty = false;
  info->access = false;
  info->sector = sector;
}

static void
save_disk (struct cache_info *info)
{
  ASSERT (lock_held_by_current_thread (&info->lock));
  ASSERT (info->is_valid);
  ASSERT (access_count > 0);
  if (info->dirty)
    {
      disk_write (filesys_disk, info->sector, info->buffer);
      info->dirty = false;
    }
}

static struct cache_info*
get_or_evict_cache (disk_sector_t sector)
{
  ASSERT (access_count > 0);
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
  lock_acquire (&cache_lock);
  lock_release (&cache_lock);
  return info;
}

static struct cache_info*
get_cache (disk_sector_t sector)
{
  ASSERT (access_count > 0);
  int i = 0;
  lock_acquire (&cache_lock);
  for (i = 0; i < CACHE_SIZE; ++i)
  {
    if (cache[i].is_valid && cache[i].sector == sector)
    {
      lock_release (&cache_lock);
      return &cache[i];
    }
  }
  lock_release (&cache_lock);
  return NULL;
}

static struct cache_info*
get_empty_cache (void)
{
  ASSERT (access_count > 0);
  int i = 0;
  lock_acquire (&cache_lock);
  for (i = 0; i < CACHE_SIZE; ++i)
  {
    lock_acquire (&cache[i].lock);
    if (!cache[i].is_valid)
    {
      lock_release (&cache[i].lock);
      lock_release (&cache_lock);
      return &cache[i];
    }
    lock_release (&cache[i].lock);
  }
  lock_release (&cache_lock);
  return NULL;
}

static struct cache_info*
evict_cache (void)
{
  ASSERT (access_count > 0);
  lock_acquire (&access_count_lock);
  access_count--;
  while (access_count > 0)
  {
    cond_wait (&access_count_cond, &access_count_lock);
  }
  access_count++;
  static size_t clock = 0;
  lock_acquire (&cache_lock);
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
  lock_release (&cache_lock);
  lock_acquire (&info->lock);
  save_disk (info);
  info->is_valid = false;
  lock_release (&info->lock);
  lock_release (&access_count_lock);
  return info;
}

static void
read_ahead_func (void *aux UNUSED)
{
  while (true) 
  {
    lock_acquire (&finished_lock);
    if (finished) {
      lock_release (&finished_lock);
      break;
    }
    lock_release (&finished_lock);

    lock_acquire (&read_ahead_lock);
    while (list_empty (&read_ahead_queue))
    {
      cond_wait (&read_ahead_cond, &read_ahead_lock);
    }
    struct read_ahead_entry* entry
      = list_entry (
          list_pop_front (&read_ahead_queue),
          struct read_ahead_entry,
          elem);
    disk_sector_t sector = entry->sector;
    lock_release (&read_ahead_lock);

    add_access_count ();
    get_or_evict_cache (sector);
    sub_access_count ();
  }
}

static void
write_behind_func (void *aux UNUSED)
{
  while (true) 
  {
    lock_acquire (&finished_lock);
    if (finished) {
      lock_release (&finished_lock);
      break;
    }
    lock_release (&finished_lock);
    add_access_count ();
    lock_acquire (&cache_lock);
    int i = 0;
    for (i = 0; i < CACHE_SIZE; ++i)
    {
      lock_acquire (&cache[i].lock);
      if (cache[i].is_valid && cache[i].dirty)
      {
        save_disk (&cache[i]);
      }
      lock_release (&cache[i].lock);
    }
    lock_release (&cache_lock);
    sub_access_count ();
    timer_msleep (1000);
  }
}

static unsigned
cache_hash_func (const struct hash_elem *elem, void *aux UNUSED)
{
  struct cache_info *entry = hash_entry (elem, struct cache_info, helem);
  return hash_bytes( &entry->sector, sizeof (entry->sector) );
}

static bool
cache_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  struct cache_info *a_entry = hash_entry(a, struct cache_info, helem);
  struct cache_info *b_entry = hash_entry(b, struct cache_info, helem);
  return (a_entry->sector) < (b_entry->sector);
}
