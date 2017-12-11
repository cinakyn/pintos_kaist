#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "devices/timer.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "lib/string.h"

#define CACHE_SIZE 12
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

struct sector_to_index {
  disk_sector_t sector;
  int index;
  struct hash_elem helem;
};

struct read_ahead_entry {
  disk_sector_t sector;
  struct list_elem elem;
};

static struct lock cache_lock;
static struct cache_info cache[CACHE_SIZE];
static size_t remain_cache_space;
static struct hash sti_hash; /* sector to index */
static struct list read_ahead_queue;
static struct lock read_ahead_lock;
static struct condition read_ahead_cond;
static bool finished;
static struct lock finished_lock;

static void load_disk (struct cache_info *info, disk_sector_t sector);
static void save_disk (struct cache_info *info);
static struct cache_info* get_or_evict_cache (disk_sector_t);
static struct cache_info* get_cache (disk_sector_t sector);
static struct cache_info* get_empty_cache (disk_sector_t);
static struct cache_info* evict_cache (disk_sector_t);
static void read_ahead_func (void *aux);
static void write_behind_func (void *aux);
static void sti_set (disk_sector_t sector, int index);
static int sti_get (disk_sector_t sector);
static void sti_clear (disk_sector_t sector, int index);
static unsigned sti_hash_func(const struct hash_elem *, void *);
static bool sti_less_func(const struct hash_elem *, const struct hash_elem *, void *);

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
  cond_init (&read_ahead_cond);
  list_init (&read_ahead_queue);
  hash_init (&sti_hash, sti_hash_func, sti_less_func, NULL);
  finished = false;
  remain_cache_space = CACHE_SIZE;
  thread_create ("cache_read_ahead", 0, read_ahead_func, NULL);
  thread_create ("cache_write_behind", 0, write_behind_func, NULL);
}

void
cache_finish (void)
{
  lock_acquire (&finished_lock);
  finished = true;
  lock_release (&finished_lock);
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
  ASSERT (offset + len <= DISK_SECTOR_SIZE);
  struct cache_info* info = get_or_evict_cache (sector);
  memcpy (buffer, info->buffer + offset, len);
  info->access = true;
  lock_release (&info->lock);

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
  ASSERT (offset + len <= DISK_SECTOR_SIZE);
  struct cache_info* info = get_or_evict_cache (sector);
  memcpy (info->buffer + offset, buffer, len);
  info->access = true;
  info->dirty = true;
  lock_release (&info->lock);
}

static void
load_disk (struct cache_info *info, disk_sector_t sector)
{
  ASSERT (lock_held_by_current_thread (&info->lock));
  ASSERT (info->is_valid);
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
  if (info->dirty)
    {
      disk_write (filesys_disk, info->sector, info->buffer);
      info->dirty = false;
    }
}

static struct cache_info*
get_or_evict_cache (disk_sector_t sector)
{
  lock_acquire (&cache_lock);
  struct cache_info *info;
  info = get_cache (sector);
  if (info != NULL)
  {
    ASSERT (lock_held_by_current_thread (&info->lock));
    lock_release (&cache_lock);
    return info;
  }

  info = get_empty_cache (sector);
  if (info == NULL) 
  {
    info = evict_cache (sector);
  }
  info->is_valid = true;
  lock_release (&cache_lock);
  load_disk (info, sector);
  ASSERT (lock_held_by_current_thread (&info->lock));
  return info;
}

static struct cache_info*
get_cache (disk_sector_t sector)
{
  ASSERT (lock_held_by_current_thread (&cache_lock));
  int index = sti_get (sector);
  struct cache_info *info;
  if (index >= 0)
  {
    info = &cache[index];
    lock_acquire (&info->lock);
  }
  else
  {
    info = NULL;
  }
  return info;
}

static struct cache_info*
get_empty_cache (disk_sector_t sector)
{
  ASSERT (lock_held_by_current_thread (&cache_lock));
  if (remain_cache_space == 0)
  {
    return NULL;
  }
  int i = 0;
  for (i = 0; i < CACHE_SIZE; ++i)
  {
    lock_acquire (&cache[i].lock);
    if (!cache[i].is_valid)
    {
      sti_set (sector, i);
      remain_cache_space -= 1;
      return &cache[i];
    }
    lock_release (&cache[i].lock);
  }
  ASSERT (false);
  return NULL;
}

static struct cache_info*
evict_cache (disk_sector_t sector)
{
  ASSERT (lock_held_by_current_thread (&cache_lock));
  static size_t clock = 0;
  while (true)
  {
    lock_acquire (&cache[clock].lock);
    if (!cache[clock].is_valid)
    {
      lock_release (&cache[clock].lock);
    }
    else if (cache[clock].access)
    {
      cache[clock].access = false;
      lock_release (&cache[clock].lock);
    }
    else
    {
      break;
    }
    clock += 1;
    clock %= CACHE_SIZE;
  }
  struct cache_info *info = &cache[clock];
  sti_clear (info->sector, clock);
  sti_set (sector, clock);
  save_disk (info);
  info->is_valid = false;
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

    struct cache_info *info = get_or_evict_cache (sector);
    lock_release (&info->lock);
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
    timer_msleep (WRITE_BEIND_PERIOD_MS);
  }
}

static void 
sti_set (disk_sector_t sector, int index)
{
  ASSERT (lock_held_by_current_thread (&cache_lock));
  struct sector_to_index *entry = malloc (sizeof (struct sector_to_index));
  entry->sector = sector;
  entry->index = index;
  struct hash_elem *already = hash_insert (&sti_hash, &entry->helem);
  if (already != NULL)
  {
    struct sector_to_index *entry = hash_entry (already, struct sector_to_index, helem);
  }
  ASSERT (already == NULL);
}

static int
sti_get (disk_sector_t sector)
{
  ASSERT (lock_held_by_current_thread (&cache_lock));
  struct sector_to_index temp;
  temp.sector = sector;
  struct hash_elem *elem = hash_find (&sti_hash, &temp.helem);
  if (elem != NULL)
  {
    struct sector_to_index *entry = hash_entry (elem, struct sector_to_index, helem);
    return entry->index;
  }
  else
  {
    return -1;
  }
}

static void 
sti_clear (disk_sector_t sector, int index UNUSED)
{
  ASSERT (lock_held_by_current_thread (&cache_lock));
  struct sector_to_index temp;
  temp.sector = sector;
  struct hash_elem *removed = hash_delete (&sti_hash, &temp.helem);
  ASSERT (removed != NULL);
  struct sector_to_index *entry = hash_entry (removed, struct sector_to_index, helem);
  free (entry);
}

static unsigned
sti_hash_func (const struct hash_elem *elem, void *aux UNUSED)
{
  struct sector_to_index *entry = hash_entry (elem, struct sector_to_index, helem);
  return hash_bytes( &entry->sector, sizeof (entry->sector) );
}

static bool
sti_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  struct sector_to_index *a_entry = hash_entry(a, struct sector_to_index, helem);
  struct sector_to_index *b_entry = hash_entry(b, struct sector_to_index, helem);
  return (a_entry->sector) < (b_entry->sector);
}
