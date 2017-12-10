#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/cache.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define BLOCKS_PER_SECTOR 128

/* On-disk inode.
   Must be exactly DISK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    off_t length;                       /* File size in bytes. */
    disk_sector_t doubly_indirect_disk;
    bool is_dir;
    uint32_t unsed[124];
    unsigned magic;                     /* Magic number. */
  };

struct inode_indirect_disk
  {
    disk_sector_t blocks[BLOCKS_PER_SECTOR];
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, DISK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    disk_sector_t sector;               /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
    struct lock lock;
    unsigned magic;                     /* Magic number. */
  };


/* Returns the disk sector that contains byte offset POS within
   INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static disk_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  struct inode_indirect_disk indirect_disk;
  disk_sector_t index = pos / DISK_SECTOR_SIZE;
  cache_read (inode->data.doubly_indirect_disk, &indirect_disk);
  disk_sector_t second_sector =
    indirect_disk.blocks[index / BLOCKS_PER_SECTOR];
  cache_read (second_sector, &indirect_disk);
  disk_sector_t third_sector =
    indirect_disk.blocks[(index % BLOCKS_PER_SECTOR)];
  return third_sector;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;
static struct lock open_inodes_lock;
static uint8_t zeros[DISK_SECTOR_SIZE];

static void inode_init_indirect_disk (struct inode_indirect_disk* disk);
static bool inode_expand (struct inode *node, off_t from, off_t to);

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
  lock_init (&open_inodes_lock);
  memset (zeros, 0, DISK_SECTOR_SIZE);
  int i = 0;
  for (i = 0; i < DISK_SECTOR_SIZE; ++i)
  {
    ASSERT (zeros[i] == 0);
  }
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   disk.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (disk_sector_t sector, off_t length)
{
  struct inode_disk *disk_inode = NULL;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == DISK_SECTOR_SIZE);
  disk_sector_t sector_for_first;
  if (!free_map_allocate (1, &sector_for_first))
  {
    return false;
  }
  disk_inode = calloc (1, sizeof *disk_inode);
  disk_inode->length = length;
  disk_inode->magic = INODE_MAGIC;
  disk_inode->doubly_indirect_disk = sector_for_first;
  struct inode_indirect_disk *first_disk = malloc (sizeof (struct inode_indirect_disk));
  inode_init_indirect_disk (first_disk);
  cache_write (disk_inode->doubly_indirect_disk, first_disk);
  cache_write (sector, disk_inode);
  free (disk_inode);
  free (first_disk);
  if (length > 0)
  {
    struct inode *node = inode_open (sector);
    lock_acquire (&node->lock);
    inode_expand (node, 0, length);
    lock_release (&node->lock);
    inode_close (node);
  }
  return true;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (disk_sector_t sector) 
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  lock_acquire (&open_inodes_lock);
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      ASSERT (inode->data.magic == INODE_MAGIC);
      ASSERT (inode->magic == INODE_MAGIC);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          lock_release (&open_inodes_lock);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL) {
    lock_release (&open_inodes_lock);
    return NULL;
  }

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->magic = INODE_MAGIC;
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init (&inode->lock);
  cache_read (inode->sector, &inode->data);
  ASSERT (inode->data.magic == INODE_MAGIC);
  ASSERT (inode->magic == INODE_MAGIC);
  lock_release (&open_inodes_lock);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
  {
    lock_acquire (&inode->lock);
    ASSERT (inode->data.magic == INODE_MAGIC);
    ASSERT (inode->magic == INODE_MAGIC);
    inode->open_cnt++;
    lock_release (&inode->lock);
  }
  return inode;
}

/* Returns INODE's inode number. */
disk_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  lock_acquire (&inode->lock);
  ASSERT (inode->data.magic == INODE_MAGIC);
  ASSERT (inode->magic == INODE_MAGIC);
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          free_map_release (inode->sector, 1);
          size_t to_total = inode->data.length / DISK_SECTOR_SIZE;
          size_t to_first = to_total / BLOCKS_PER_SECTOR;
          size_t alloc_count = (to_total + 1) + (to_first + 1);
          struct inode_indirect_disk *first_disk = malloc (sizeof (struct inode_indirect_disk));
          cache_read (inode->data.doubly_indirect_disk, first_disk);
          free_map_release (inode->data.doubly_indirect_disk, 1);
          size_t i = 0;
          for (i = 0; i < BLOCKS_PER_SECTOR; ++i)
          {
            disk_sector_t s = first_disk->blocks[i];
            if (s < (uint32_t)-1)
            {
              struct inode_indirect_disk *second_disk = malloc (sizeof (struct inode_indirect_disk));
              cache_read (s, second_disk);
              free_map_release (s, 1);
              alloc_count -= 1;
              size_t k = 0;
              for (k = 0; k < BLOCKS_PER_SECTOR; ++k)
              {
                disk_sector_t ss = second_disk->blocks[k];
                if (ss < (uint32_t)-1)
                {
                  free_map_release (ss, 1);
                  alloc_count -= 1;
                }
                else
                {
                  break;
                }
              }
              free (second_disk);
            }
            else
            {
              break;
            }
          }
          free (first_disk);
          ASSERT (alloc_count == 0);
        }
      cache_write (inode->sector, &inode->data);
      lock_release (&inode->lock);
      free (inode);
    }
  else 
    {
      lock_release (&inode->lock);
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  ASSERT (inode->data.magic == INODE_MAGIC);
  ASSERT (inode->magic == INODE_MAGIC);
  lock_acquire (&inode->lock);
  inode->removed = true;
  lock_release (&inode->lock);
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  ASSERT (inode->data.magic == INODE_MAGIC);
  ASSERT (inode->magic == INODE_MAGIC);
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0) 
    {
      if (offset >= inode_length (inode))
      {
        break;
      }
      /* Disk sector to read, starting byte offset within sector. */
      disk_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % DISK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = DISK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;
      cache_read_len (sector_idx, buffer + bytes_read, sector_ofs, chunk_size); 

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);
  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  ASSERT (inode->data.magic == INODE_MAGIC);
  ASSERT (inode->magic == INODE_MAGIC);
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  bool length_changed;
  off_t node_length;
  lock_acquire (&inode->lock); 
  if (inode->data.length < offset + size)
  {
    length_changed = true;
    node_length = offset + size;
    inode_expand (inode, inode->data.length, node_length);
  }
  else
  {
    length_changed = false;
    node_length = inode->data.length;
    lock_release (&inode->lock);
  }

  while (size > 0) 
    {
      if (offset >= node_length)
      {
        break;
      }
      /* Sector to write, starting byte offset within sector. */
      disk_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % DISK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = node_length - offset;
      int sector_left = DISK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

//    if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE)
//      {
//        /* Write full sector directly to disk. */
//        cache_write (sector_idx, buffer + bytes_written);
//      }
//    else
//      {
//        /* We need a bounce buffer. */
//        if (bounce == NULL)
//          {
//            bounce = malloc (DISK_SECTOR_SIZE);
//            if (bounce == NULL)
//              break;
//          }

//        /* If the sector contains data before or after the chunk
//           we're writing, then we need to read in the sector
//           first.  Otherwise we start with a sector of all zeros. */
//        if (sector_ofs > 0 || chunk_size < sector_left)
//          cache_read (sector_idx, bounce);
//        else
//          memset (bounce, 0, DISK_SECTOR_SIZE);
//        memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
//        cache_write (sector_idx, bounce);
//      }
      cache_write_len (sector_idx, buffer + bytes_written, sector_ofs, chunk_size);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  if (length_changed)
  {
    inode->data.length = node_length;
    lock_release (&inode->lock);
  }
  free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  lock_acquire (&inode->lock);
  inode->deny_write_cnt++;
  lock_release (&inode->lock);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  lock_acquire (&inode->lock);
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
  lock_release (&inode->lock);
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  lock_acquire (&inode->lock);
  ASSERT (inode->data.magic == INODE_MAGIC);
  ASSERT (inode->magic == INODE_MAGIC);
  off_t len = inode->data.length;
  lock_release (&inode->lock);
  return len;
}

static void
inode_init_indirect_disk (struct inode_indirect_disk* disk)
{
  size_t i = 0;
  for (i = 0; i < BLOCKS_PER_SECTOR; ++i)
  {
    disk->blocks[i] = -1;
  }
}

static bool 
inode_expand (struct inode* node, off_t from, off_t to)
{
  ASSERT (node->data.magic == INODE_MAGIC);
  ASSERT (node->magic == INODE_MAGIC);
  ASSERT (lock_held_by_current_thread (&node->lock));
  disk_sector_t di_sector = node->data.doubly_indirect_disk;
  int from_total;
  int from_first;
  int from_second;
  int to_total;
  int to_first;
  int to_second;
  if (from > 0)
  {
    from_total = ((int)from - 1) / DISK_SECTOR_SIZE;
    from_first = from_total / BLOCKS_PER_SECTOR;
    from_second = from_total % BLOCKS_PER_SECTOR;
  }
  else
  {
    from_total = -1;
    from_first = -1;
    from_second = BLOCKS_PER_SECTOR - 1;
  }
  if (to > 0)
  {
    to_total = ((int)to - 1) / DISK_SECTOR_SIZE;
    to_first = to_total / BLOCKS_PER_SECTOR;
    to_second = to_total % BLOCKS_PER_SECTOR;
  }
  else
  {
    to_total = -1;
    to_first = -1;
    to_second = BLOCKS_PER_SECTOR - 1;
  }
  int alloc_count = (to_total - from_total) + (to_first - from_first);
  if (alloc_count == 0)
  {
    return true;
  }
  disk_sector_t *sector_arr = malloc (alloc_count * sizeof (disk_sector_t));
  int i;
  for (i = 0; i < alloc_count; ++i)
  {
    if (!free_map_allocate (1, sector_arr + i))
    {
      break;
    }
  }
  if (i < alloc_count)
  {
    int k;
    for (k = 0; k < i; ++k)
    {
      free_map_release (*(sector_arr + k), 1);
    }
    return false;
  }
  i = 0;
  ASSERT (di_sector < (uint32_t)-1);
  struct inode_indirect_disk *first_disk = malloc (sizeof (struct inode_indirect_disk));
  cache_read (di_sector, first_disk);
  struct inode_indirect_disk *second_disk = NULL;
  if (from_first >= 0)
  {
    ASSERT (first_disk->blocks[from_first] < (uint32_t)-1);
    second_disk = malloc (sizeof (struct inode_indirect_disk));
    cache_read (first_disk->blocks[from_first], second_disk);
    ASSERT (second_disk->blocks[from_second] < (uint32_t)-1);
  }
  while (from_first != to_first || from_second != to_second)
  {
    from_second += 1;
    if (from_second >= BLOCKS_PER_SECTOR)
    {
      if (second_disk != NULL)
      {
        cache_write (first_disk->blocks[from_first], second_disk);
        free (second_disk);
      }
      from_first += 1;
      from_second = 0;
      second_disk = malloc (sizeof (struct inode_indirect_disk));
      inode_init_indirect_disk (second_disk);
      first_disk->blocks[from_first] = *(sector_arr + i);
      i += 1;
    }
    second_disk->blocks[from_second] = *(sector_arr + i);
    i += 1;
    cache_write (second_disk->blocks[from_second], zeros);
  }
  cache_write (first_disk->blocks[from_first], second_disk);
  free (second_disk);
  cache_write (di_sector, first_disk);
  free (first_disk);
  ASSERT (i == alloc_count);
  return true;
}
