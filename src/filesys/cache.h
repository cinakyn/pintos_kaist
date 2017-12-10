#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "devices/disk.h"
#include "filesys/off_t.h"

void cache_init (void);
void cache_finish (void);
void cache_read (disk_sector_t sector, void *buffer);
void cache_write (disk_sector_t sector, const void *buffer);
void cache_read_len (disk_sector_t sector, void *buffer, off_t offset, off_t length);
void cache_write_len (disk_sector_t sector, const void *buffer, off_t offset, off_t length);

#endif /* filesys/cache.h */
