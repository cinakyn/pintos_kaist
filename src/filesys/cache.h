#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "devices/disk.h"

void cache_init (void);
void cache_finish (void);
void cache_read (disk_sector_t sector, void *buffer);
void cache_write (disk_sector_t sector, const void *buffer);

#endif /* filesys/cache.h */
