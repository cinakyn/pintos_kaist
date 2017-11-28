#ifndef VM_MMAP_FILE_H
#define VM_MMAP_FILE_H

#include "lib/user/syscall.h"
#include "lib/stdint.h"
#include "lib/stddef.h"
#include "filesys/off_t.h"

struct mmap_info
{
  mapid_t id;
  struct file *mapped_file;
  uintptr_t mapped_addr;
  size_t file_size;
  size_t total_size;
  off_t ofs;
  bool read_one_time;
  bool writable;
};

struct mmap_info *mmap_get_info (struct mmap_info** info_list, size_t size, void *addr);
mapid_t mmap_add_info (
    struct mmap_info** info_list, 
    size_t size, 
    struct file *mapped_file, 
    uintptr_t mapped_addr, 
    off_t ofs, 
    size_t file_size, 
    size_t total_size, 
    bool read_one_time,
    bool writable
    );
void mmap_remove_info (struct mmap_info** info_list, mapid_t id);
size_t mmap_swap_in (void *frame, void *vaddr, struct mmap_info *minfo);
size_t mmap_swap_out (void *frame, void *vaddr, struct mmap_info *minfo);
size_t mmap_calc_index (uintptr_t mapped_addr, uintptr_t vaddr);

#endif /* vm/mmap-file.h */
