#ifndef VM_SUPPAGE_H
#define VM_SUPPAGE_H

#include "lib/kernel/hash.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "vm/mmap-file.h"

struct suppage
{
  struct lock sp_lock;
  struct hash sp_map;
};

enum mem_type
{
  MEM_TYPE_SWAP,
  MEM_TYPE_MMAP_FILE,
  MEM_TYPE_FRAME,
  MEM_TYPE_INVALID
};

struct suppage_info
{
  enum mem_type mt;
  uint32_t *pagedir;
  void *page;
  size_t index;
  struct mmap_info *mmap_info;
  bool writable;
  struct hash_elem helem;
  struct lock *proc_info_lock;
};


void suppage_init (struct suppage *sp);
void suppage_clear (struct suppage *sp);
struct suppage_info *suppage_create_info (struct suppage *sp, struct lock *proc_info_lock, uint32_t *pagedir, void *upage, bool writable);
void suppage_set_mmap_info (struct suppage_info *sp, struct mmap_info *mmap_info, size_t index);
void suppage_remove_info (struct suppage *sp, struct suppage_info *info);
struct suppage_info *suppage_get_info (struct suppage *sp, void *upage);

#endif /* vm/suppage.h */
