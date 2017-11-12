#ifndef VM_SUPPAGE_H
#define VM_SUPPAGE_H

#include "lib/kernel/hash.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"

struct suppage
{
  struct lock sp_lock;
  struct hash sp_map;
};

enum mem_type
{
  MEM_TYPE_SWAP,
  MEM_TYPE_FRAME,
  MEM_TYPE_INVALID
};

struct suppage_info
{
  enum mem_type mt;
  uint32_t *pagedir;
  void *page;
  size_t index;
  bool writable;
  struct hash_elem helem;
};


void suppage_init (struct suppage *sp);
void suppage_clear (struct suppage *sp);
struct suppage_info *suppage_create_info (struct suppage *sp, uint32_t *pagedir, void *upage, bool writable);
struct suppage_info *suppage_get_info (struct suppage *sp, void *upage);

#endif /* vm/suppage.h */
