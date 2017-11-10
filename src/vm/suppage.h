#ifndef VM_SUPPAGE_H
#define VM_SUPPAGE_H

#include "lib/kernel/hash.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"

struct suppage
{
  uint32_t *pagedir;
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
  void *page;
  void *frame;
  size_t index;
  bool writable;
  struct hash_elem helem;
};


void suppage_init (struct suppage *sp, uint32_t *pagedir);
void suppage_clear (struct suppage *sp);
void suppage_set_swap (struct suppage *sp, void *upage, bool writable, size_t index);
void suppage_set_frame (struct suppage *sp, void *upage, bool writable, void *frame);
struct suppage_info *suppage_get_info (struct suppage *sp, void *upage);

#endif /* vm/suppage.h */
