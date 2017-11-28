#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stdbool.h>
#include <stdint.h>
#include "vm/suppage.h"
#include "threads/synch.h"
#include "vm/mmap-file.h"

struct lock frame_magic_lock;

void frame_init (void);
void *frame_get (struct suppage_info *owner);
void *frame_with_owner (struct suppage_info *owner);
void frame_return (struct suppage_info *owner);
void frame_exit (void);

#endif /* vm/frame.h */
