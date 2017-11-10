#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stdbool.h>
#include <stdint.h>
#include "vm/suppage.h"

void frame_init (void);
void *frame_get (uint32_t *pd, void *upage, struct suppage *sp, bool writable);
void frame_return (uint32_t *pd, void *upage, void *frame);
void frame_exit (void);

#endif /* vm/frame.h */
