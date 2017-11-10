#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stddef.h>

void swap_init (void);
void swap_exit (void);
void swap_in (size_t index, void *frame);
size_t swap_out (void *frame);
void swap_clear (size_t index);

#endif /* vm/swap.h */
