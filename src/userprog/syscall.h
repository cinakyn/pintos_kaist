#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

struct lock filesys_lock;

void syscall_init (void);
void syscall_exit_status (int status);

#endif /* userprog/syscall.h */
