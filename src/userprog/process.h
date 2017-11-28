#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "vm/mmap-file.h"

struct process_info 
{
  pid_t pid;
  char *name;
  int status;
  bool terminated;
  struct process_info *parent;
  struct process_info *children[256];
  struct file *owned_files[256];
  struct mmap_info *owned_mmap[256];
  tid_t inner_thread;
  struct condition wait_cond;
  struct lock wait_lock;
  struct lock info_lock;
  struct list_elem elem;
};

void process_init (void);
tid_t process_execute (const char *cmd_line);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
struct process_info *process_get_info (tid_t tid);
struct process_info *process_get_info_pid (pid_t pid);

#endif /* userprog/process.h */
