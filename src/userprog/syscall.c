#include <devices/input.h>
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);
static void syscall_halt (void *sp, struct intr_frame *);
static void syscall_exit (void *sp, struct intr_frame *);
static void syscall_exec (void *sp, struct intr_frame *);
static void syscall_wait (void *sp, struct intr_frame *);
static void syscall_create (void *sp, struct intr_frame *);
static void syscall_remove (void *sp, struct intr_frame *);
static void syscall_open (void *sp, struct intr_frame *);
static void syscall_filesize (void *sp, struct intr_frame *);
static void syscall_read (void *sp, struct intr_frame *);
static void syscall_write (void *sp, struct intr_frame *);
static void syscall_seek (void *sp, struct intr_frame *);
static void syscall_tell (void *sp, struct intr_frame *);
static void syscall_close (void *sp, struct intr_frame *);
static bool convert_addr (const void *vaddr, size_t size, void **paddr);
static bool convert_str (const char *vaddr, char **paddr);
static struct file *get_file (int fd);
static struct lock filesys_lock;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{
  void *sp = f->esp;
  void *pAdd;
  if (!convert_addr (f->esp, sizeof (int), &pAdd))
  {
    syscall_exit_status (-1);
    return;
  }
  int call_number = *((int *)(pAdd));
  sp += sizeof (int);
  switch (call_number)
    {
      case SYS_HALT:
        syscall_halt (sp, f);
        break;
      case SYS_EXIT:
        syscall_exit (sp, f);
        break;
      case SYS_EXEC:
        syscall_exec (sp, f);
        break;
      case SYS_WAIT:
        syscall_wait (sp, f);
        break;
      case SYS_CREATE:
        syscall_create (sp, f);
        break;
      case SYS_REMOVE:
        syscall_remove (sp, f);
        break;
      case SYS_OPEN:
        syscall_open (sp, f);
        break;
      case SYS_FILESIZE:
        syscall_filesize (sp, f);
        break;
      case SYS_READ:
        syscall_read (sp, f);
        break;
      case SYS_WRITE:
        syscall_write (sp, f);
        break;
      case SYS_SEEK:
        syscall_seek (sp, f);
        break;
      case SYS_TELL:
        syscall_tell (sp, f);
        break;
      case SYS_CLOSE:
        syscall_close (sp, f);
        break;
      default:
        printf ("wtf\n");
        syscall_exit_status (-1);
    }
}

static void syscall_halt (void *sp UNUSED, struct intr_frame *f UNUSED)
{
  power_off ();
}

static void syscall_exit (void *sp, struct intr_frame *f UNUSED)
{
  int status;
  void *pAdd;
  if (!convert_addr (sp, sizeof (int), &pAdd))
    {
      status = -1;
    }
  else
    {
      status = *((int *)pAdd);
    }
  syscall_exit_status (status);
}

void syscall_exit_status (int status)
{
  struct process_info *info = process_get_info (thread_current ()->tid);
  lock_acquire (&info->info_lock);
  lock_acquire (&filesys_lock);
  info->status = status;
  size_t i = 0;
  for (i = 0;
       i < sizeof (info->owned_files) / sizeof (struct file *);
       ++i)
    {
      struct file *f = info->owned_files[i];
      if (f != NULL)
        {
          file_close (f);
          info->owned_files[i] = NULL;
        }
    }
  printf ("%s: exit(%d)\n", info->name, status); 
  lock_release (&filesys_lock);
  lock_release (&info->info_lock);
  thread_exit ();
}

static void syscall_exec (void *sp, struct intr_frame *f)
{
  void *pAdd;
  char *cmd_line;
  if (!convert_addr (sp, sizeof (char *), &pAdd))
    {
      f->eax = -1;
      syscall_exit_status (-1);
      return;
    }
  cmd_line = *((char **)pAdd);
  if (!convert_str (cmd_line, &cmd_line))
    {
      f->eax = -1;
      syscall_exit_status (-1);
      return;
    }

  lock_acquire (&filesys_lock);
  tid_t tid = process_execute (cmd_line);
  if (tid >= 0)
    {
      f->eax = process_get_info (tid)->pid;
    }
  else
    {
      f->eax = -1;
    }
  lock_release (&filesys_lock);
}

static void syscall_wait (void *sp, struct intr_frame *f)
{
  pid_t pid;
  void *pAdd;
  if (!convert_addr (sp, sizeof (pid_t), &pAdd))
    {
      f->eax = -1;
      syscall_exit_status (-1);
      return;
    }
  pid = *((pid_t *) pAdd);
  struct process_info *info = process_get_info_pid (pid);
  if (info == NULL)
    {
      f->eax = -1;
    }
  else
    {
      f->eax = process_wait (info->inner_thread);
    }
}

static void syscall_create (void *sp, struct intr_frame *f)
{
  void *pAdd;
  char *file_name;
  unsigned initial_size;
  if (!convert_addr (sp, sizeof (char *), &pAdd))
    {
      f->eax = false;
      syscall_exit_status (-1);
      return;
    }
  file_name = *((char **)pAdd);
  sp += sizeof (char *);
  if (!convert_str (file_name, &file_name))
    {
      f->eax = false;
      syscall_exit_status (-1);
      return;
    }
  if (!convert_addr (sp, sizeof (unsigned *), &pAdd))
    {
      f->eax = false;
      syscall_exit_status (-1);
      return;
    }
  initial_size = *((unsigned *)pAdd);
  lock_acquire (&filesys_lock);
  f->eax = filesys_create (file_name, initial_size);
  lock_release (&filesys_lock);
}

static void syscall_remove (void *sp, struct intr_frame *f)
{
  void *pAdd;
  char *file_name;
  if (!convert_addr (sp, sizeof (char *), &pAdd))
    {
      f->eax = false;
      syscall_exit_status (-1);
      return;
    }
  file_name = *((char **)pAdd);
  if (!convert_str (file_name, &file_name))
    {
      f->eax = false;
      syscall_exit_status (-1);
      return;
    }
  lock_acquire (&filesys_lock);
  f->eax = filesys_remove (file_name);
  lock_release (&filesys_lock);
}

static void syscall_open (void *sp, struct intr_frame *f)
{
  void *pAdd;
  if (!convert_addr (sp, sizeof (char *), &pAdd))
    {
      syscall_exit_status (-1);
      return;
    }
  char *file_name = *((char **)pAdd);
  if (!convert_str (file_name, &file_name))
    {
      syscall_exit_status (-1);
      return;
    }
  lock_acquire (&filesys_lock);
  struct file *o = filesys_open (file_name);
  if (o == NULL)
    {
      f->eax  = -1;
    }
  else
    {
      struct process_info *proc_info = process_get_info (thread_current ()->tid);
      lock_acquire (&proc_info->info_lock);
      size_t i;
      for (i = 0;
           i < sizeof (proc_info->owned_files) / sizeof (struct file *);
           ++i)
        {
          if (proc_info->owned_files[i] == NULL)
            {
              proc_info->owned_files[i] = o;
              break;
            }
        }
      lock_release (&proc_info->info_lock);
      // there's no room
      if (i >= sizeof (proc_info->owned_files) / sizeof (struct file *))
      {
        f->eax = -1;
      }
      else
      {
        f->eax = i + 2;
      }
    }
  lock_release (&filesys_lock);
}

static void syscall_filesize (void *sp, struct intr_frame *f)
{
  void *pAdd;
  int fd;
  // get fd
  if (!convert_addr (sp, sizeof (int), &pAdd))
    {
      syscall_exit_status (-1);
      return;
    }
  fd = *((int *)pAdd);

  if (fd < 2)
    {
      f->eax = -1;
      return;
    }
  struct file *fp = get_file (fd);
  if (fp == NULL)
  {
    f->eax = -1;
    return;
  }
  lock_acquire (&filesys_lock);
  f->eax = file_length (fp);
  lock_release (&filesys_lock);
}

static void syscall_read (void *sp, struct intr_frame *f)
{
  void *pAdd;
  int fd;
  void *buffer;
  unsigned size;
  // get fd
  if (!convert_addr (sp, sizeof (int), &pAdd))
    {
      syscall_exit_status (-1);
      return;
    }
  fd = *((int *)pAdd);
  sp += sizeof (int);
  //get buffer
  if (!convert_addr (sp, sizeof (void *), &pAdd))
    {
      syscall_exit_status (-1);
      return;
    }
  buffer = *((void **)pAdd);
  sp += sizeof (void *);
  // get size
  if (!convert_addr (sp, sizeof (unsigned), &pAdd))
    {
      syscall_exit_status (-1);
      return;
    }
  size = *((unsigned *)pAdd);
  sp += sizeof (unsigned);
  // verify buffer content
  if (!convert_addr (buffer, size, &buffer))
    {
      syscall_exit_status (-1);
      return;
    }

  if (fd < 0 || fd == 1)
    {
      f->eax = -1;
      return;
    }
  if (fd == 0)
    {
      unsigned i;
      int written = 0;
      for (i = 0; i < size; ++i)
        {
          uint8_t c = input_getc ();
          *(((uint8_t *)buffer) + i) = c;
          written++;
          if (c == 0)
            break;
        }
      f->eax = written;
    }
  struct file *fp = get_file (fd);
  if (fp == NULL)
  {
    f->eax = -1;
    return;
  }
  lock_acquire (&filesys_lock);
  f->eax = file_read (fp, buffer, size);
  lock_release (&filesys_lock);
}

static void syscall_write (void *sp, struct intr_frame *f)
{
  void *pAdd;
  int fd;
  void *buffer;
  unsigned size;
  // get fd
  if (!convert_addr (sp, sizeof (int), &pAdd))
    {
      syscall_exit_status (-1);
      return;
    }
  fd = *((int *)pAdd);
  sp += sizeof (int);
  //get buffer
  if (!convert_addr (sp, sizeof (void *), &pAdd))
    {
      syscall_exit_status (-1);
      return;
    }
  buffer = *((void **)pAdd);
  sp += sizeof (void *);
  // get size
  if (!convert_addr (sp, sizeof (unsigned), &pAdd))
    {
      syscall_exit_status (-1);
      return;
    }
  size = *((unsigned *)pAdd);
  sp += sizeof (unsigned);
  // verify buffer content
  if (!convert_addr (buffer, size, &buffer))
    {
      syscall_exit_status (-1);
      return;
    }

  if (fd <= 0)
    {
      f->eax = -1;
      return;
    }
  if (fd == 1)
    {
      f->eax = size;
      putbuf ((char *)buffer, size / sizeof (char));
    }
  struct file *fp = get_file (fd);
  if (fp == NULL)
  {
    f->eax = -1;
    return;
  }
  lock_acquire (&filesys_lock);
  f->eax = file_write (fp, buffer, size);
  lock_release (&filesys_lock);
}

static void syscall_seek (void *sp, struct intr_frame *f)
{
  void *pAdd;
  int fd;
  unsigned position;
  // get fd
  if (!convert_addr (sp, sizeof (int), &pAdd))
    {
      syscall_exit_status (-1);
      return;
    }
  fd = *((int *)pAdd);
  sp += sizeof (int);
  // get position
  if (!convert_addr (sp, sizeof (unsigned), &pAdd))
    {
      syscall_exit_status (-1);
      return;
    }
  position = *((unsigned *)pAdd);

  if (fd < 2)
    {
      return;
    }
  struct file *fp = get_file (fd);
  if (fp == NULL)
  {
    f->eax = -1;
    return;
  }
  lock_acquire (&filesys_lock);
  file_seek (fp, position);
  lock_release (&filesys_lock);
}

static void syscall_tell (void *sp, struct intr_frame *f)
{
  void *pAdd;
  int fd;
  // get fd
  if (!convert_addr (sp, sizeof (int), &pAdd))
    {
      syscall_exit_status (-1);
      return;
    }
  fd = *((int *)pAdd);

  if (fd < 2)
    {
      f->eax = 0;
      return;
    }
  struct file *fp = get_file (fd);
  if (fp == NULL)
  {
    f->eax = 0;
    return;
  }
  lock_acquire (&filesys_lock);
  f->eax = file_tell (fp);
  lock_release (&filesys_lock);
}

static void syscall_close (void *sp, struct intr_frame *f)
{
  void *pAdd;
  int fd;
  // get fd
  if (!convert_addr (sp, sizeof (int), &pAdd))
    {
      syscall_exit_status (-1);
      return;
    }
  fd = *((int *)pAdd);

  if (fd < 2)
    {
      return;
    }
  struct file *fp = get_file (fd);
  if (fp == NULL)
  {
    f->eax = -1;
    return;
  }
  struct process_info *proc_info = process_get_info (thread_current ()->tid);
  lock_acquire (&proc_info->info_lock);
  proc_info->owned_files[fd - 2] = NULL;
  lock_release (&proc_info->info_lock);
  lock_acquire (&filesys_lock);
  file_close (fp);
  lock_release (&filesys_lock);
}

/* returns validty of vaddr. and set paddr */
static bool convert_addr (const void *vaddr, size_t size, void **paddr)
{
  if (!is_user_vaddr (vaddr + size - 1))
    {
      *paddr = NULL;
      return false;
    }
  void *unused_result = pagedir_get_page (thread_current ()->pagedir, vaddr + size - 1);
  if (unused_result == NULL)
    {
      *paddr = NULL;
      return false;
    }
  if (!is_user_vaddr (vaddr))
    {
      *paddr = NULL;
      return false;
    }
  void *result = pagedir_get_page (thread_current ()->pagedir, vaddr);
  if (result == NULL)
    {
      *paddr = NULL;
      return false;
    }
  *paddr = result;
  return true;
}

/* returns validty of string. and set paddr */
static bool convert_str (const char *vaddr, char **paddr)
{
  if (!is_user_vaddr (vaddr))
    {
      *paddr = NULL;
      return false;
    }
  char *result = pagedir_get_page (thread_current ()->pagedir, vaddr);
  if (result == NULL)
    {
      *paddr = NULL;
      return false;
    }
  const char* index = vaddr;
  while (is_user_vaddr (index))
  {
    if (*index  == '\0')
    {
      break;
    }
    index++;
  }
  if (!is_user_vaddr (index) || pagedir_get_page (thread_current ()->pagedir, index) == NULL)
  {
      *paddr = NULL;
      return false;
  }
  *paddr = result;
  return true;
}

static struct file *
get_file (int fd)
{
  if (fd < 2)
    {
      return NULL;
    }
  struct process_info *proc_info = process_get_info (thread_current ()->tid);
  lock_acquire (&proc_info->info_lock);
  struct file* fp;
  if (fd >= (int) (sizeof (proc_info->owned_files) / sizeof (proc_info->owned_files[0])))
    {
      fp = NULL;
    }
  else
    {
      fp = proc_info->owned_files[fd - 2];
    }
  lock_release (&proc_info->info_lock);
  return fp;
}
