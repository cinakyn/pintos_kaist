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
#include "vm/mmap-file.h"
#include "vm/frame.h"

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
static void syscall_close (void *sp, struct intr_frame *);
static void syscall_mmap (void *sp, struct intr_frame *);
static void syscall_munmap (void *sp, struct intr_frame *);
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static bool is_valid_addr (void *vaddr, size_t size, bool writable);
static bool is_valid_str (char *vaddr);
static bool copy_value (const void *from, void *to, size_t size);
static struct file *get_file (int fd);

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
  int call_number;
  if (!copy_value (f->esp, &call_number, sizeof (call_number)))
    {
      syscall_exit_status (-1);
      return;
    }
  sp += sizeof (int);
  thread_current ()->esp_backup = f->esp;
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
      case SYS_MMAP:
        syscall_mmap (sp, f);
        break;
      case SYS_MUNMAP:
        syscall_munmap (sp, f);
        break;
      default:
        printf ("wtf\n");
        syscall_exit_status (-1);
    }
    thread_current ()->esp_backup = NULL;
}

static void syscall_halt (void *sp UNUSED, struct intr_frame *f UNUSED)
{
  power_off ();
}

static void syscall_exit (void *sp, struct intr_frame *f UNUSED)
{
  int status;
  if (!copy_value (sp, &status, sizeof (status)))
    {
      status = -1;
    }
  syscall_exit_status (status);
}

void syscall_exit_status (int status)
{
  struct process_info *info = process_get_info (thread_current ()->tid);
  lock_acquire (&filesys_lock);
  lock_acquire (&info->info_lock);
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
  lock_release (&info->info_lock);
  lock_release (&filesys_lock);
  thread_exit ();
}

static void syscall_exec (void *sp, struct intr_frame *f)
{
  char *cmd_line;
  if (!copy_value (sp, &cmd_line, sizeof (cmd_line)))
    {
      f->eax = -1;
      syscall_exit_status (-1);
      return;
    }
  if (!is_valid_str (cmd_line))
    {
        f->eax = -1;
        syscall_exit_status (-1);
        return;
    }
  tid_t tid = process_execute (cmd_line);
  if (tid >= 0)
    {
      f->eax = process_get_info (tid)->pid;
    }
  else
    {
      f->eax = -1;
    }
}

static void syscall_wait (void *sp, struct intr_frame *f)
{
  pid_t pid;
  if (!copy_value (sp, &pid, sizeof (pid)))
    {
      f->eax = -1;
      syscall_exit_status (-1);
      return;
    }
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
  char *file_name;
  if (!copy_value (sp, &file_name, sizeof (file_name)))
    {
      f->eax = -1;
      syscall_exit_status (-1);
      return;
    }
  if (!is_valid_str (file_name))
    {
      f->eax = -1;
      syscall_exit_status (-1);
      return;
    }
  sp += sizeof (file_name);
  unsigned initial_size;
  if (!copy_value (sp, &initial_size, sizeof (initial_size)))
    {
      f->eax = -1;
      syscall_exit_status (-1);
      return;
    }
  lock_acquire (&filesys_lock);
  f->eax = filesys_create (file_name, initial_size);
  lock_release (&filesys_lock);
}

static void syscall_remove (void *sp, struct intr_frame *f)
{
  char *file_name;
  if (!copy_value (sp, &file_name, sizeof (file_name)))
    {
      f->eax = -1;
      syscall_exit_status (-1);
      return;
    }
  if (!is_valid_str (file_name))
    {
      f->eax = -1;
      syscall_exit_status (-1);
      return;
    }
  lock_acquire (&filesys_lock);
  f->eax = filesys_remove (file_name);
  lock_release (&filesys_lock);
}

static void syscall_open (void *sp, struct intr_frame *f)
{
  char *file_name;
  if (!copy_value (sp, &file_name, sizeof (file_name)))
    {
      f->eax = -1;
      syscall_exit_status (-1);
      return;
    }
  if (!is_valid_str (file_name))
    {
      f->eax = -1;
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
  // get fd
  int fd;
  if (!copy_value (sp, &fd, sizeof (fd)))
    {
      f->eax = -1;
      syscall_exit_status (-1);
      return;
    }

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
  // get fd
  int fd;
  if (!copy_value (sp, &fd, sizeof (fd)))
    {
      f->eax = -1;
      syscall_exit_status (-1);
      return;
    }
  sp += sizeof (fd);
  //get buffer
  void *buffer;
  if (!copy_value (sp, &buffer, sizeof (buffer)))
    {
      f->eax = -1;
      syscall_exit_status (-1);
      return;
    }
  sp += sizeof (buffer);
  // get size
  unsigned size;
  if (!copy_value (sp, &size, sizeof (size)))
    {
      f->eax = -1;
      syscall_exit_status (-1);
      return;
    }
  sp += sizeof (size);
  // verify buffer content
  if (!is_valid_addr (buffer, size, true))
    {
      f->eax = -1;
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
  // get fd
  int fd;
  if (!copy_value (sp, &fd, sizeof (fd)))
    {
      f->eax = -1;
      syscall_exit_status (-1);
      return;
    }
  sp += sizeof (fd);
  //get buffer
  void *buffer;
  if (!copy_value (sp, &buffer, sizeof (buffer)))
    {
      f->eax = -1;
      syscall_exit_status (-1);
      return;
    }
  sp += sizeof (buffer);
  // get size
  unsigned size;
  if (!copy_value (sp, &size, sizeof (size)))
    {
      f->eax = -1;
      syscall_exit_status (-1);
      return;
    }
  sp += sizeof (size);
  // verify buffer content
  if (!is_valid_addr (buffer, size, false))
    {
      f->eax = -1;
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

static void syscall_seek (void *sp, struct intr_frame *f UNUSED)
{
  // get fd
  int fd;
  if (!copy_value (sp, &fd, sizeof (fd)))
    {
      syscall_exit_status (-1);
      return;
    }
  sp += sizeof (fd);
  // get position
  unsigned position;
  if (!copy_value (sp, &position, sizeof (position)))
    {
      syscall_exit_status (-1);
      return;
    }
  sp += sizeof (position);

  if (fd < 2)
    {
      return;
    }
  struct file *fp = get_file (fd);
  if (fp == NULL)
  {
    return;
  }
  lock_acquire (&filesys_lock);
  file_seek (fp, position);
  lock_release (&filesys_lock);
}

static void syscall_tell (void *sp, struct intr_frame *f)
{
  // get fd
  int fd;
  if (!copy_value (sp, &fd, sizeof (fd)))
    {
      f->eax = -1;
      syscall_exit_status (-1);
      return;
    }

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
  // get fd
  int fd;
  if (!copy_value (sp, &fd, sizeof (fd)))
    {
      f->eax = -1;
      syscall_exit_status (-1);
      return;
    }

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

static void
syscall_mmap (void *sp, struct intr_frame *f)
{
  // get fd
  int fd;
  if (!copy_value (sp, &fd, sizeof (fd)))
    {
      f->eax = -1;
      syscall_exit_status (-1);
      return;
    }

  if (fd < 2)
    {
      f->eax = 0;
      syscall_exit_status (-1);
      return;
    }
  if (get_file (fd) == NULL)
    {
      f->eax = 0;
      syscall_exit_status (-1);
      return;
    }
  sp += sizeof (fd);
  //get buffer
  void *addr;
  if (!copy_value (sp, &addr, sizeof (addr)))
    {
      f->eax = -1;
      syscall_exit_status (-1);
      return;
    }
  if ((uintptr_t) addr == 0)
    {
      f->eax = MAP_FAILED;
      return;
    }
  if (pg_ofs (addr) != 0)
    {
      f->eax = MAP_FAILED;
      return;
    }
  struct process_info *proc_info = process_get_info (thread_current ()->tid);
  struct file *mapped_file = get_file (fd);
  lock_acquire (&filesys_lock);
  size_t file_size = file_length (mapped_file);
  lock_release (&filesys_lock);

  lock_acquire (&frame_magic_lock);
  lock_acquire (&proc_info->info_lock);
  mapid_t id = mmap_add_info (proc_info->owned_mmap, 256, mapped_file, (uintptr_t)addr, 0, file_size, file_size, false, true);
  lock_release (&proc_info->info_lock);
  lock_release (&frame_magic_lock);
  f->eax = id;
}

static void
syscall_munmap (void *sp, struct intr_frame *f)
{
  // get mapid
  mapid_t id;
  if (!copy_value (sp, &id, sizeof (id)))
    {
      f->eax = -1;
      syscall_exit_status (-1);
      return;
    }
  struct process_info *proc_info = process_get_info (thread_current ()->tid);
  lock_acquire (&frame_magic_lock);
  lock_acquire (&proc_info->info_lock);
  mmap_remove_info (proc_info->owned_mmap, id);
  lock_release (&proc_info->info_lock);
  lock_release (&frame_magic_lock);
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "r" (byte));
  return error_code != -1;
}

static bool
is_valid_addr (void *vaddr, size_t size, bool writable)
{
  if (!is_user_vaddr (vaddr + size - 1))
    {
      return false;
    }
  if (!is_user_vaddr (vaddr))
    {
      return false;
    }
  if (get_user (vaddr + size - 1) < 0)
    {
      return false;
    }
  if (get_user (vaddr) < 0)
    {
      return false;
    }
  if (writable)
    {
      if (!put_user (vaddr + size - 1, (uint8_t)get_user (vaddr + size - 1)))
        {
          return false;
        }
      if (!put_user (vaddr, (uint8_t)get_user (vaddr)))
        {
          return false;
        }
    }
  return true;
}

static bool is_valid_str (char *vaddr)
{
  char* index = vaddr;
  while (true)
  {
    if (!is_user_vaddr (index))
      {
        return false;
      }
    int read = get_user ((uint8_t *)index);
    if (read < 0)
      {
        return false;
      }
    if ((char) read  == '\0')
    {
      break;
    }
    index++;
  }
  return true;
}
static bool copy_value (const void *from, void *to, size_t size)
{
  size_t i = 0;
  const char *f = from;
  char *t = to;
  for (i = 0; i < size; ++i)
  {
    if (!is_user_vaddr (f + i))
      {
        return false;
      }
    int read = get_user ((uint8_t *)(f + i));
    if (read < 0)
      {
        return false;
      }
    *(t + i) = (char) read;
  }
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
