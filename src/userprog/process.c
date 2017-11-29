#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "vm/frame.h"
#include "vm/mmap-file.h"
#include "userprog/syscall.h"

static thread_func start_process NO_RETURN;
static pid_t get_next_pid (void);
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static void process_info_init (struct process_info *info, tid_t tid);
static pid_t next_pid;
static struct lock pid_lock;
static struct list pinfo_list;
static struct lock pinfo_list_lock;

struct process_start_info
{
  char *cmd_line;
  struct semaphore sema_ready;
  struct semaphore sema_done;
  bool success;
};

/* get next pid_t to use */
static pid_t
get_next_pid (void)
{
  lock_acquire (&pid_lock);
  pid_t result = next_pid++;
  lock_release (&pid_lock);
  return result;
}

/* intialize procss system. */
void
process_init (void)
{
  next_pid = 10000;
  lock_init (&pid_lock);
  list_init (&pinfo_list);
  lock_init (&pinfo_list_lock);

  /* init process. */
  struct process_info *info = calloc (sizeof (struct process_info), 1);
  ASSERT (info != NULL);
  process_info_init (info, thread_current()->tid);
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *cmd_line) 
{
  char *cmd_copy;
  tid_t tid;

  /* limit cmd_line */
  if (strlen (cmd_line) * sizeof (char) > 1024)
    return TID_ERROR;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  cmd_copy = palloc_get_page (0);
  if (cmd_copy == NULL)
    return TID_ERROR;
  strlcpy (cmd_copy, cmd_line, PGSIZE);

  /* Allocate process info */
  struct process_info *info = calloc (sizeof (struct process_info), 1);
  if (info == NULL)
    return TID_ERROR;

  /* Create a new thread to execute FILE_NAME. */
  struct process_start_info start_info;
  start_info.success = false;
  start_info.cmd_line = cmd_copy;
  sema_init (&start_info.sema_ready, 0);
  sema_init (&start_info.sema_done, 0);
  tid = thread_create (cmd_line, PRI_DEFAULT, start_process, &start_info);
  if (tid == TID_ERROR)
    palloc_free_page (cmd_copy);

  /* set process info */
  process_info_init (info, tid);
  // add to parent
  struct process_info *parent_info = process_get_info (thread_current ()->tid);
  lock_acquire (&parent_info->info_lock);
  size_t i;
  for (i = 0;
       i < sizeof (parent_info->children) / sizeof (parent_info->children[0]);
       ++i)
    {
      if (parent_info->children[i] == NULL)
      {
        parent_info->children[i] = info;
        break;
      }
    }
  ASSERT (i < sizeof (parent_info->children) / sizeof (parent_info->children[0]));
  info->parent = parent_info;
  lock_release (&parent_info->info_lock);
  sema_up (&start_info.sema_ready);
  sema_down (&start_info.sema_done);
  if (start_info.success)
    {
      return tid;
    }
  else
    {
      return -1;
    }
}

static void 
process_info_init (struct process_info *info, tid_t tid)
{
  info->inner_thread = tid;
  info->parent = NULL;
  info->pid = get_next_pid ();
  info->name = NULL;
  info->terminated = false;
  info->exec_file = NULL;
  memset (info->children, 0, sizeof (info->children));
  memset (info->owned_files, 0, sizeof (info->owned_files));
  memset (info->owned_mmap, 0, sizeof (info->owned_mmap));
  lock_init (&info->wait_lock);
  lock_init (&info->info_lock);
  cond_init (&info->wait_cond);
  lock_acquire (&pinfo_list_lock);
  {
    list_push_back (&pinfo_list, &info->elem);
  }
  lock_release (&pinfo_list_lock);
}


/* A thread function that loads a user process and makes it start
   running. */
static void
start_process (void *aux)
{
  struct intr_frame if_;
  bool success;
  struct process_start_info* start_info = aux;
  char* cmd_line = start_info->cmd_line;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (cmd_line, &if_.eip, &if_.esp);
  start_info->success = success;
  sema_up (&start_info->sema_done);
  /* If load failed, quit. */
  palloc_free_page (cmd_line);
  if (!success) 
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  // find child.
  struct process_info* info = process_get_info (thread_current()->tid);
  struct process_info* child_info = NULL;
  lock_acquire (&info->info_lock);
  {
    size_t i;
    for (i = 0; 
         i < sizeof (info->children) / sizeof (info->children[0]);
         ++i)
      {
        struct process_info *temp = info->children[i];
        if (temp != NULL && temp->inner_thread == child_tid)
          {
            ASSERT (child_info == NULL);
            child_info = temp;
          }
      }
  }
  lock_release (&info->info_lock);
  // get status.
  if (child_info == NULL)
    {
      return -1;
    }
  else
    {
      while (!child_info->terminated)
        {
          lock_acquire (&info->wait_lock);
          cond_wait (&info->wait_cond, &info->wait_lock);
          lock_release (&info->wait_lock);
        }
      ASSERT (child_info->terminated);
      int result = child_info->status;
      // remove child.
      size_t i;
      for (i = 0; 
           i < sizeof (info->children) / sizeof (info->children[0]);
           ++i)
        {
          if (info->children[i] == child_info)
            {
              info->children[i] = NULL;
            }
        }
      lock_acquire (&pinfo_list_lock);
      list_remove (&child_info->elem);
      lock_release (&pinfo_list_lock);
      if (child_info->name != NULL)
      {
        free (child_info->name);
      }
      free (child_info);
      return result;
    }
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *curr = thread_current ();
  uint32_t *pd;

  struct process_info *info = process_get_info (curr->tid);
  struct process_info *parent_info = info->parent;

  /* ummap */
  lock_acquire (&frame_magic_lock);
  lock_acquire (&info->info_lock);
  size_t i;
  for (i = 0;
       i < sizeof (info->owned_mmap) / sizeof (struct mmap_info *);
       ++i)
    {
      if (info->owned_mmap[i] != NULL)
        {
          mmap_remove_info (info->owned_mmap, i);
        }
    }
  lock_release (&info->info_lock);
  lock_release (&frame_magic_lock);

  /* modidfy process info */
  lock_acquire (&filesys_lock);
  {
    file_allow_write (info->exec_file);
    file_close (info->exec_file);
  }
  lock_release (&filesys_lock);
  lock_acquire (&info->info_lock);
  {
    info->terminated = true;
    info->exec_file = NULL;
  }
  lock_release (&info->info_lock);

  /* wait children which isn't terminated. */
  for (i = 0; 
       i < sizeof (info->children) / sizeof (info->children[0]);
       ++i)
    {
      struct process_info *child_info = info->children[i];
      if (child_info != NULL)
        {
          process_wait (child_info->inner_thread);
        }
    }


  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = curr->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      curr->pagedir = NULL;
      pagedir_activate (NULL);
      lock_acquire (&frame_magic_lock);
      suppage_clear (&curr->sp);
      pagedir_destroy (pd);
      lock_release (&frame_magic_lock);
    }

  /* release waiting parent process */
  if (parent_info != NULL)
  {
    lock_acquire (&parent_info->info_lock);
    {
      lock_acquire (&parent_info->wait_lock);
      cond_broadcast (&parent_info->wait_cond, &parent_info->wait_lock);
      lock_release (&parent_info->wait_lock);
    }
    lock_release (&parent_info->info_lock);
  }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* get process info from tid */
struct process_info *
process_get_info (tid_t tid)
{
  lock_acquire (&pinfo_list_lock);
  struct list_elem *e;
  struct process_info *found = NULL;
  for (e = list_begin (&pinfo_list);
       e != list_end (&pinfo_list);
       e = list_next (e))
    {
      struct process_info *info = list_entry (e, struct process_info, elem);
      if (info->inner_thread == tid)
        {
          found = info;
          break;
        }
    }
  lock_release (&pinfo_list_lock);
  ASSERT (found != NULL);
  return found;
}

/* get process info from pid */
struct process_info *
process_get_info_pid (pid_t pid)
{
  lock_acquire (&pinfo_list_lock);
  struct list_elem *e;
  struct process_info *found = NULL;
  for (e = list_begin (&pinfo_list);
       e != list_end (&pinfo_list);
       e = list_next (e))
    {
      struct process_info *info = list_entry (e, struct process_info, elem);
      if (info->pid == pid)
        {
          found = info;
          break;
        }
    }
  lock_release (&pinfo_list_lock);
  return found;
}


/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, const char *cmd_line);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *cmd_line, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();
  lock_acquire (&frame_magic_lock);
  suppage_init (&t->sp);
  lock_release (&frame_magic_lock);

  /* Open executable file. */
  char file_name[1024];
  size_t index = 0;
  char temp_c = cmd_line[index];
  while (temp_c != ' ' && temp_c != '\0')
    {
      file_name[index] = cmd_line[index];
      index += 1;
      temp_c = cmd_line[index];
      ASSERT (index < 1023);
    }
  file_name[index] = '\0';
  lock_acquire (&filesys_lock);
  file = filesys_open (file_name);
  lock_release (&filesys_lock);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  lock_acquire (&filesys_lock);
  file_deny_write (file);
  int read_result = file_read (file, &ehdr, sizeof ehdr);
  lock_release (&filesys_lock);
  /* Read and verify executable header. */
  if (read_result != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      lock_acquire (&filesys_lock);
      bool fail = file_ofs < 0 || file_ofs > file_length (file);
      lock_release (&filesys_lock);
      if (fail)
        goto done;
      lock_acquire (&filesys_lock);
      file_seek (file, file_ofs);
      lock_release (&filesys_lock);

      lock_acquire (&filesys_lock);
      fail = file_read (file, &phdr, sizeof phdr) != sizeof phdr;
      lock_release (&filesys_lock);
      if (fail)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              load_segment (file, file_page, (void *) mem_page, read_bytes, zero_bytes, writable);
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, cmd_line))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  if (!success)
    {
      lock_acquire (&filesys_lock);
      file_close (file);
      lock_release (&filesys_lock);
    }
  else
    {
      struct process_info *info = process_get_info (thread_current ()->tid);
      lock_acquire (&info->info_lock);
      info->exec_file = file;
      lock_release (&info->info_lock);
    }
  return success;
}

/* load() helpers. */

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  lock_acquire (&filesys_lock);
  bool fail = phdr->p_offset > (Elf32_Off) file_length (file);
  lock_release (&filesys_lock);
  if (fail) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  struct process_info *info = process_get_info (thread_current ()->tid);
  lock_acquire (&frame_magic_lock);
  lock_acquire (&info->info_lock);
  ASSERT (mmap_add_info (info->owned_mmap, 256, file, (uintptr_t)upage, ofs, read_bytes, read_bytes + zero_bytes, true, writable)
          != MAP_FAILED);
  lock_release (&info->info_lock);
  lock_release (&frame_magic_lock);

  /*
  char buffer[1024];
  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      size_t page_read_bytes = read_bytes < 1024 ? read_bytes : 1024;
      size_t page_zero_bytes = 1024 - page_read_bytes;

      if (file_read (file, buffer, page_read_bytes) != (int) page_read_bytes)
        {
          return false;
        }
      memset (buffer + page_read_bytes, 0, page_zero_bytes);

      bool pass = memcmp (buffer, upage, 1024) == 0;
      if (!pass)
      {
        printf ("compare fail %p\n", upage);
      }
      ASSERT (pass);
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += 1024;
    }
  */
  return true;

  /*
  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      lock_acquire (&frame_magic_lock);
      struct suppage_info *owner = suppage_create_info (
          &thread_current ()->sp,
          thread_current ()->pagedir,
          upage,
          writable);
      uint8_t *kpage = frame_get (owner);
      lock_release (&frame_magic_lock);
      if (kpage == NULL)
        return false;

      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
  */
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, const char *cmd_line) 
{
  uint8_t *kpage;
  size_t cpy_dst_size;

  lock_acquire (&frame_magic_lock);
  struct suppage_info *owner = suppage_create_info (
      &thread_current ()->sp,
      &process_get_info (thread_current ()->tid)->info_lock,
      thread_current ()->pagedir,
      ((uint8_t *) PHYS_BASE) - PGSIZE,
      true);
  kpage = frame_get (owner);
  lock_release (&frame_magic_lock);

  if (kpage != NULL) 
    {
      *esp = PHYS_BASE;
      /* argument pass */
      // copy cmd
      cpy_dst_size = (strlen (cmd_line) + 1) * sizeof (char);
      *esp = *esp - cpy_dst_size;
      strlcpy (*esp, cmd_line, cpy_dst_size);
      char *cmd_copy = *esp;
      // word align
      *esp = *esp - ((size_t)(*esp)) % 4;
      // tokenize
      *esp = *esp - sizeof (char *);
      memset (*esp, 0, sizeof (char *));
      int argc = 0;
      char *argv[128];
      char *token, *save_ptr;
      for (token = strtok_r (cmd_copy, " ", &save_ptr);
           token != NULL;
           token = strtok_r (NULL, " ", &save_ptr))
        {
          argv[argc] = token;
          argc += 1;
          ASSERT ((size_t)argc < sizeof (argv) / sizeof (char *));
        }
      *esp = *esp - argc * sizeof (char *);
      memcpy (*esp, argv, argc * sizeof (char *));
      // others
      char **argv_ptr = *esp;
      *esp = *esp - sizeof (char **);
      memcpy (*esp, &argv_ptr, sizeof (char **));
      *esp = *esp - sizeof (int);
      memcpy (*esp, &argc, sizeof (int));
      *esp = *esp - sizeof (void *);
      memset (*esp, 0, sizeof (void *));

      // set proc_name for exit message
      char **name = &(process_get_info (thread_current() ->tid)->name);
      *name = malloc (sizeof (char) * (strlen (argv[0]) + 1));
      memcpy (*name, argv[0], sizeof (char) * (strlen (argv[0]) + 1));
    }
  // hex_dump (0, *esp, 128, true);
  return true;
}
