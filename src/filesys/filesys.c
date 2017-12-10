#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/cache.h"
#include "devices/disk.h"
#include "threads/thread.h"
#include "threads/malloc.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format (void);
static struct inode *filesys_open_inode (const char *name);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  filesys_disk = disk_get (0, 1);
  if (filesys_disk == NULL)
    PANIC ("hd0:1 (hdb) not present, file system initialization failed");

  cache_init ();
  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
  cache_finish ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, bool is_dir)
{
  printf ("create: name %s\n", name);
  if (strlen (name) == 0)
  {
    return false;
  }
  ASSERT (strlen (name) == 1 || *(name + strlen(name) - 1) != '/');

  bool is_absolute = name[0] == '/';
  size_t name_offset = is_absolute ? 1 : 0;

  struct dir *current_dir;
  if (thread_current ()->current_dir == NULL || is_absolute)
  {
    is_absolute = true;
    current_dir = dir_open_root ();
  }
  else 
  {
    current_dir = dir_reopen (thread_current ()->current_dir);
  }

  char *name_copy = malloc (strlen (name) + 1);
  strlcpy (name_copy, name + name_offset, strlen (name) - name_offset + 1);
  char *token, *save_ptr, *last_slash;
  last_slash = strrchr (name_copy, '/');
  bool success = true;
  for (token = strtok_r (name_copy, "/", &save_ptr); token != NULL; token = strtok_r (NULL, "/", &save_ptr))
  {
    if (strlen (token) == 0)
    {
      continue;
    }
    if (token > last_slash)
    {
      break;
    }
    printf ("create: token %s\n", token);
    struct inode *current_node;
    if (dir_lookup (current_dir, token, &current_node))
    {
      if (!inode_is_dir (current_node))
      {
        success = false;
        break;
      }
      dir_close (current_dir);
      current_dir = dir_open (current_node);
    }
    else
    {
      disk_sector_t sector;
      success = free_map_allocate (1, &sector)
                && inode_create (sector, 0, true)
                && dir_add (current_dir, token, sector);
      if (!success)
      {
        free_map_release (sector, 1);
        break;
      }
    }
  }
  printf ("create: filename %s\n", token);
  if (token == NULL || strlen (token) == 0)
  {
    success = false;
  }
  if (success)
  {
    disk_sector_t sector;
    success = free_map_allocate (1, &sector) 
              && inode_create (sector, initial_size, is_dir)
              && dir_add (current_dir, token, sector);
    if (!success)
    {
      free_map_release (sector, 1);
    }
  }
  free (name_copy);
  dir_close (current_dir);
  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  struct inode *node = filesys_open_inode (name);
  struct file *result = NULL;
  if (node != NULL)
  {
    result = file_open (node);
  }
  return result;
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  printf ("remove: name %s\n", name);
  if (strlen (name) == 0)
  {
    return false;
  }
  if (strcmp (name, "/") == 0)
  {
    return false;
  }
  ASSERT (strlen (name) == 1 || *(name + strlen(name) - 1) != '/');

  bool is_absolute = name[0] == '/';
  size_t name_offset = is_absolute ? 1 : 0;

  struct dir *current_dir;
  if (thread_current ()->current_dir == NULL || is_absolute)
  {
    is_absolute = true;
    current_dir = dir_open_root ();
  }
  else 
  {
    current_dir = dir_reopen (thread_current ()->current_dir);
  }

  char *name_copy = malloc (strlen (name) + 1);
  strlcpy (name_copy, name + name_offset, strlen (name) - name_offset + 1);
  char *token, *save_ptr, *last_slash;
  last_slash = strrchr (name_copy, '/');
  bool success = true;
  for (token = strtok_r (name_copy, "/", &save_ptr); token != NULL; token = strtok_r (NULL, "/", &save_ptr))
  {
    if (strlen (token) == 0)
    {
      continue;
    }
    if (token > last_slash)
    {
      break;
    }
    printf ("remove: token %s\n", token);
    struct inode *current_node;
    if (dir_lookup (current_dir, token, &current_node))
    {
      if (!inode_is_dir (current_node))
      {
        success = false;
        break;
      }
      dir_close (current_dir);
      current_dir = dir_open (current_node);
    }
    else
    {
      success = false;
      break;
    }
  }

  printf ("remove: filename %s\n", token);
  if (token == NULL || strlen (token) == 0)
  {
    success = false;
  }
  if (success)
  {
    struct inode *current_node = NULL;
    if (dir_lookup (current_dir, token, &current_node))
    {
      if (inode_is_dir (current_node))
      {
        struct dir *temp_dir = dir_open (inode_reopen (current_node));
        if (dir_is_empty (temp_dir))
        {
          dir_remove (current_dir, token);
        }
        else
        {
          success = false;
        }
        dir_close (temp_dir);
      }
      else
      {
        dir_remove (current_dir, token);
      }
      inode_close (current_node);
    }
    else
    {
      success = false;
    }
  }
  free (name_copy);
  dir_close (current_dir);
  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}

static struct inode *
filesys_open_inode (const char *name)
{
  printf ("open_inode: name %s\n", name);
  if (strlen (name) == 0)
  {
    return NULL;
  }
  ASSERT (strlen (name) == 1 || *(name + strlen(name) - 1) != '/');

  bool is_absolute = name[0] == '/';
  size_t name_offset = is_absolute ? 1 : 0;

  struct dir *current_dir;
  if (thread_current ()->current_dir == NULL || is_absolute)
  {
    is_absolute = true;
    current_dir = dir_open_root ();
  }
  else 
  {
    current_dir = dir_reopen (thread_current ()->current_dir);
  }

  char *name_copy = malloc (strlen (name) + 1);
  strlcpy (name_copy, name + name_offset, strlen (name) - name_offset + 1);
  char *token, *save_ptr, *last_slash;
  last_slash = strrchr (name_copy, '/');
  bool success = true;
  for (token = strtok_r (name_copy, "/", &save_ptr); token != NULL; token = strtok_r (NULL, "/", &save_ptr))
  {
    if (strlen (token) == 0)
    {
      continue;
    }
    if (token > last_slash)
    {
      break;
    }
    printf ("open_inode: token %s\n", token);
    struct inode *current_node;
    if (dir_lookup (current_dir, token, &current_node))
    {
      if (!inode_is_dir (current_node))
      {
        success = false;
        break;
      }
      dir_close (current_dir);
      current_dir = dir_open (current_node);
    }
    else
    {
      success = false;
      break;
    }
  }

  printf ("open_inode: filename %s\n", token);
  struct inode *result = NULL;
  if (success)
  {
    if (token == NULL || strlen (token) == 0)
    {
      result = inode_reopen (dir_get_inode (current_dir));
    }
    else
    {
      dir_lookup (current_dir, token, &result);
    }
  }
  free (name_copy);
  dir_close (current_dir);
  return result;
}
