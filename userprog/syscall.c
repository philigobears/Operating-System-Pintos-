#include "devices/shutdown.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>

static void syscall_handler (struct intr_frame *);
static struct lock filesys_lock;

void
syscall_init (void)
{
  lock_init (&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void *
get_kernel_space_pointer (const void *page)
{
  return pagedir_get_page (thread_current ()->pagedir, page);
}

static bool
valid_pointer (const void *va)
{
  return is_user_vaddr(va) && get_kernel_space_pointer (va) != NULL;
}

static void
die (struct intr_frame *f)
{
  thread_current ()->wait_status->exit_code = -1;
  thread_current ()->wait_status->success = true;
  f->eax = -1;
  printf ("%s: exit(%d)\n", thread_name (), -1);
  thread_exit ();
}

static void
syscall_handle_halt (uint32_t *args UNUSED, struct intr_frame *f UNUSED)
{
  shutdown_power_off ();
}

static void
syscall_handle_exit (uint32_t *args, struct intr_frame *f)
{
  uint32_t status = args[1];
  thread_current ()->wait_status->exit_code = status;
  thread_current ()->wait_status->success = true;
  f->eax = status;
  printf ("%s: exit(%d)\n", thread_name (), status);
  thread_exit ();
}

static void
syscall_handle_exec (uint32_t *args, struct intr_frame *f)
{
  char *file_name = (char *) args[1];
  if (!valid_pointer (file_name))
    die (f);

  lock_acquire (&filesys_lock);
  tid_t child = process_execute (file_name);
  lock_release (&filesys_lock);
  if (child == TID_ERROR)
    f->eax = -1;
  else
    f->eax = child;
}

static void
syscall_handle_wait (uint32_t *args, struct intr_frame *f)
{
  f->eax = process_wait (args[1]);
}

static void
syscall_handle_create (uint32_t *args UNUSED, struct intr_frame *f UNUSED)
{
  ;
}

static void
syscall_handle_remove (uint32_t *args UNUSED, struct intr_frame *f UNUSED)
{
  ;
}

static void
syscall_handle_open (uint32_t *args UNUSED, struct intr_frame *f UNUSED)
{
  ;
}

static void
syscall_handle_filesize (uint32_t *args UNUSED, struct intr_frame *f UNUSED)
{
  ;
}

static void
syscall_handle_read (uint32_t *args UNUSED, struct intr_frame *f UNUSED)
{
  ;
}

static void
syscall_handle_write (uint32_t *args, struct intr_frame *f)
{
  lock_acquire (&filesys_lock);
  putbuf (get_kernel_space_pointer ((const void *) args[2]), args[3]);
  lock_release (&filesys_lock);
  f->eax = args[3];
}

static void
syscall_handle_seek (uint32_t *args UNUSED, struct intr_frame *f UNUSED)
{
  ;
}

static void
syscall_handle_tell (uint32_t *args UNUSED, struct intr_frame *f UNUSED)
{
  ;
}

static void
syscall_handle_close (uint32_t *args UNUSED, struct intr_frame *f UNUSED)
{
  ;
}

static void
syscall_handle_null (uint32_t *args, struct intr_frame *f)
{
  f->eax = args[1] + 1;
}

static void
syscall_handler (struct intr_frame *f)
{
  uint32_t *args = ((uint32_t *) f->esp);
  if (!valid_pointer (args))
    die (f);

  switch (args[0])
    {
    case SYS_HALT:
      syscall_handle_halt (args, f);
      break;
    case SYS_EXIT:
      syscall_handle_exit (args, f);
      break;
    case SYS_EXEC:
      syscall_handle_exec (args, f);
      break;
    case SYS_WAIT:
      syscall_handle_wait (args, f);
      break;
    case SYS_CREATE:
      syscall_handle_create (args, f);
      break;
    case SYS_REMOVE:
      syscall_handle_remove (args, f);
      break;
    case SYS_OPEN:
      syscall_handle_open (args, f);
      break;
    case SYS_FILESIZE:
      syscall_handle_filesize (args, f);
      break;
    case SYS_READ:
      syscall_handle_read (args, f);
      break;
    case SYS_WRITE:
      syscall_handle_write (args, f);
      break;
    case SYS_SEEK:
      syscall_handle_seek (args, f);
      break;
    case SYS_TELL:
      syscall_handle_tell (args, f);
      break;
    case SYS_CLOSE:
      syscall_handle_close (args, f);
      break;
    case SYS_NULL:
      syscall_handle_null (args, f);
      break;
    default:
      die (f);
      break;
    }
}
