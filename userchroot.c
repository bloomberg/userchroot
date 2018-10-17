#if defined (__linux__) && defined (MOUNT_PROC)
#include <linux/version.h>
#endif

#if defined (__linux__) && defined (MOUNT_PROC)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24))
#define _GNU_SOURCE
#define USERCHROOT_USE_LINUX_CLONE
#include <sched.h>
#include <sys/mount.h>
#include <sys/wait.h>
#endif
#endif

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "userchroot.h"
#include "fundamental_devices.h"


/*
 * The userchroot utility will call chroot for one specific directory
 * and immediately give up the privileges and return to normal user
 * before executing the given command.
 *
 * Before doing that, however, the tool will check if the chroot is
 * happening in one of the configured authorized directories. The idea
 * is to control how the initial chroot image is populated so that we
 * don't chroot to arbitrary chroot locations, but instead we chroot
 * to a whitelisted parent directory.
 *
 * The idea is that any user will be able to do the chroot, but
 * setting up the image will be a process run only by a different
 * user, in order to ensure the image is a "pre-approved" image.
 *
 * The configuration will be in the following format:
 * user:/absolute/path
 *
 * This utility will verify if the requested directory is an immediate
 * child of one of the absolute paths, it will make sure it is not a
 * symlink, and it will also make sure the configured directory has
 * the ownership set to the configured user and also check if the
 * permission doesnt violate a 0022 umask.
 *
 * It will also verify if the config file is owned by root and doesn't
 * violate 0022 umask.
 *
 */

// this two macros serve the purpose of turning a -D clause
// into a constant char**
// As seen in: http://gcc.gnu.org/onlinedocs/cpp/Stringification.html
#define EXPANDED2(X) #X
#define EXPANDED(X) EXPANDED2(X)

#ifndef CONFIGFILE
#error CONFIGFILE should be defined at build time
#endif
static const char CFG[] = EXPANDED(CONFIGFILE);

#ifndef VERSION_STRING
#error VERSION_STRING should be defined at build time
#endif
static const char VERSION[] = EXPANDED(VERSION_STRING);

#define USAGESTR "usage: userchroot path <--install-devices|--uninstall-devices|command ...>\n"
#define USAGE() fprintf(stderr,USAGESTR);exit(ERR_EXIT_CODE);

static void whitelist_char_check(const char* str, int allow_slashes) {
  // whitelist the characters on paths...
  int len = strlen(str);
  int i;
  for (i = 0; i < len; i++) {
    char c = str[i];
    if ((c >= 0x41 && c <= 0x5A) ||  // A-Z
        (c >= 0x61 && c <= 0x7A) ||  // a-z
        (c >= 0x30 && c <= 0x39) ||  // 0-9
        (c == 0x2E ||                // .
         c == 0x5F ||                // _
         c == 0x2B ||                // +
         c == 0x2C ||                // ,
         c == 0x2D)                  // -
        ) {
      continue;
    } else if (allow_slashes && c == '/') {
      continue;
    } else {
      fprintf(stderr,"Path %s contains non-whitelisted characters. Aborting.\n", str);
      exit(ERR_EXIT_CODE);
    }
  }
}

static void check_base_path(const char* path) {
  int rc; // generic return code checking
  // let's make sure the entire path up to the the given path is owned
  // and only writable by root
  int clen = strlen(path)+1;
  char* tosplit = malloc(clen);
  if (tosplit == NULL) {
    fprintf(stderr,"Failed to allocate memory. Aborting.\n");
    exit(ERR_EXIT_CODE);
  }
  struct stat pstat;
  strncpy(tosplit,path,clen);
  int interrupt = 0;
  while (!interrupt) {
    char* slash = strrchr(tosplit, '/');
    if (slash == NULL) {
      // the root directory is exceptional, so we shouldn't really get here.
      fprintf(stderr,"Paths should be always absolute. Aborting.\n");
      exit(ERR_EXIT_CODE);
    }
    if (slash == tosplit) {
      // that means we're on the root already, so this is the last thing to check.
      interrupt = 1;
    } else {
      // split the dir in the last slash.
      slash[0] = 0;
    }

    rc = lstat(tosplit, &pstat);
    if (rc != 0) {
      fprintf(stderr,"Failed to stat directory %s. Aborting.\n", tosplit);
      exit(ERR_EXIT_CODE);
    }
    if (!S_ISDIR(pstat.st_mode)) {
      fprintf(stderr,"%s is not a directory. Aborting.\n", tosplit);
      exit(ERR_EXIT_CODE);
    }
    if (pstat.st_uid != 0) {
      fprintf(stderr,"Directory %s should be owned by root. Aborting.\n", tosplit);
      exit(ERR_EXIT_CODE);
    }
    if (pstat.st_mode & 00022) {
      fprintf(stderr,"Directory %s has non-restrictive permissions. Aborting.\n", tosplit);
      exit(ERR_EXIT_CODE);
    }
  }

}

static void check_config_file(FILE* config) {
  int rc; // generic return code checking
  // all the path up to that configfile should be owned and writable only by root
  check_base_path(CFG);

  // make sure configuration exists and has sane permissions
  struct stat configfilestat;
  rc = lstat(CFG, &configfilestat);
  if (rc != 0) {
    fprintf(stderr,"Failed to stat config file %s. Aborting.\n", CFG);
    exit(ERR_EXIT_CODE);
  }
  if (!S_ISREG(configfilestat.st_mode)) {
    fprintf(stderr,"Configuration file %s is not a regular file.\n", CFG);
  }
  if (configfilestat.st_uid != 0) {
    fprintf(stderr,"Configuration file %s should be owned by root. Aborting.\n", CFG);
    exit(ERR_EXIT_CODE);
  }
  if (configfilestat.st_mode & 00022) {
    fprintf(stderr,"Configuration file %s has non-restrictive permissions. Aborting.\n", CFG);
    exit(ERR_EXIT_CODE);
  }
  dev_t device = configfilestat.st_dev;
  ino_t inode  = configfilestat.st_ino;

  rc = fstat(fileno(config), &configfilestat);
  if (rc != 0) {
    fprintf(stderr,"Failed to fstat. Aborting.\n");
    exit(ERR_EXIT_CODE);
  }
  if (configfilestat.st_dev != device ||
      configfilestat.st_ino != inode) {
    fprintf(stderr,"Config file moved after opening. Aborting.\n");
  }
}


extern char** environ;
static void portable_clearenv() {
#ifdef _HAVE_CLEARENV
  int rc = clearenv();
  if (rc) {
    fprintf(stderr,"Failed to clear environment. Aborting.\n");
    exit(ERR_EXIT_CODE);
  }
#else
  /* This code is copied and slightly modified from:
   *  https://www.securecoding.cert.org/confluence/display/seccode/
   *    ENV03-C.+Sanitize+the+environment+when+invoking+external+programs
   */
  static char *namebuf = NULL;
  static size_t lastlen = 0;
  while (environ != NULL && environ[0] != NULL) {
    size_t len = strcspn(environ[0], "=");
    if (len == 0) {
      fprintf(stderr,"Corrupted environment. Aborting.\n");
      exit(ERR_EXIT_CODE);
    }
    if (len > lastlen) {
      namebuf = realloc(namebuf, len+1);
      if (namebuf == NULL) {
        fprintf(stderr,"Failed to allocate memory. Aborting.\n");
        exit(ERR_EXIT_CODE);
      }
      lastlen = len;
    }
    memcpy(namebuf, environ[0], len);
    namebuf[len] = '\0';
    if (unsetenv(namebuf) == -1) {
      fprintf(stderr,"Failed to clear envionment. Aborting.\n");
      exit(ERR_EXIT_CODE);
    }
  }
#endif
}

struct epilogue_data {
  uid_t target_user;
  char** argv;
  char** envp;
};

void epilogue(struct epilogue_data* d) {

  // Now we need to relinquish our powers back to the calling user.
  int rc = setuid(d->target_user);
  if (rc != 0) {
    fprintf(stderr,"Failed to give up privileges. Aborting.\n");
    exit(ERR_EXIT_CODE);
  }

  // Before executing, even if the system call succeeded, let's make
  // sure we would fail in trying to regain privileges
  if (setuid(0) == 0 || seteuid(0) == 0 ||
      setgid(0) == 0 || setegid(0) == 0) {
    fprintf(stderr,"Failed to give up privileges. Aborting.\n");
    exit(ERR_EXIT_CODE);
  }
  if (getuid() == 0 || geteuid() == 0 ||
      getgid() == 0 || getegid() == 0) {
    fprintf(stderr,"Failed to give up privileges. Aborting.\n");
    exit(ERR_EXIT_CODE);
  }


  rc = chdir("/");
  if (rc != 0) {
    fprintf(stderr,"Failed to chdir to the root directory. Aborting.\n");
    exit(ERR_EXIT_CODE);
  }

  // And finally, execute the desired command.
  // we skip the first two arguments from argv and do a execve.
  d->argv++;d->argv++;
  whitelist_char_check(d->argv[0], 1);
  execve(d->argv[0],d->argv,d->envp);
  // if we are here, it means something went wrong.
  fprintf(stderr,"Failed to exec %s: %s\n", d->argv[0], strerror(errno));
  exit(ERR_EXIT_CODE);
}

#if defined (__linux__) && defined (MOUNT_PROC)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24))

static char child_stack[1048576];
static char proc_guard_stack[1048576];

static int child_fn(void* v) {
  struct epilogue_data* ed = (struct epilogue_data*)v;
  epilogue(ed);
  return 0;
}

static int proc_guard(void *v) {

  // Since we're in the chroot, we don't need to unmount the current
  // proc, simply because there isn't any current proc mounted.
  //
  // Mount the child's view of proc, which includes only processes
  // in its namespace.
  int rc = mkdir("/proc", S_IRWXU);
  if(0 != rc && EEXIST != errno) {
    fprintf(
            stderr,
            "Failed to mkdir /proc. Error: %s\n", strerror(errno)
            );
    return rc;
  }
  else {
    rc = mount(
               "proc",
               "/proc",
               "proc",
               MS_REC|MS_NOSUID|MS_NODEV|MS_NOEXEC,
               NULL
               );
    if(0 != rc) {
      fprintf(
              stderr,
              "Failed to mount proc. Error: %s\n", strerror(errno)
              );
      return rc;
    }
  }

  pid_t child_pid =
    clone(
          child_fn,
          child_stack+sizeof(child_stack),
          SIGCHLD,
          v
          );
  if(-1 == child_pid) {
    fprintf(stderr, "Failed to clone. Error: %s\n", strerror(errno));
  }
  else {
    // init to -1 in case waitpid fails and leaves it untouched.
    int child_status = -1;
    int p = 0;
    while (p = waitpid(-1, &child_status, 0)) {
      if (p == child_pid || p == -1) {
        break;
      }
    }

    // always try and unmount even if the pid failed so we don't leak.
    int umount_rc = umount("/proc");

    if (umount_rc) {
      fprintf(stderr, "Failed to umount. Error: %s\n", strerror(errno));
    }

    // now unlink the directory we made just to be clean.
    rmdir("/proc");
    return WIFSIGNALED(child_status) ? 1 : WEXITSTATUS(child_status);
  }

}
#endif
#endif

int main(int argc, char* argv[], char* envp[]) {
  portable_clearenv();
  int rc; // generic return code checking

  // make sure we're running with root privileges
  if (geteuid() != 0) {
    fprintf(stderr,"Should be run with root privileges. Aborting.\n");
    exit(ERR_EXIT_CODE);
  }
  if (getgid() == 0 ||
      getegid() == 0) {
    fprintf(stderr,"userchroot should not be setgid root. Aborting.\n");
    exit(ERR_EXIT_CODE);
  }
  // make sure we're not actually running as root
  uid_t target_user = getuid();
  if (target_user == 0) {
    fprintf(stderr,"Should not be run as root. Aborting.\n");
    exit(ERR_EXIT_CODE);
  }

  // we open the config file first to avoid time-of-check-time-of-use
  // race conditions. The file is sent to check_config_file to make
  // sure we actually opened the same file that we are stat-ing.
  FILE* config = fopen(CFG, "r");
  if (config == NULL) {
    fprintf(stderr,"Failed to open configuration file %s. Aborting.\n", CFG);
    exit(ERR_EXIT_CODE);
  }
  check_config_file(config);

  // let's get the path
  char* path;
  if (argc < 3) {
    USAGE();
  } else {
    path = argv[1];
  }

  whitelist_char_check(path, 1);
  struct stat dirstat;
  rc = lstat(path, &dirstat);
  if (rc != 0) {
    fprintf(stderr, "Failed to stat %s. Aborting.\n",path);
    USAGE();
    exit(ERR_EXIT_CODE);
  }
  if (!S_ISDIR(dirstat.st_mode)) {
    fprintf(stderr, "%s is not a directory. Aborting.\n",path);
    USAGE();
    exit(ERR_EXIT_CODE);
  }
  if (dirstat.st_mode & 00022) {
    fprintf(stderr,"Directory %s has non-restrictive permissions. Aborting.\n", path);
    exit(ERR_EXIT_CODE);
  }
  uid_t final_dir_owner = dirstat.st_uid;

  // let's strip the last part of the path
  char* base_path = path;
  if (base_path[0] != '/') {
    fprintf(stderr,"Path %s should be absolute. Aborting.\n",path);
    USAGE();
    exit(ERR_EXIT_CODE);
  }
  char* relative_path = strrchr(path, '/');
  if (relative_path == NULL) {
    fprintf(stderr,"Failed to identify last component of the path %s. Aborting.\n",path);
    USAGE();
    exit(ERR_EXIT_CODE);
  } else {
    // we will split this string in two, the base directory and the
    // relative entry.
    relative_path[0] = 0;
    relative_path++;
  }
  if (base_path[0] == 0) {
    fprintf(stderr,"This is not a possible target for userchroot. Aborting.\n");
    USAGE();
    exit(ERR_EXIT_CODE);
  }
  if (relative_path[0] == 0) {
    fprintf(stderr,"Trailing slashes are not allowed in the path. Aborting.\n");
    USAGE();
    exit(ERR_EXIT_CODE);
  }
  if (relative_path[0] == '.' &&
      (relative_path[1] == 0 ||
       (relative_path[1] == '.' &&
        relative_path[2] == 0))) {
    fprintf(stderr,". and .. are not allowed as part of the chroot path. Aborting.\n");
    exit(ERR_EXIT_CODE);
  }
  whitelist_char_check(base_path, 1);
  whitelist_char_check(relative_path, 0);

  struct stat statbase_path;
  rc = lstat(base_path, &statbase_path);
  if (rc != 0) {
    fprintf(stderr,"Failed to stat %s. Aborting.\n",base_path);
    USAGE();
    exit(ERR_EXIT_CODE);
  }
  if (!S_ISDIR(statbase_path.st_mode)) {
    fprintf(stderr, "%s is not a directory. Aborting.\n",path);
    USAGE();
    exit(ERR_EXIT_CODE);
  }
  if (statbase_path.st_mode & 00022) {
    fprintf(stderr,"Directory %s has non-restrictive permissions. Aborting.\n", base_path);
    exit(ERR_EXIT_CODE);
  }
  if (statbase_path.st_uid != final_dir_owner) {
    fprintf(stderr,"%s and %s/%s must have the same owner. Aborting.\n", base_path, base_path, relative_path);
    exit(ERR_EXIT_CODE);
  }
  struct passwd *pwent;
  pwent = getpwuid(statbase_path.st_uid);
  if (pwent == NULL) {
    fprintf(stderr,"Failed to getpwuid. Aborting.\n");
    exit(ERR_EXIT_CODE);
  }

  // that path should be below a place owned and only writable by root
  check_base_path(base_path);

  // Ok, at this point we have the base path and the user name.
  // Now we need to open the configuration file and see if we have a
  // match.
  int linelen = strlen(base_path) + strlen(pwent->pw_name) + 3;
  char* line = malloc(linelen);
  if (line == NULL) {
    fprintf(stderr,"Failed to allocate memory. Aborting.\n");
    exit(ERR_EXIT_CODE);
  }
  rc = snprintf(line, linelen, "%s:%s\n", pwent->pw_name, base_path);
  if (rc <= 0) {
    fprintf(stderr,"Failed to assemble configuration line test. Aborting.\n");
    exit(ERR_EXIT_CODE);
  }

  // Now we look for this exact string in the configuration file.
  // we're going to use fgets, which will return the next line or up
  // to the buffer limit, that means that if a line is bigger then the
  // buffer, it will go another pass.
  //
  // we're going to set the buffer to the same as our desired line,
  // since we don't care of anything bigger than that.
  char *rline = malloc(linelen);
  if (rline == NULL) {
    fprintf(stderr,"Failed to allocate memory. Aborting.\n");
    exit(ERR_EXIT_CODE);
  }

  int found = 0;
  while (feof(config) == 0 &&
         fgets(rline, linelen, config) != NULL) {
    int ignore = 0;
    while (strchr(rline, '\n') == NULL) {
      // we want to ignore lines bigger than linelen...
      // so we will continue to consume until we find a line break.
      ignore = 1;
      if (feof(config) || fgets(rline, linelen, config) == NULL) {
        break;
      }
    }

    if (!ignore && strncmp(line, rline, linelen) == 0) {
      found = 1;
      break;
    }
  }
  if (fclose(config)) {
    fprintf(stderr,"Failed to close configuration file. Aborting.\n");
    exit(ERR_EXIT_CODE);
  }
  if (!found) {
    fprintf(stderr,"Permission Denied when reading config file. Aborting.\n");
    exit(ERR_EXIT_CODE);
  }

  // If we got to this point it means we're clear to go.
  int path_len = strlen(base_path)+strlen(relative_path)+2;
  char* final_path = malloc(path_len);
  if (final_path == NULL) {
    fprintf(stderr,"Failed to allocate memory. Aborting.\n");
    exit(ERR_EXIT_CODE);
  }
  rc = snprintf(final_path, path_len, "%s/%s", base_path, relative_path);
  if (rc <= 0) {
    fprintf(stderr,"Failed to assemble path. Aborting.\n");
    exit(ERR_EXIT_CODE);
  }

  // lame but efficient argument parsing
  if (argc >= 3 &&
      argv[2] != NULL &&
      argv[2][0] == '-') {

    // this mode can only be run by the owner of the chroot image.
    if (target_user != statbase_path.st_uid) {
      fprintf(stderr,"install or uninstall devices can only be called by the owner of the chroot. Aborting.\n");
      exit(ERR_EXIT_CODE);
    }

    if (strncmp("--install-devices",argv[2],17) == 0) {
      rc = create_fundamental_devices(final_path);
      exit(rc);
    } else if (strncmp("--uninstall-devices",argv[2],19) == 0) {
      rc = unlink_fundamental_devices(final_path);
      exit(rc);
    } else {
      USAGE();
      exit(ERR_EXIT_CODE);
    }
  } else {

    // move to the chroot path before doing the chroot.
    rc = chdir(final_path);
    if (rc != 0) {
      fprintf(stderr,"Failed to chdir to the chroot directory. Aborting.\n");
      exit(ERR_EXIT_CODE);
    }
    // Now the actual chroot call.
    rc = chroot(final_path);
    if (rc != 0) {
      fprintf(stderr,"Failed to chroot. Aborting.\n");
      exit(ERR_EXIT_CODE);
    }

    struct epilogue_data* ed =
      (struct epilogue_data*)malloc(sizeof(struct epilogue_data));
    if(NULL == ed) {
      fprintf(stderr,"Failed to allocate epilogue_data. Aborting.\n");
      exit(ERR_EXIT_CODE);
    }
    ed->target_user = target_user;
    ed->argv = argv;
    ed->envp = envp;
#if defined USERCHROOT_USE_LINUX_CLONE

    // Our goal here is to mount /proc without exposing other
    // processes to the invoked command. Basically, /proc should only
    // give the invoked command a view of itself and all the processes
    // it forked.  However, we have to have two levels of indirection
    // via clone so that we can detect the completion of the execve
    // and cleanup after ourselves.
    pid_t child_pid =
      clone(
            proc_guard,
            proc_guard_stack + sizeof(proc_guard_stack),
            CLONE_NEWNS | CLONE_NEWPID | SIGCHLD,
            ed);
    if(-1 == child_pid) {
      fprintf(stderr, "Failed to clone. Error: %s\n", strerror(errno));
      return child_pid;
    }
    else {
      int child_status = -1;
      int p = 0;
      while (p = waitpid(child_pid, &child_status, 0)) {
        if (p == child_pid || p == -1) {
          break;
        }
      }

      return WIFSIGNALED(child_status) ? 1 : WEXITSTATUS(child_status);
    }

#else
    epilogue(ed);
    // Should never get here as epilogue does execve but it's possible
    // that the compiler wouldn't notice so we need to return from int
    // main here.
    return 0;
#endif
  }
}


// ----------------------------------------------------------------------------
// Copyright 2015 Bloomberg Finance L.P.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------- END-OF-FILE ----------------------------------
