#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

#ifdef _USE_MOUNT_LOFS_INSTEAD_OF_MKNOD
#include <sys/mntent.h>
#include <sys/mount.h>
#endif

#include "userchroot.h"
#include "fundamental_devices.h"

static void create_fundamental_device(const char* chroot_path,
                                     const char* device_path) {
  int rc;
  struct stat realdev;
  struct stat chrtdev;

  int name_size = strlen(chroot_path) + strlen(device_path) + 1;
  char* final_path = malloc(name_size);
  if (final_path == NULL) {
    fprintf(stderr,"Failed to allocate memory. Aborting.\n");
    exit(ERR_EXIT_CODE);
  }
  rc = snprintf(final_path, name_size, "%s%s", chroot_path, device_path);
  if (rc < 0) {
    fprintf(stderr,"Failed to produce full path for device. Aborting.\n");
    exit(ERR_EXIT_CODE);
  }
  rc = stat(final_path, &chrtdev);
  if (!rc) {
    fprintf(stderr,"%s already exists. Aborting.\n", final_path);
    exit(ERR_EXIT_CODE);
  }
  rc = stat(device_path, &realdev);
  if (rc) {
    fprintf(stderr,"Failed to stat %s. Aborting.\n", device_path);
    exit(ERR_EXIT_CODE);
  }
  // we need to let the devices be created with the appropriate
  // modes. However, since the file will be group-owned by
  // the user creating the device, we make sure the new mount permissions
  // prevent the user from having any permission granted just by the group.

  // Clear out existing group permission bits
  mode_t device_mode = realdev.st_mode  & (~S_IRWXG);
  // Set new group permission bits to be identical to other's permission bits
  device_mode = device_mode | ((device_mode & S_IRWXO) << 3);
#ifdef _USE_MOUNT_LOFS_INSTEAD_OF_MKNOD
  char  mount_optbuf[MAX_MNTOPT_STR] = { '\0', };

  rc = mkdir(final_path, device_mode);
  if (rc) {
    fprintf(stderr,"Failed to mkdir %s to mount. Aborting.\n", final_path);
  }
  rc = mount(device_path, final_path, MS_DATA|MS_OPTIONSTR,
             MNTTYPE_LOFS, NULL, 0, mount_optbuf, MAX_MNTOPT_STR);
  if (rc) {
    fprintf(stderr,"Failed to lofs mount %s.", final_path);
    exit(ERR_EXIT_CODE);
  }
#else
  rc = mknod(final_path, device_mode, realdev.st_rdev);
  if (rc) {
    fprintf(stderr,"Failed to create the device for %s.", final_path);
    exit(ERR_EXIT_CODE);
  }
#endif // _USE_MOUNT_LOFS_INSTEAD_OF_MKNOD

  free(final_path);
}

static int unlink_fundamental_device(const char* chroot_path,
                                     const char* device_path) {
  int rc;
  int name_size = strlen(chroot_path) + strlen(device_path) + 1;
  char* final_path = malloc(name_size);
  if (final_path == NULL) {
    fprintf(stderr,"Failed to allocate memory.\n");
    return 1;
  }
  rc = snprintf(final_path, name_size, "%s%s", chroot_path, device_path);
  if (rc < 0) {
    fprintf(stderr,"Failed to produce full path for device.\n");
    free(final_path);
    return 1;
  }
#ifdef _USE_MOUNT_LOFS_INSTEAD_OF_MKNOD
  rc = umount(final_path);
  if (rc) {
    fprintf(stderr,"Failed to umount %s.\n", final_path);
    free(final_path);
    return 1;
  }
  rc = rmdir(final_path);
  if (rc) {
    fprintf(stderr,"Failed to rmdir %s.\n", final_path);
    free(final_path);
    return 1;
  }
  rc = rmdir(final_path);
#else
  rc = unlink(final_path);
  if (rc) {
    fprintf(stderr,"Failed to unlink %s.\n", final_path);
    free(final_path);
    return 1;
  }
#endif // _USE_MOUNT_LOFS_INSTEAD_OF_MKNOD
  free(final_path);
  return 0;
}

int create_fundamental_devices(const char* chroot_path) {
  mode_t original_mask = umask(0000);
  create_fundamental_device(chroot_path,"/dev/null");
  create_fundamental_device(chroot_path,"/dev/zero");
  create_fundamental_device(chroot_path,"/dev/random");
  create_fundamental_device(chroot_path,"/dev/urandom");

  // add mount for /dev/poll on Solaris
#if defined(sun) || defined(__sun)
  create_fundamental_device(chroot_path,"/dev/poll");
#endif

  umask(original_mask);
  return 0;
}

int unlink_fundamental_devices(const char* chroot_path) {
  int err = 0;

  err |= unlink_fundamental_device(chroot_path,"/dev/null");
  err |= unlink_fundamental_device(chroot_path,"/dev/zero");
  err |= unlink_fundamental_device(chroot_path,"/dev/random");
  err |= unlink_fundamental_device(chroot_path,"/dev/urandom");

  // unmount /dev/poll on Solaris
#if defined(sun) || defined(__sun)
  err |= unlink_fundamental_device(chroot_path,"/dev/poll");
#endif

  return err ? ERR_EXIT_CODE : 0;
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
