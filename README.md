# userchroot - Allow regular users to invoke chroot'd processes

This tool allows a system administrator to create pre-defined chroot
locations and allow regular users to run processes on those
environments.

We use it at Bloomberg to allow non-privileged users to run builds on
a chroot'd environment on Linux x86_64, Solaris sparc, and AIX
powerpc.

## Fundamental Devices

There are some devices that so many processes expect to exist, that
when provisioning ephemeral chroot locations as a non-privileged user
you may need to make available. Those devices are:

 * /dev/zero
 * /dev/random
 * /dev/urandom
 * /dev/null
 * /dev/poll (Solaris only)
 * /dev/shm (Linux only)

The userchroot command offers a "--install-devices" and
"--uninstall-devices" that will allow a non-privileged user to create
and destroy those devices.

This allow us to run the entire build infrastructure as a
non-privileged user.

# How to build

There is very little build-time customization, so we provide a simple
Makefile that will use the implicit rules in order to build the
executable.

```
make
```

# Compile-time settings

## PREFIX

This variables (defaults to /usr/local) controls the default base path
to the CONFIGFILE.

## CONFIGFILE

This variable (defaults to /etc/userchroot.conf) will set the
path for the config file. 

This tool will check for the config file in two places:
* `$(PREFIX)/etc/userchroot.conf`
* `/etc/userchroot.conf`

The tool will verify that the file as well
as the entire path leading to the file is root owned, has limited
permissions and is not a symbolic link.

## VERSIONSTRING

This variable (defaults to an ident string created with `git describe
--tags`). This will be stored in a static string in the executable for
identifying the version with `ident`.

# Conditional compilations

## _HAVE_CLEARENV

We include a compat implementation of clearenv for architectures where
that system call is not available. This is evaluated by the makefile
by using the test-clearenv.sh script.

## _USE_MOUNT_LOFS_INSTEAD_OF_MKNOD

When running inside a Solaris zone, you will not be allowed to use
mknod. As an alternative, the tool will allow you to use a lofs mount
to the system location for the fundamental devices.

## __linux__

On Linux we also create /dev/shm and mount it as a tmpfs, since the
GNU Libc will not only expect that location to exist, but it will also
check that it is actually a tmpfs location. Without this, named pipes
do not work on Linux.

## __sun

On Solaris, we mount the kernel poll device at /dev/poll. This is a
Solaris-only replacement for `select` and `poll`.

# How to install

The executable needs to be setuid root, but it must *not* be setgid
root. In fact, it will validate that you haven't given too much
permissions to it.

# How to use

The config file must have the a path to a pre-approved chroot image
and the name of the user that owns that image. In the format:

```
user:/path/to/userchroot/base
```

Then any user will be able to run

```
userchroot /path/to/userchroot/base/myimage some command
```

As well as:

```
userchroot /path/to/userchroot/base/myimage --install-devices
```

or

```
userchroot /path/to/userchroot/base/myimage --uninstall-devices
```

As long as:

 * The entire path leading to /path/to/userchroot is owned by root and
   doesn't have open permissions.
 * The directory /path/to/userchroot/base is owned by the configured
   user and doesn't have open permissions.
 * The directory /path/to/userchroot/base/myimage is owned by the
   configured user and doesn't have open permissions.

This will result on ```some command``` being invoked after performing
the chroot to the location and dropping the privileges back to the
calling user.

# Copyright statement


```
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
```
