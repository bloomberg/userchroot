PREFIX?=/bldroot
CONFIGFILE?=/etc/userchroot.conf

GIT_DESCRIBE:=$(shell git describe --tags --long 2>/dev/null)
VERSION_TEMPLATE:='$$Id: userchroot GIT_DESCRIBE $$'
VERSION_STRING:=$(subst GIT_DESCRIBE,$(GIT_DESCRIBE),$(VERSION_TEMPLATE))

VPATH?=.
HAVE_CLEARENV:=$(shell CC=$(CC) $(VPATH)/test-clearenv.sh && \
	         echo "-D_HAVE_CLEARENV")

CFLAGS+= -DCONFIGFILE=$(CONFIGFILE) \
	 -DPREFIX=$(PREFIX) \
	 -DVERSION_STRING=$(VERSION_STRING) \
	 $(HAVE_CLEARENV) \
	 -DMOUNT_PROC

SOURCES:=userchroot.c fundamental_devices.c
OBJECTS:=$(subst .c,.o,$(SOURCES))

userchroot: $(OBJECTS)
	$(CC) $^ -o $@

clean:
	rm -f *.o userchroot


# ----------------------------------------------------------------------------
# Copyright 2015 Bloomberg Finance L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ----------------------------- END-OF-FILE ----------------------------------
