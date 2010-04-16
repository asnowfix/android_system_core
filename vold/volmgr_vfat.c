
/*
 * Copyright (C) 2008 The Android Open Source Project
 * Copyright (c) 2009-2010, Code Aurora Forum. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <fcntl.h>

#include <sys/mount.h>
#include <cutils/properties.h>

#include "vold.h"
#include "volmgr.h"
#include "volmgr_vfat.h"
#include "logwrapper.h"

#define VFAT_DEBUG 0
#define VFAT_TYPE_LEN 9
#define VFAT_VOL_NAME_LEN 12

static char FSCK_MSDOS_PATH[] = "/system/bin/fsck_msdos";

int vfat_identify(blkdev_t *dev, char **volume_name)
{
    int rc = -1, fd;
    char *devpath, vfat_type [VFAT_TYPE_LEN], vfat_volume_name[VFAT_VOL_NAME_LEN];
    int i = 0;

#if VFAT_DEBUG
    LOG_VOL("vfat_identify(%d:%d):", dev->major, dev->minor);
#endif

    devpath = blkdev_get_devpath(dev);

    if ((fd = open(devpath, O_RDWR)) < 0) {
        LOGE("Unable to open device '%s' (%s)", devpath,
             strerror(errno));
        free(devpath);
        return -errno;
    }

    /* For FAT16:
     * The fat type is stored at byte 55 and is 8 bytes long
     * The volume label/name is stored at byte 44 and is 11 bytes long
     */

    if (lseek(fd, 54, SEEK_SET) < 0) {
        LOGE("Unable to lseek to get superblock (%s)", strerror(errno));
        rc =  -errno;
        goto out;
    }
    /* Read FAT type */
    if (read(fd, &vfat_type, sizeof(vfat_type)) != sizeof(vfat_type)) {
        LOGE("Unable to read superblock (%s)", strerror(errno));
        rc =  -errno;
        goto out;
    }

    vfat_type[VFAT_TYPE_LEN - 1] = '\0';
    /* Check FAT type for FAT16 */
    if (!strncmp(vfat_type,"FAT16",5)) {
        if (lseek(fd, 43, SEEK_SET) < 0) {
            LOGE("Unable to lseek to get superblock (%s)", strerror(errno));
            rc =  -errno;
            goto out;
        }
        /* Read volume name */
        if (read(fd, vfat_volume_name, sizeof(vfat_volume_name)) != sizeof(vfat_volume_name)) {
            LOGE("Unable to read superblock (%s)", strerror(errno));
            rc =  -errno;
            goto out;
        }

        vfat_volume_name[VFAT_VOL_NAME_LEN - 1] = '\0';
        rc = 0;
        goto trim;
    }

    /* For FAT32:
     * The fat type is stored at byte 83 and is 8 bytes long
     * The volume label/name is stored at byte 72 and is 11 bytes long
     */
    if (lseek(fd, 82, SEEK_SET) < 0) {
        LOGE("Unable to lseek to get superblock (%s)", strerror(errno));
        rc =  -errno;
        goto out;
    }
    /* Read File type info */
    if (read(fd, &vfat_type, sizeof(vfat_type)) != sizeof(vfat_type)) {
        LOGE("Unable to read superblock (%s)", strerror(errno));
        rc =  -errno;
        goto out;
    }

    vfat_type[VFAT_TYPE_LEN - 1] = '\0';
    /* Check file type for FAT32 */
    if (!strncmp(vfat_type,"FAT32",5)) {
        if (lseek(fd, 71, SEEK_SET) < 0) {
            LOGE("Unable to lseek to get superblock (%s)", strerror(errno));
            rc =  -errno;
            goto out;
        }

     if (read(fd, vfat_volume_name, sizeof(vfat_volume_name)) != sizeof(vfat_volume_name)) {
         LOGE("Unable to read superblock (%s)", strerror(errno));
         rc =  -errno;
         goto out;
        }

     vfat_volume_name[VFAT_VOL_NAME_LEN -1] = '\0';
     rc = 0;
    }

trim:
    /*
     * Remove blank space at the end of the string, volume name
     */
    for (i = (strlen(vfat_volume_name)-1); i >= 0; i--) {
        if (vfat_volume_name[i] == ' ') {
            vfat_volume_name[i] = '\0';
        } else {
            break;
        }
    }
    if (strlen(vfat_volume_name))
        *volume_name = strdup(vfat_volume_name);
    else
        *volume_name = NULL;
    LOGE("Volume_name= %s", vfat_volume_name);

out:
#if VFAT_DEBUG
    LOG_VOL("vfat_identify(%s): rc = %d", devpath, rc);
#endif
    free(devpath);
    close(fd);
    return rc;
}

int vfat_check(blkdev_t *dev)
{
    int rc;
    boolean rw = true;

#if VFAT_DEBUG
    LOG_VOL("vfat_check(%d:%d):", dev->major, dev->minor);
#endif

    if (access(FSCK_MSDOS_PATH, X_OK)) {
        LOGE("vfat_check(%d:%d): %s not found (skipping checks)",
             dev->major, dev->minor, FSCK_MSDOS_PATH);
        return 0;
    }

    int pass = 1;
    do {
        char *args[5];
        args[0] = FSCK_MSDOS_PATH;
        args[1] = "-p";
        args[2] = "-f";
        args[3] = blkdev_get_devpath(dev);
        args[4] = NULL;
        rc = logwrap(4, args, 1);
        free(args[3]);

        if (rc == 0) {
            LOG_VOL("Filesystem check completed OK");
            return 0;
        } else if (rc == 2) {
            LOG_VOL("Filesystem check failed (not a FAT filesystem)");
            return -ENODATA;
        } else if (rc == 4) {
            if (pass++ <= 3) {
                LOG_VOL("Filesystem modified - rechecking (pass %d)",
                        pass);
                continue;
            } else {
                LOG_VOL("Failing check after too many rechecks");
                return -EIO;
            }
        } else if (rc == -11) {
            LOG_VOL("Filesystem check crashed");
            return -EIO;
        } else {
            LOG_VOL("Filesystem check failed (unknown exit code %d)", rc);
            return -EIO;
        }
    } while (0);
    return 0;
}

int vfat_mount(blkdev_t *dev, volume_t *vol, boolean safe_mode)
{
    int flags, rc;
    char *devpath;

    devpath = blkdev_get_devpath(dev);

#if VFAT_DEBUG
    LOG_VOL("vfat_mount(%d:%d, %s, %d):", dev->major, dev->minor, vol->mount_point, safe_mode);
#endif

    flags = MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_DIRSYNC;

    if (vol->state == volstate_mounted) {
        LOG_VOL("Remounting %d:%d on %s, safe mode %d", dev->major,
                dev->minor, vol->mount_point, safe_mode);
        flags |= MS_REMOUNT;
    }

    /*
     * Note: This is a temporary hack. If the sampling profiler is enabled,
     * we make the SD card world-writable so any process can write snapshots.
     *
     * TODO: Remove this code once we have a drop box in system_server.
     */
    char value[PROPERTY_VALUE_MAX];
    property_get("persist.sampling_profiler", value, "");
    if (value[0] == '1') {
        LOGW("The SD card is world-writable because the"
            " 'persist.sampling_profiler' system property is set to '1'.");
        rc = mount(devpath, vol->mount_point, "vfat", flags,
                "utf8,uid=1000,gid=1015,fmask=000,dmask=000,shortname=mixed");
    } else {
        /*
         * The mount masks restrict access so that:
         * 1. The 'system' user cannot access the SD card at all -
         *    (protects system_server from grabbing file references)
         * 2. Group users can RWX
         * 3. Others can only RX
         */
        rc = mount(devpath, vol->mount_point, "vfat", flags,
                "utf8,uid=1000,gid=1015,fmask=702,dmask=702,shortname=mixed");
    }

    if (rc && errno == EROFS) {
        LOGE("vfat_mount(%d:%d, %s): Read only filesystem - retrying mount RO",
             dev->major, dev->minor, vol->mount_point);
        flags |= MS_RDONLY;
        rc = mount(devpath, vol->mount_point, "vfat", flags,
                   "utf8,uid=1000,gid=1015,fmask=702,dmask=702,shortname=mixed");
    }

    if (rc == 0) {
        char *lost_path;
        asprintf(&lost_path, "%s/LOST.DIR", vol->mount_point);
        if (access(lost_path, F_OK)) {
            /*
             * Create a LOST.DIR in the root so we have somewhere to put
             * lost cluster chains (fsck_msdos doesn't currently do this)
             */
            if (mkdir(lost_path, 0755)) {
                LOGE("Unable to create LOST.DIR (%s)", strerror(errno));
            }
        }
        free(lost_path);
    }

#if VFAT_DEBUG
    LOG_VOL("vfat_mount(%s, %d:%d): mount rc = %d", dev->major,k dev->minor,
            vol->mount_point, rc);
#endif
    free (devpath);
    return rc;
}
