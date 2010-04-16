
/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <limits.h>

#include "vold.h"
#include "ums.h"

#define DEBUG_UMS 0
#define SYSFS_CLASS_SCSI_DEVICE_PATH  "/sys/class/scsi_device"
#define BLOCK_EVENT_PARAMS_SIZE 5
#define USBSCSI_EVENT_PARAMS_SIZE 4

static int usb_bootstrap();
static int usb_bootstrap_scsidevice(char *sysfs_path);
static int usb_bootstrap_block(char *devpath);
static int usb_bootstrap_usbblk(char *devpath);
static int usb_bootstrap_usbblk_partition(char *devpath);
static void free_uevent_params(char **uevent_param, int count);

static boolean host_connected = false;
static boolean ums_enabled = false;

int ums_bootstrap(void)
{
    int rc;
    rc = usb_bootstrap();
    return rc;
}

void ums_enabled_set(boolean enabled)
{
    ums_enabled = enabled;
    send_msg(enabled ? VOLD_EVT_UMS_ENABLED : VOLD_EVT_UMS_DISABLED);
}

boolean ums_enabled_get()
{
    return ums_enabled;
}

void ums_hostconnected_set(boolean connected)
{
#if DEBUG_UMS
    LOG_VOL("ums_hostconnected_set(%d):", connected);
#endif
    host_connected = connected;

    if (!connected)
        ums_enabled_set(false);
    send_msg(connected ? VOLD_EVT_UMS_CONNECTED : VOLD_EVT_UMS_DISCONNECTED);
}

int ums_enable(char *dev_fspath, char *lun_syspath)
{
    LOG_VOL("ums_enable(%s, %s):", dev_fspath, lun_syspath);

    int fd;
    char filename[255];

    sprintf(filename, "/sys/%s/file", lun_syspath);
    if ((fd = open(filename, O_WRONLY)) < 0) {
        LOGE("Unable to open '%s' (%s)", filename, strerror(errno));
        return -errno;
    }

    if (write(fd, dev_fspath, strlen(dev_fspath)) < 0) {
        LOGE("Unable to write to ums lunfile (%s)", strerror(errno));
        close(fd);
        return -errno;
    }
    
    close(fd);
    return 0;
}

int ums_disable(char *lun_syspath)
{
#if DEBUG_UMS
    LOG_VOL("ums_disable(%s):", lun_syspath);
#endif

    int fd;
    char filename[255];

    sprintf(filename, "/sys/%s/file", lun_syspath);
    if ((fd = open(filename, O_WRONLY)) < 0) {
        LOGE("Unable to open '%s' (%s)", filename, strerror(errno));
        return -errno;
    }

    char ch = 0;

    if (write(fd, &ch, 1) < 0) {
        LOGE("Unable to write to ums lunfile (%s)", strerror(errno));
        close(fd);
        return -errno;
    }
    
    close(fd);
    return 0;
}

boolean ums_hostconnected_get(void)
{
    return host_connected;
}

int ums_send_status(void)
{
    int rc;

#if DEBUG_UMS
    LOG_VOL("ums_send_status():");
#endif

    rc = send_msg(ums_enabled_get() ? VOLD_EVT_UMS_ENABLED :
                                      VOLD_EVT_UMS_DISABLED);
    if (rc < 0)
        return rc;

    rc = send_msg(ums_hostconnected_get() ? VOLD_EVT_UMS_CONNECTED :
                                            VOLD_EVT_UMS_DISCONNECTED);

    return rc;
}
/*
 * Scan for USB scsi_device uevent and simulate them
 */
static int usb_bootstrap()
{
    DIR *d;
    struct dirent *de;

    if (!(d = opendir(SYSFS_CLASS_SCSI_DEVICE_PATH))) {
        LOG_ERROR("Unable to open '%s' (%m)", SYSFS_CLASS_SCSI_DEVICE_PATH);
        return -errno;
    }

    while ((de = readdir(d))) {
        char tmp[PATH_MAX];

        if (de->d_name[0] == '.')
            continue;

        sprintf(tmp, "%s/%s", SYSFS_CLASS_SCSI_DEVICE_PATH, de->d_name);
        if (usb_bootstrap_scsidevice(tmp))
            LOG_ERROR("Error bootstrapping controller '%s' (%m)", tmp);
    }
    closedir(d);

    return 0;
}

static int usb_bootstrap_scsidevice(char *sysfs_path)
{
    char saved_cwd[PATH_MAX];
    char new_cwd[PATH_MAX];
    char *uevent_params[USBSCSI_EVENT_PARAMS_SIZE];
    char *p;
    char filename[PATH_MAX];
    char tmp[PATH_MAX];
    char devpath[PATH_MAX];
    ssize_t sz;

#if DEBUG_UMS
    LOG_VOL("bootstrap_card(%s):", sysfs_path);
#endif

    /*
     * sysfs_path is based on /sys/class, but we want the actual device class
     */
    if (!getcwd(saved_cwd, sizeof(saved_cwd))) {
        LOGE("Error getting working dir path");
        return -errno;
    }

    if (chdir(sysfs_path) < 0) {
        LOGE("Unable to chdir to %s (%m)", sysfs_path);
        return -errno;
    }

    if (!getcwd(new_cwd, sizeof(new_cwd))) {
        LOGE("Buffer too small for device path");
        return -errno;
    }

    if (chdir(saved_cwd) < 0) {
        LOGE("Unable to restore working dir");
        return -errno;
    }

    p = &new_cwd[4]; // Skip over '/sys'

    /* Truncate /scsi_device and scsi device id  */
    truncate_sysfs_path(p, 2, devpath, sizeof(devpath));

    /*
     * Collect parameters so we can simulate a UEVENT
     */
    sprintf(tmp, "DEVPATH=%s", devpath);
    uevent_params[0] = (char *) strdup(tmp);

    sprintf(tmp, "DEVTYPE=scsi_device");
    uevent_params[1] = (char *) strdup(tmp);

    sprintf(tmp, "MODALIAS=scsi:t-0x00");
    uevent_params[2] = (char *) strdup(tmp);

    uevent_params[3] = (char *) NULL;

    if (simulate_uevent("scsi", devpath, "add", uevent_params) < 0) {
        LOGE("Error simulating uevent (%m)");
        free_uevent_params(uevent_params, USBSCSI_EVENT_PARAMS_SIZE);
        return -errno;
    }
    free_uevent_params(uevent_params, USBSCSI_EVENT_PARAMS_SIZE);

    /*
     *  Check for block drivers
     */
    sprintf(tmp, "%s/block", devpath);
    sprintf(filename, "/sys%s/block", devpath);
    if (!access(filename, F_OK)) {
        if (usb_bootstrap_block(tmp)) {
            LOGE("Error bootstrapping block @ %s", tmp);
        }
    }

    return 0;
}

static int usb_bootstrap_block(char *devpath)
{
    DIR *d;
    struct dirent *de;
    char filename[PATH_MAX];
#if DEBUG_UMS
    LOG_VOL("usb_bootstrap_block(%s):", devpath);
#endif
    sprintf(filename, "/sys%s", devpath);

    if (!(d = opendir(filename))) {
        LOG_ERROR("Unable to open '%s' (%m)", filename);
        return -errno;
    }

    /* read uevent path of the disk*/
    while ((de = readdir(d))) {
        char tmp[PATH_MAX];

        if (de->d_name[0] == '.')
            continue;
        sprintf(tmp, "%s/%s", devpath, de->d_name);
        if (usb_bootstrap_usbblk(tmp))
            LOGE("Error bootstraping usbblk @ %s", tmp);
    }
    closedir(d);
    return 0;
}

static int usb_bootstrap_usbblk(char *devpath)
{
    char *usbblk_devname;
    int part_no;
    int rc;

#if DEBUG_UMS
    LOG_VOL("usb_bootstrap_usbblk(%s):", devpath);
#endif

    if ((rc = usb_bootstrap_usbblk_partition(devpath))) {
        LOGE("Error bootstrapping usbblk partition '%s'", devpath);
        return rc;
    }

    for (usbblk_devname = &devpath[strlen(devpath)];
         *usbblk_devname != '/'; usbblk_devname--);
    usbblk_devname++;

    /* Read the uevent path for portions on the disk */
    for (part_no = 0; part_no < 4; part_no++) {
        char part_file[PATH_MAX];
        sprintf(part_file, "/sys%s/%s%d", devpath, usbblk_devname, part_no);
        if (!access(part_file, F_OK)) {
            char part_devpath[PATH_MAX];

            sprintf(part_devpath, "%s/%s%d", devpath, usbblk_devname, part_no);
            if (usb_bootstrap_usbblk_partition(part_devpath))
                LOGE("Error bootstrapping usbblk partition '%s'", part_devpath);
        }
    }

    return 0;
}

static int usb_bootstrap_usbblk_partition(char *devpath)
{
    char filename[PATH_MAX];
    char *uevent_buffer;
    ssize_t sz;
    char *uevent_params[BLOCK_EVENT_PARAMS_SIZE];
    char tmp[PATH_MAX];
    FILE *fp;
    char line[PATH_MAX];

#if DEBUG_BOOTSTRAP
    LOG_VOL("usb_bootstrap_usbblk_partition(%s):", devpath);
#endif
    sprintf(tmp, "DEVPATH=%s", devpath);
    uevent_params[0] = strdup(tmp);

    sprintf(filename, "/sys%s/uevent", devpath);
    if (!(fp = fopen(filename, "r"))) {
        LOGE("Unable to open '%s' (%m)", filename);
        return -errno;
    }

    while (fgets(line, sizeof(line), fp)) {
        line[strlen(line)-1] = 0;
        if (!strncmp(line, "MAJOR=",6))
            uevent_params[1] = strdup(line);
        else if (!strncmp(line, "MINOR=",6))
            uevent_params[2] = strdup(line);
        else if (!strncmp(line, "DEVTYPE=", 8))
            uevent_params[3] = strdup(line);
    }
    fclose(fp);
    uevent_params[4] = '\0';

    if (!uevent_params[1] || !uevent_params[2] || !uevent_params[3]) {
        LOGE("usbblk uevent missing required params");
        free_uevent_params(uevent_params, BLOCK_EVENT_PARAMS_SIZE);
        return -1;
    }

    if (simulate_uevent("block", devpath, "add", uevent_params) < 0) {
        LOGE("Error simulating uevent (%m)");
        free_uevent_params(uevent_params, BLOCK_EVENT_PARAMS_SIZE);
        return -errno;
    }

    free_uevent_params(uevent_params, BLOCK_EVENT_PARAMS_SIZE);
    return 0;
}

void free_uevent_params(char **uevent_param, int count)
{
    int i;
    char *p;
    for (i=0; i< count; i++) {
        p = uevent_param[i];
        if (p != NULL)
            free(p);
    }
}
