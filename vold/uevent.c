
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

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "vold.h"
#include "uevent.h"
#include "mmc.h"
#include "blkdev.h"
#include "volmgr.h"
#include "media.h"

#define DEBUG_UEVENT 0

#define UEVENT_PARAMS_MAX 32

#define SPEED_MAX 6
#define VERSION_MAX 6
#define MANUFACTURER_MAX 16
#define USB1_VERSION 1
#define USB_FULL_SPEED 12
enum uevent_action { action_add, action_remove, action_change };

struct uevent {
    char *path;
    enum uevent_action action;
    char *subsystem;
    char *param[UEVENT_PARAMS_MAX];
    unsigned int seqnum;
};

struct uevent_dispatch {
    char *subsystem;
    int (* dispatch) (struct uevent *);
};

typedef struct uevent_list {
    struct uevent *event;
    struct uevent_list *next;
} uevent_list_t;

struct uevent_list *uevent_list_root = NULL;


static void dump_uevent(struct uevent *);
static int dispatch_uevent(struct uevent *event);
static void free_uevent(struct uevent *event);
static char *get_uevent_param(struct uevent *event, char *param_name);

static int handle_powersupply_event(struct uevent *event);
static int handle_switch_event(struct uevent *);
static int handle_battery_event(struct uevent *);
static int handle_mmc_event(struct uevent *);
static int handle_block_event(struct uevent *);
static int handle_bdi_event(struct uevent *);
static int handle_usb_event(struct uevent *);
static void _cb_blkdev_ok_to_destroy(blkdev_t *dev);
static int add_usb_uevent_to_list(struct uevent *event);
static int read_usb_device_property(char *event_path, char *prop, char *dev_prop, int len);

static struct uevent_dispatch dispatch_table[] = {
    { "switch", handle_switch_event }, 
    { "battery", handle_battery_event }, 
    { "mmc", handle_mmc_event },
    { "block", handle_block_event },
    { "bdi", handle_bdi_event },
    { "power_supply", handle_powersupply_event },
    { "usb", handle_usb_event },
    { "scsi", handle_usb_event },
    { NULL, NULL }
};

static boolean low_batt = false;
static boolean door_open = true;

int process_uevent_message(int socket)
{
    char buffer[64 * 1024]; // Thank god we're not in the kernel :)
    int count;
    char *s = buffer;
    char *end;
    struct uevent *event;
    int param_idx = 0;
    int i;
    int first = 1;
    int rc = 0;

    if ((count = recv(socket, buffer, sizeof(buffer), 0)) < 0) {
        LOGE("Error receiving uevent (%s)", strerror(errno));
        return -errno;
    }

    if (!(event = malloc(sizeof(struct uevent)))) {
        LOGE("Error allocating memory (%s)", strerror(errno));
        return -errno;
    }

    memset(event, 0, sizeof(struct uevent));

    end = s + count;
    while (s < end) {
        if (first) {
            char *p;
            for (p = s; *p != '@'; p++);
            p++;
            event->path = strdup(p);
            first = 0;
        } else {
            if (!strncmp(s, "ACTION=", strlen("ACTION="))) {
                char *a = s + strlen("ACTION=");
               
                if (!strcmp(a, "add"))
                    event->action = action_add;
                else if (!strcmp(a, "change"))
                    event->action = action_change;
                else if (!strcmp(a, "remove"))
                    event->action = action_remove;
            } else if (!strncmp(s, "SEQNUM=", strlen("SEQNUM=")))
                event->seqnum = atoi(s + strlen("SEQNUM="));
            else if (!strncmp(s, "SUBSYSTEM=", strlen("SUBSYSTEM=")))
                event->subsystem = strdup(s + strlen("SUBSYSTEM="));
            else
                event->param[param_idx++] = strdup(s);
        }
        s+= strlen(s) + 1;
    }

    rc = dispatch_uevent(event);
    
    free_uevent(event);
    return rc;
}

int simulate_uevent(char *subsys, char *path, char *action, char **params)
{
    struct uevent *event;
    char tmp[255];
    int i, rc;

    if (!(event = malloc(sizeof(struct uevent)))) {
        LOGE("Error allocating memory (%s)", strerror(errno));
        return -errno;
    }

    memset(event, 0, sizeof(struct uevent));

    event->subsystem = strdup(subsys);

    if (!strcmp(action, "add"))
        event->action = action_add;
    else if (!strcmp(action, "change"))
        event->action = action_change;
    else if (!strcmp(action, "remove"))
        event->action = action_remove;
    else {
        LOGE("Invalid action '%s'", action);
        return -1;
    }

    event->path = strdup(path);

    for (i = 0; i < UEVENT_PARAMS_MAX; i++) {
        if (!params[i])
            break;
        event->param[i] = strdup(params[i]);
    }
    if ((default_usb_devpath != NULL &&
        !strncmp(path, default_usb_devpath, strlen(default_usb_devpath))) ||
        (default_usb2_devpath != NULL &&
        !strncmp(path, default_usb2_devpath, strlen(default_usb2_devpath)))) {
        rc = add_usb_uevent_to_list(event);
    } else {
        rc = dispatch_uevent(event);
        free_uevent(event);
    }
    return rc;
}
/*
 * Store USB devices uevents and process them after vold bootstrap.
 */
int add_usb_uevent_to_list(struct uevent *event)
{
    int rc = 0;
    struct uevent_list *node;

    if (!(node = malloc(sizeof(struct uevent_list)))) {
        free_uevent(event);
        return -errno;
    }
    node->event = event;
    node->next = NULL;

    if (!uevent_list_root)
        uevent_list_root = node;
    else {
        struct uevent_list *list_scan;
        list_scan = uevent_list_root;
        while(list_scan->next)
            list_scan = list_scan->next;

        list_scan->next = node;
    }

    return rc;
}
/*
 * Dispatch uevent to the event handlers and delete event node from the list.
 */
void process_uevent_list()
{
    struct uevent_list *list_scan, *node;
    if (!uevent_list_root) {
        return;
    }
    list_scan = uevent_list_root;
    while(list_scan) {
        node = list_scan;
        dispatch_uevent(node->event);
        list_scan = list_scan->next;
        free_uevent(node->event);
        free(node);
    }
    return;
}

static int dispatch_uevent(struct uevent *event)
{
    int i;

#if DEBUG_UEVENT
    dump_uevent(event);
#endif
    for (i = 0; dispatch_table[i].subsystem != NULL; i++) {
        if (!strcmp(dispatch_table[i].subsystem, event->subsystem))
            return dispatch_table[i].dispatch(event);
    }

#if DEBUG_UEVENT
    LOG_VOL("No uevent handlers registered for '%s' subsystem", event->subsystem);
#endif
    return 0;
}

static void dump_uevent(struct uevent *event)
{
    int i;

    LOG_VOL("[UEVENT] Sq: %u S: %s A: %d P: %s",
              event->seqnum, event->subsystem, event->action, event->path);
    for (i = 0; i < UEVENT_PARAMS_MAX; i++) {
        if (!event->param[i])
            break;
        LOG_VOL("%s", event->param[i]);
    }
}

static void free_uevent(struct uevent *event)
{
    int i;
    free(event->path);
    free(event->subsystem);
    for (i = 0; i < UEVENT_PARAMS_MAX; i++) {
        if (!event->param[i])
            break;
        free(event->param[i]);
    }
    free(event);
}

static char *get_uevent_param(struct uevent *event, char *param_name)
{
    int i;

    for (i = 0; i < UEVENT_PARAMS_MAX; i++) {
        if (!event->param[i])
            break;
        if (!strncmp(event->param[i], param_name, strlen(param_name)))
            return &event->param[i][strlen(param_name) + 1];
    }

    LOGE("get_uevent_param(): No parameter '%s' found", param_name);
    return NULL;
}

/*
 * ---------------
 * Uevent Handlers
 * ---------------
 */

static int handle_powersupply_event(struct uevent *event)
{
    char *ps_type = get_uevent_param(event, "POWER_SUPPLY_TYPE");

    if (!strcasecmp(ps_type, "battery")) {
        char *ps_cap = get_uevent_param(event, "POWER_SUPPLY_CAPACITY");
        int capacity = atoi(ps_cap);
  
        if (capacity < 5)
            low_batt = true;
        else
            low_batt = false;
        volmgr_safe_mode(low_batt || door_open);
    }
    return 0;
}

static int handle_switch_event(struct uevent *event)
{
    char *name = get_uevent_param(event, "SWITCH_NAME");
    char *state = get_uevent_param(event, "SWITCH_STATE");

    /* As a part of compostiion switch, mass storage driver
     * sends offline event and de-register its event from switch
     * Hence there is possibility that before handling the switch
     * event, the mass storage sysfs mass storage entries might
     * have removed. So, if name or state is NULL, consider it as
     * offline and send false
     * */
    if(name == NULL || state == NULL) {
        ums_hostconnected_set(false);
        volmgr_enable_ums(false);
	return 0;
    }
    if (!strcmp(name, "usb_mass_storage")) {
        if (!strcmp(state, "online")) {
            ums_hostconnected_set(true);
        } else {
            ums_hostconnected_set(false);
            volmgr_enable_ums(false);
        }
    } else if (!strcmp(name, "sd-door")) {
        if (!strcmp(state, "open"))
            door_open = true;
        else
            door_open = false;
        volmgr_safe_mode(low_batt || door_open);
    }
    return 0;
}

static int handle_battery_event(struct uevent *event)
{
    return 0;
}

static int handle_block_event(struct uevent *event)
{
    char mediapath[255];
    media_t *media;
    int n;
    int maj, min;
    blkdev_t *blkdev;

    /*
     * Look for backing media for this block device
     */
    if (!strncmp(get_uevent_param(event, "DEVPATH"),
                 "/devices/virtual/",
                 strlen("/devices/virtual/"))) {
        n = 0;
    } else if (!strcmp(get_uevent_param(event, "DEVTYPE"), "disk"))
        n = 2;
    else if (!strcmp(get_uevent_param(event, "DEVTYPE"), "partition"))
        n = 3;
    else {
        LOGE("Bad blockdev type '%s'", get_uevent_param(event, "DEVTYPE"));
        return -EINVAL;
    }

    truncate_sysfs_path(event->path, n, mediapath, sizeof(mediapath));

    if (!(media = media_lookup_by_path(mediapath, false))) {
#if DEBUG_UEVENT
        LOG_VOL("No backend media found @ device path '%s'", mediapath);
#endif
        return 0;
    }

    maj = atoi(get_uevent_param(event, "MAJOR"));
    min = atoi(get_uevent_param(event, "MINOR"));

    if (event->action == action_add) {
        blkdev_t *disk;

        /*
         * If there isn't a disk already its because *we*
         * are the disk
         */
        if (media->media_type == media_mmc)
            disk = blkdev_lookup_by_devno(maj, ALIGN_MMC_MINOR(min));
        else if (media->media_type == media_usb) {
            char path[PATH_MAX];
            /*
             * Truncate partition name from the device path.
             * partition names are created using their
             * major and minor number
             */
            if (n == 3)
                truncate_sysfs_path(event->path, 1, path, sizeof(path));
            else
                strlcpy(path, event->path, sizeof(path));

            disk = blkdev_lookup_by_path(path);
        } else
            disk = blkdev_lookup_by_devno(maj, 0);

        if (!(blkdev = blkdev_create(disk,
                                     event->path,
                                     maj,
                                     min,
                                     media,
                                     get_uevent_param(event, "DEVTYPE")))) {
            LOGE("Unable to allocate new blkdev (%s)", strerror(errno));
            return -1;
        }

        blkdev_refresh(blkdev);

        /*
         * Add the blkdev to media
         */
        int rc;
        if ((rc = media_add_blkdev(media, blkdev)) < 0) {
            LOGE("Unable to add blkdev to card (%d)", rc);
            return rc;
        }

        LOGI("New blkdev %d.%d on media %s, media path %s, Dpp %d",
                blkdev->major, blkdev->minor, media->name, mediapath,
                blkdev_get_num_pending_partitions(blkdev->disk));

        if (blkdev_get_num_pending_partitions(blkdev->disk) == 0) {
            if ((rc = volmgr_consider_disk(blkdev->disk)) < 0) {
                if (rc == -EBUSY) {
                    LOGI("Volmgr not ready to handle device");
                } else {
                    LOGE("Volmgr failed to handle device (%d)", rc);
                    return rc;
                }
            }
        }
    } else if (event->action == action_remove) {
        if (!(blkdev = blkdev_lookup_by_devno(maj, min)))
            return 0;

        LOGI("Destroying blkdev %d.%d @ %s on media %s", blkdev->major,
                blkdev->minor, blkdev->devpath, media->name);
        volmgr_notify_eject(blkdev, _cb_blkdev_ok_to_destroy);

    } else if (event->action == action_change) {
        if (!(blkdev = blkdev_lookup_by_devno(maj, min)))
            return 0;

        LOGI("Modified blkdev %d.%d @ %s on media %s", blkdev->major,
                blkdev->minor, blkdev->devpath, media->name);
        
        blkdev_refresh(blkdev);
    } else  {
#if DEBUG_UEVENT
        LOG_VOL("No handler implemented for action %d", event->action);
#endif
    }
    return 0;
}

static void _cb_blkdev_ok_to_destroy(blkdev_t *dev)
{
    media_t *media = media_lookup_by_dev(dev);
    if (media)
        media_remove_blkdev(media, dev);
    blkdev_destroy(dev);
}

static int handle_bdi_event(struct uevent *event)
{
    return 0;
}

static int handle_mmc_event(struct uevent *event)
{
    if (event->action == action_add) {
        media_t *media;
        char serial[80];
        char *type;

        /*
         * Pull card information from sysfs
         */
        type = get_uevent_param(event, "MMC_TYPE");
        if (strcmp(type, "SD") && strcmp(type, "MMC"))
            return 0;
        
        read_sysfs_var(serial, sizeof(serial), event->path, "serial");
        if (!(media = media_create(event->path,
                                   get_uevent_param(event, "MMC_NAME"),
                                   serial,
                                   media_mmc))) {
            LOGE("Unable to allocate new media (%s)", strerror(errno));
            return -1;
        }
        LOGI("New MMC card '%s' (serial %u) added @ %s", media->name,
                  media->serial, media->devpath);
    } else if (event->action == action_remove) {
        media_t *media;

        if (!(media = media_lookup_by_path(event->path, false))) {
            LOGE("Unable to lookup media '%s'", event->path);
            return -1;
        }

        LOGI("MMC card '%s' (serial %u) @ %s removed", media->name, 
                  media->serial, media->devpath);
        media_destroy(media);
    } else {
#if DEBUG_UEVENT
        LOG_VOL("No handler implemented for action %d", event->action);
#endif
    }

    return 0;
}

static int handle_usb_event(struct uevent *event)
{
    if (event->action == action_add) {
        media_t *media;
        char serial[80];
        char *type;
        char speed[SPEED_MAX], manf[MANUFACTURER_MAX];
        char version[VERSION_MAX];
        int len, speed_len;
        char *endptr;
        long val;

        type = get_uevent_param(event, "DEVTYPE");
        LOG_VOL("Device type: %s Event path: %s", type, event->path);
        /*
         * Read version and speed properties of the device that are connected
         * to FSUSB port. If version is 2 and speed is 12 Mbs then device is
         * not running at top speed. Send a notification to Mount Services.
         */
        if (!strncmp(type, "usb_device", strlen(type)) &&
            !strncmp(event->path, default_usb2_devpath,
                             strlen(default_usb2_devpath))) {

            len = read_usb_device_property(event->path, "/version",
                                                   version, sizeof(version));

            speed_len = read_usb_device_property(event->path, "/speed",
                                                       speed, sizeof(speed));
            if (speed_len > 0  && len > 0) {
                errno = 0;
                val = strtol(version, &endptr, 10);
                if ((errno == 0) && (endptr != version) && (val > USB1_VERSION)) {
                    val = strtol(speed, &endptr, 10);
                    if ((errno == 0) && (endptr != speed) && (val == USB_FULL_SPEED)) {
                        len = read_usb_device_property(event->path,
                                         "/manufacturer", manf, sizeof(manf));
                        if (len)
                            volmgr_send_speed_mismatch(manf);
                   }
                }
            }
        }
        if (strcmp(type, "scsi_device"))
            return 0;

        if (!(media = media_create(event->path,
                                   "USB",
                                   NULL,
                                   media_usb))) {
            LOGE("Unable to allocate new media (%m)");
            return -1;
        }
        LOG_VOL("New usb host '%s' added @ %s", media->name, media->devpath);
    } else if (event->action == action_remove) {
        media_t *media;

       if (!(media = media_lookup_by_path(event->path, false))) {
            LOGE("Unable to lookup media '%s'", event->path);
            return -1;
        }

        LOG_VOL("usb host '%s' @ %s removed", media->name, media->devpath);
        media_destroy(media);
    } else {
        LOGE("No handler implemented for action %d", event->action);
    }
    return 0;
}

static int read_usb_device_property(char *event_path, char *prop, char *dev_prop, int len)
{
    char path[PATH_MAX];
    int fd, rc;

    memset(dev_prop, 0, len);
    strlcpy(path, "/sys", sizeof(path));
    strlcat(path, event_path, sizeof(path));
    strlcat(path, prop, sizeof(path));
    if ((fd = open(path, O_RDONLY)) < 0) {
        LOGE("Unable to open device '%s' (%s)", path, strerror(errno));
        rc = 0;
    } else if ((rc = read(fd, dev_prop, len)) < 0)  {
        LOGE("Unable to read device property (%d, %s)",
                      rc, strerror(errno));
        rc = 0;
    }
    return rc;
}
