#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os

from struct import *

from qiling.exception import *
from qiling.const import *
from .const import *
from .mach_port import *

def map_commpage(ql):
    if ql.arch.type == QL_ARCH.X8664:
        addr_base = X8664_COMM_PAGE_START_ADDRESS
        addr_size = 0x100000
    elif ql.arch.type == QL_ARCH.ARM64:
        addr_base = ARM64_COMM_PAGE_START_ADDRESS
        addr_size = 0x1000
    ql.mem.map(addr_base, addr_size, info="[commpage]")
    time_lock_slide = 0x68
    ql.mem.write(addr_base+time_lock_slide, ql.pack32(0x1))

def shared_region_map_and_slide_setup(ql, fd, files_count,
                                      files, mappings_count, mappings,
                                      sr_file_mappings, shared_region):
    ql.log.warning('shared_region_map_and_slide_setup is not implemented!')
    mappings_next = 0

    for i in range(files_count):
        srfmp = SrFileMappings(ql)
        srfmp.fd = files[i].sf_fd
        srfmp.mappings_count = files[i].sf_mappings_count
        srfmp.mappings = mappings[mappings_next:mappings_next + srfmp.mappings_count]
        mappings_next += srfmp.mappings_count
        if mappings_next > mappings_count:
            raise QlErrorSyscallError("Mappings for files are out of bound.")
        srfmp.slide = files[i].slide
        sr_file_mappings.append(srfmp)

    for i in range(files_count):
        if sr_file_mappings[i].mappings_count == 0:
            continue
    # sr_file_mappings.append(SrFileMappings())

def vm_shared_region_enter(ql):
    ql.shared_region = SharedRegion(ql)
    ql.macos_shared_region = True
    ql.macos_shared_region_port = MachPort(9999)        # random port name

def vm_shared_region_create(ql):
    pass

def vm_shared_region_get(ql, task):
    return task.shared_region

def vm_shared_region_trim_and_get(ql, task):
    return vm_shared_region_get(task)

def vm_shared_region_map_file(ql, shared_region, files_count, sr_file_mappings):
    ql.log.warning('vm_shared_region_map_file is not implemented!')


def shared_region_map_and_slide(ql, fd, files_count, files, mappings_count, mappings):
    print(fd, files, mappings_count)
    sr_file_mappings = []
    shared_region = None

    # Turn files, mappings into sr_file_mappings and other setup.
    error = shared_region_map_and_slide_setup(ql, fd, files_count,
            files, mappings_count, mappings,
	        sr_file_mappings, shared_region)

    # map the file(s) into that shared region's submap
    kr = vm_shared_region_map_file(ql, shared_region, files_count, sr_file_mappings)

class SrFileMappings:

    def __init__(self, ql):
        self.fd = None
        self.mappings_count = None
        self.mappings = None
        self.slide = None
        self.fp = None
        self.vp = None
        self.file_size = None
        self.file_control = None

# reference to osfmk/vm/vm_shared_region.h
class SharedRegion:
    def __init__(self, ql):
        self.ref_count = 0
        self.slide = 0

# reference to osfmk/mach/shared_memory_server.h
class SharedFileMappingNp:
    def __init__(self, ql):
        self.size = 32
        self.ql = ql
    
    def read_mapping(self, addr):
        content = self.ql.mem.read(addr, self.size)
        self.sfm_address = unpack("<Q", self.ql.mem.read(addr, 8))[0]
        self.sfm_size = unpack("<Q", self.ql.mem.read(addr + 8, 8))[0]
        self.sfm_file_offset = unpack("<Q", self.ql.mem.read(addr + 16, 8))[0]
        self.sfm_max_prot = unpack("<L", self.ql.mem.read(addr + 24, 4))[0]
        self.sfm_init_prot = unpack("<L", self.ql.mem.read(addr + 28, 4))[0]

        self.ql.log.debug("[ShareFileMapping]: addr: 0x{:X}, size: 0x{:X}, fileOffset:0x{:X}, maxProt: {}, initProt: {}".format(
            self.sfm_address, self.sfm_size, self.sfm_file_offset, self.sfm_max_prot, self.sfm_init_prot
            ))


# reference to osfmk/mach/shared_memory_server.h
class SharedFileMappingSlideNp:

    def __init__(self, ql) -> None:
        self.size = 40
        self.ql = ql

    def translate(self, sfm_address, sfm_size, sfm_file_offset, sfm_max_prot, sfm_init_prot, slide_size, slide_start):
        self.sms_address = sfm_address
        self.sms_size = sfm_size
        self.sms_file_offset = sfm_file_offset
        self.sms_max_prot = sfm_max_prot
        self.sms_init_prot = sfm_init_prot
        self.sms_slide_size = slide_size    # user_addr_t = u_int32_t    len = 4
        self.sms_slide_start = slide_start  # user_addr_t = u_int32_t    len = 4

        self.ql.log.debug("[ShareFileMappingSlide]: addr: 0x{:X}, size: 0x{:X}, fileOffset:0x{:X}, maxProt: {}, initProt: {}, slideSize:{}, slideStart:{}".format(
            self.sms_address, self.sms_size, self.sms_file_offset, self.sms_max_prot, self.sms_init_prot, self.sms_slide_size, self.sms_slide_start, self.sms_slide_size, self.sms_slide_start
            ))



class VmSharedRegion:
    def __init__(self, ql):
        self.ql = ql
        ql.mem.map(SHARED_REGION_BASE_X86_64, SHARED_REGION_SIZE_X86_64, info="[shared_region]")

# reference to osfmk/mach/shared_memory_server.h
class SharedFileNp:

    def __init__(self, ql) -> None:
        self.ql = ql
        self.sf_fd = None
        self.sf_mappings_count = None
        self.sf_slide = None


# reference to bsd/sys/proc_info.h
class ProcRegionWithPathInfo():

    def __init__(self, ql):
        self.ql = ql
        pass
    
    def set_path(self, path):
        self.vnode_info_path_vip_path = path

    def write_info(self, addr):
        addr += 248
        self.ql.mem.write(addr, self.vnode_info_path_vip_path)


# virtual FS
# Only have some basic func now 
# tobe completed
class FileSystem():

    def __init__(self, ql):
        self.ql = ql
        self.base_path = ql.rootfs

    def get_common_attr(self, path, cmn_flags):
        real_path = self.vm_to_real_path(path)
        if not os.path.exists(real_path):
            return None
        attr = b''
        file_stat = os.stat(real_path)
        filename = ""

        if cmn_flags & ATTR_CMN_NAME != 0:
            filename = path.split("/")[-1]
            filename_len = len(filename) + 1        # add \0
            attr += pack("<L", filename_len)
            self.ql.log.debug("FileName :{}, len:{}".format(filename, filename_len))

        if cmn_flags & ATTR_CMN_DEVID != 0:
            attr += pack("<L", file_stat.st_dev)
            self.ql.log.debug("DevID: {}".format(file_stat.st_dev))

        if cmn_flags & ATTR_CMN_OBJTYPE != 0:
            if os.path.isdir(path):
                attr += pack("<L", VDIR)
                self.ql.log.debug("ObjType: DIR")
            elif os.path.islink(path):
                attr += pack("<L", VLINK)
                self.ql.log.debug("ObjType: LINK")
            else:
                attr += pack("<L", VREG)
                self.ql.log.debug("ObjType: REG")
            
        if cmn_flags & ATTR_CMN_OBJID != 0:
            attr += pack("<Q", file_stat.st_ino)
            self.ql.log.debug("VnodeID :{}".format(file_stat.st_ino))

        # at last, add name 
        if cmn_flags & ATTR_CMN_NAME != 0:
            name_offset = len(attr) + 4
            attr = pack("<L", name_offset) + attr
            attr += filename.encode("utf8")
            attr += b'\x00'
        
        self.ql.log.debug("Attr : {}".format(attr))
    
        return attr

    def vm_to_real_path(self, vm_path):
        if not vm_path:
            return None
        if vm_path[0] == '/':
            # abs path 
            return os.path.join(self.base_path, vm_path[1:])
        else:
            # rel path
            return os.path.join(self.base_path, vm_path)

    def open(self, path, open_flags, open_mode):

        real_path = self.vm_to_real_path(path)
        
        if real_path:
            return os.open(real_path, open_flags, open_mode)
        else:
            return None

    def isexists(self, path):
        real_path = self.vm_to_real_path(path)
        return os.path.exists(real_path)
