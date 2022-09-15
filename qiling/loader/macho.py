#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os, plistlib, struct

from .loader import QlLoader

from qiling.exception import *
from qiling.const import *

from qiling.os.macos.kernel_api.hook import *
from qiling.os.memory import QlMemoryHeap

from qiling.os.macos.const import *
from qiling.os.macos.task import MachoTask
from qiling.os.macos.kernel_func import FileSystem, map_commpage
from qiling.os.macos.mach_port import MachPort, MachPortManager
from qiling.os.macos.subsystems import MachHostServer, MachTaskServer
from qiling.os.macos.utils import env_dict_to_array, page_align_end
from qiling.os.macos.thread import QlMachoThreadManagement, QlMachoThread

import lief
from lief import MachO
from lief.MachO import LOAD_COMMAND_TYPES as LC


# - execve                     // syscall execve
#   | __mac_execve             // create thread
#     | exec_activate_image    // select imagct type
#       | exec_mach_imgact
#         | load_machfile
#           | parse_machfile   // parse main macho
#           | load_dylinker    // using LC_LOAD_DYLINKER start dyld
#             | parse_machfile // parse dyld, get entry_point
#         | activate_exec_state
#             | thread_setentrypoint // set entry_point。

# See darwin-xnu/bsd/kern/kern_exec.c
# @mach-o: exec_mach_imgact()
# @fat binary: exec_fat_imgact()
# @interpreter: exec_shell_imgact

# Mach-O parse see darwin-xnu/bsd/kern/mach_loader.c
# @load_machfile() -> parse_machfile()


def load_commpage(ql):
    if ql.arch == QL_ARCH.X8664:
        COMM_PAGE_START_ADDRESS = X8664_COMM_PAGE_START_ADDRESS
    else:    
        COMM_PAGE_START_ADDRESS = ARM64_COMM_PAGE_START_ADDRESS

    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_SIGNATURE, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_CPU_CAPABILITIES64, b'\x00\x00\x00\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_UNUSED, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_VERSION, b'\x0d')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_CPU_CAPABILITIES, b'\x00\x00\x00\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_NCPUS, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_UNUSED0, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_CACHE_LINESIZE, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_SCHED_GEN, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_MEMORY_PRESSURE, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_SPIN_COUNT, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_ACTIVE_CPUS, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_PHYSICAL_CPUS, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_LOGICAL_CPUS, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_UNUSED1, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_MEMORY_SIZE, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_CPUFAMILY, b'\xec\x5e\x3b\x57')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_KDEBUG_ENABLE, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_ATM_DIAGNOSTIC_CONFIG, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_UNUSED2, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_TIME_DATA_START, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_NT_TSC_BASE, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_NT_SCALE, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_NT_SHIFT, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_NT_NS_BASE, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_NT_GENERATION, b'\x01')       # someflag seem important 
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_GTOD_GENERATION, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_GTOD_NS_BASE, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_GTOD_SEC_BASE, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_APPROX_TIME, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_APPROX_TIME_SUPPORTED, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_CONT_TIMEBASE, b'\x00')
    ql.mem.write(COMM_PAGE_START_ADDRESS + COMM_PAGE_BOOTTIME_USEC, b'\x00')


# TODO: use "load_result struct" handle return_value

class QlLoaderMACHO(QlLoader):
    ql: Qiling
    # macho x8664 loader 
    def __init__(self, ql, dyld_path=None):
        super(QlLoaderMACHO, self).__init__(ql)
        self.dyld_path      = dyld_path
        self.ql             = ql

        #FIXME: Demigod needs a better way to handle kext file
        if os.path.isdir(self.ql.argv[0]):
            basename = os.path.basename(self.ql.argv[0])
            self.kext_name = os.path.splitext(basename)[0]
            filename = self.ql.argv
            self.ql._argv = [self.ql.argv[0] + "/Contents/MacOS/" + self.kext_name]
            self.ql._path = self.ql.argv[0]
            self.plist = plistlib.load(open(filename[0] + "/Contents/Info.plist", "rb"))
            if "IOKitPersonalities" in self.plist:
                self.IOKit = True
            else:
                self.IOKit = False
        else:
            self.kext_name = None

    def run(self):
        self.profile        = self.ql.profile
        stack_address       = int(self.profile.get("OS64", "stack_address"), 16)
        stack_size          = int(self.profile.get("OS64", "stack_size"), 16)
        vmmap_trap_address  = int(self.profile.get("OS64", "vmmap_trap_address"), 16)
        self.heap_address   = int(self.profile.get("OS64", "heap_address"), 16)
        self.heap_size      = int(self.profile.get("OS64", "heap_size"), 16)        
        self.stack_address  = stack_address
        self.stack_size     = stack_size

        if self.ql.code:
            self.ql.mem.map(self.ql.os.entry_point, self.ql.os.code_ram_size, info="[shellcode_stack]")
            self.ql.os.entry_point  = (self.ql.os.entry_point + 0x200000 - 0x1000)
            
            self.ql.mem.write(self.entry_point, self.ql.code)

            self.ql.arch.regs.arch_sp = self.ql.os.entry_point
            return
        
        self.ql.os.macho_task = MachoTask()
        self.ql.os.macho_fs = FileSystem(self.ql)
        self.ql.os.macho_mach_port = MachPort(2187)
        self.ql.os.macho_port_manager = MachPortManager(self.ql, self.ql.os.macho_mach_port)
        self.ql.os.macho_host_server = MachHostServer(self.ql)
        self.ql.os.macho_task_server = MachTaskServer(self.ql)
        
        self.envs = env_dict_to_array(self.env)
        self.apples = self.ql.os.path.transform_to_relative_path(self.ql.path)
        self.ql.os.heap = QlMemoryHeap(self.ql, self.heap_address, self.heap_address + self.heap_size)

        # TODO: not sure it's right
        map_commpage(self.ql)

        self.ql.os.thread_management = QlMachoThreadManagement(self.ql)
        self.ql.os.macho_thread = QlMachoThread(self.ql)
        self.ql.os.thread_management.cur_thread = self.ql.os.macho_thread
        self.ql.os.macho_vmmap_end = vmmap_trap_address
        self.stack_sp = stack_address + stack_size

        binaries     = lief.MachO.parse(self.ql.path)

        if len(binaries) == 1:
            self.macho_file = binaries[0]

            for segment in self.macho_file.segments:
                if segment.name  == '__PAGEZERO':
                    self.seg_page_zero = segment

        if len(binaries) > 1:
            print("Fat Mach-O: {:d} binaries".format(len(binaries)))
            raise QlErrorMACHOFormat("Fat Mach-O Unsupported for now!")
        
            for binary in binaries:
                print_information(binary)
                print_header(binary)

        self.dyld_file = None
        self.is_driver      = (self.macho_file.header.file_type == 0xb)
        self.loading_file   = self.macho_file
        self.aslr_offset          = int(self.profile.get("LOADER", "aslr_offset"), 16)
        self.dyld_aslr_offset     = int(self.profile.get("LOADER", "dyld_aslr_offset"), 16)
        self.binary_entry   = 0x0
        self.proc_entry     = 0x0
        self.entry_point    = 0x0
        self.argvs          = [self.ql.path]
        self.argc           = 1
        self.string_align   = 8
        self.ptr_align      = 8
        self.needs_dynlinker = False
        self.vm_end_addr    = 0x0
        self.ql.mem.map(self.stack_address, self.stack_size, info="[stack]")
        
        if self.is_driver:
            self.loadDriver(self.stack_address)
            self.ql.hook_code(hook_kernel_api)
        else:
            self.parseMachfile(self.aslr_offset, self.dyld_aslr_offset)

        self.stack_address = (int(self.stack_sp))
        self.ql.arch.regs.arch_sp = self.stack_address # self.stack_sp
        self.init_sp = self.ql.arch.regs.arch_sp
        self.ql.os.macho_task.min_offset = page_align_end(self.vm_end_addr, PAGE_SIZE)

    # https://github.dev/apple/darwin-xnu/blob/2ff845c2e033bd0ff64b5b6aa6063a1f8f65aa32/bsd/kern/mach_loader.c#L747
    def parseMachfile(self, aslr_offset, dyld_aslr_offset, depth=0, isdyld=False):
        mmap_address = int(self.profile.get("OS64", "mmap_address"), 16)
        dlp = None

        if depth > 2:
            raise QlErrorFileLoadFailure("Mach-O file parse depth > 2")

        
        header = self.macho_file.header
        cpu_type = str(header.cpu_type).split(".")[-1]

        if cpu_type != "x86_64":
            raise QlErrorArch(f"{header.cpu_type} unsupported on macOS for now.")

        # if header.file_type == MachO.FILE_TYPES.EXECUTE:
        #     if depth !=1 and depth != 3:
        #         raise QlErrorFileLoadFailure()
            
        #     if header.flags & int(MachO.HEADER_FLAGS.DYLDLINK):
        #         self.needs_dynlinker = True

        if header.file_type == MachO.FILE_TYPES.DYLINKER:
        #     if depth != 2:
        #         raise QlErrorFileLoadFailure()
            isdyld = True
        # else:
        #     raise QlErrorFileLoadFailure()
        
        # For PIE and dyld, slide everything by the ASLR offset.
        if header.flags & int(MachO.HEADER_FLAGS.PIE) or isdyld:
            slide = aslr_offset

        # ensure header + sizeofcmds falls within the file
        # pass

        # Map the load commands into kernel memory
        # pass

        #  *  Scan through the commands, processing each one as necessary.
        #  *  We parse in three passes through the headers:
        #  *  0: determine if TEXT and DATA boundary can be page-aligned, load platform version
        #  *  1: thread state, uuid, code signature
        #  *  2: segments
        #  *  3: dyld, encryption, check entry point

        # Prepare for arm64
        # slide_realign = FALSE

        for pass_num in range(1, 4):
            # pass a lot of checks
            if isdyld:
                ncmds = self.dyld_file.commands
            else:
                ncmds = self.macho_file.commands

            for cmd in ncmds:
                if pass_num == 0:
                    if cmd.command == LC.BUILD_VERSION:
                        pass

                    elif cmd.command in [LC.VERSION_MIN_IPHONEOS, LC.VERSION_MIN_MACOSX, LC.VERSION_MIN_WATCHOS, LC.VERSION_MIN_TVOS]:
                        pass

                elif pass_num == 1:
                    if cmd.command == LC.UNIXTHREAD:
                        self.loadUnixThread(cmd, isdyld, slide)

                    elif cmd.command == LC.MAIN:
                        self.loadMain(cmd, isdyld)

                    elif cmd.command == LC.UUID:
                        pass

                    elif cmd.command == LC.CODE_SIGNATURE:
                        pass

                elif pass_num == 2:
                    if cmd.command == LC.SEGMENT:
                        pass

                    elif cmd.command == LC.SEGMENT_64:
                        self.loadCommandSegment64(pass_num, cmd, isdyld, slide)

                elif pass_num == 3:
                    if cmd.command == LC.LOAD_DYLINKER:
                        dlp = cmd

                    elif cmd.command in [LC.ENCRYPTION_INFO, LC.ENCRYPTION_INFO_64]:
                        pass

        if dlp is not None:
            self.loadDylinker(dlp, dyld_aslr_offset, depth)

        if depth == 0:
            self.mmap_address = mmap_address
            self.stack_sp = self.loadStack()

            if self.needs_dynlinker:
                self.ql.log.info("ProcEntry: {}".format(hex(self.proc_entry)))
                self.entry_point = self.proc_entry + dyld_aslr_offset
                self.ql.log.info("Dyld entry point: {}".format(hex(self.entry_point)))
            else:
                self.entry_point = self.proc_entry + aslr_offset

            self.ql.log.info("Binary Entry Point: 0x{:X}".format(self.binary_entry))
            self.macho_entry = self.binary_entry + self.aslr_offset
            self.load_address = self.macho_entry

        # load_commpage not wroking with ARM64, yet
        if  self.ql.arch == QL_ARCH.X8664:
            load_commpage(self.ql)
        
        depth += 1

        return self.proc_entry



    def loadCommandSegment64(self, pass_num, cmd, isdyld, slide):
        # pass checks
        self.loadSegment(cmd, isdyld, slide)

    def loadSegment(self, scp, isdyld, slide):
        PAGE_SIZE = 0x1000 # minimum

        # if isdyld:
        #     slide = self.dyld_aslr_offset
        # else:
        #     slide = self.aslr_offset

        vaddr_start = scp.virtual_address + slide
        vaddr_end = scp.virtual_address + scp.virtual_size + slide 
        seg_size = scp.virtual_size
        seg_name = scp.name
        seg_data = bytes(scp.content)
        
        print(" | load_segment {:<20} vm[0x{:016x}:0x{:016x}] file[{:>6x}:{:<6x}] prot {:02}/{:02} flags {:02x}"
                .format(seg_name, vaddr_start, vaddr_end,
                        PAGE_SIZE + scp.file_offset, PAGE_SIZE + scp.file_offset + scp.file_size,
                        scp.init_protection, scp.max_protection, scp.flags))

        # pass checks
        if seg_size == 0:
            return 0      # LOAD_SUCCESS
        
        #  * For PIE, extend page zero rather than moving it.  Extending
        #  * page zero keeps early allocations from falling predictably
        #  * between the end of page zero and the beginning of the first
        #  * slid segment.

        #  * This is a "page zero" segment:  it starts at address 0,
        #  * is not mapped from the binary file and is not accessible.
        #  * User-space should never be able to access that memory, so
        #  * make it completely off limits by raising the VM map's
        #  * minimum offset.

        # vm_end = 

        if seg_name == '__PAGEZERO':
            self.ql.mem.map(vaddr_start, PAGE_SIZE, info="[__PAGEZERO]")
            self.ql.mem.write(vaddr_start, b'\x00' * PAGE_SIZE)
            if self.vm_end_addr < vaddr_end:
                self.vm_end_addr = vaddr_end
        else:
            if vaddr_end % PAGE_SIZE != 0:
                vaddr_end = ((vaddr_end // PAGE_SIZE) + 1) * PAGE_SIZE
                seg_size = vaddr_end - vaddr_start
                seg_data = seg_data.ljust(seg_size, b'\0')
        
            self.ql.mem.map(vaddr_start, seg_size,  info="[%s]" % scp.name)
            self.ql.mem.write(vaddr_start, seg_data)
            # print(f"seg_name:{seg_name} [{hex(vaddr_start)}:{hex(vaddr_end)}] size:{hex(seg_size)}")
            # print(self.ql.mem.read(vaddr_start, 0x2000).hex())
            # print(seg_data.hex())
            if self.vm_end_addr < vaddr_end:
                self.vm_end_addr = vaddr_end

        return vaddr_start
    
    # get dyld entry_point from here
    def loadUnixThread(self, cmd, isdyld, slide):
        if not isdyld:
            self.binary_entry = cmd.pc
 
        self.proc_entry = cmd.pc
        self.ql.log.debug("Binary Thread Entry: {}".format(hex(self.proc_entry)))

    def loadMain(self, cmd, isdyld):
        if self.seg_page_zero.virtual_size:
            if not isdyld:
                self.binary_entry = cmd.entrypoint + self.seg_page_zero.virtual_size
            self.proc_entry = cmd.entrypoint + self.seg_page_zero.virtual_size

        self.needs_dynlinker = True
        print(f"self.binary_entry={hex(self.binary_entry)}  self.proc_entry={hex(self.proc_entry)}")
    
    def loadDylinker(self, cmd, slide, depth):
        self.dyld_path = cmd.name

        if not self.dyld_path:
            raise QlErrorMACHOFormat("Error No Dyld path")

        self.dyld_path =  os.path.join(self.ql.rootfs + self.dyld_path)
        dyld_fat = lief.MachO.parse(self.dyld_path)
        if len(dyld_fat) == 1:
            self.dyld_file = dyld_fat
        if len(dyld_fat) > 1:
            print("Fat Mach-O: {:d} binaries".format(len(dyld_fat)))
            for dyld in dyld_fat:
                if str(dyld.header.cpu_type).split(".")[-1] == "x86_64":
                    self.dyld_file = dyld
                    break
            if self.dyld_file is None:
                raise QlErrorMACHOFormat("Unsupported dyld arch type.")

        self.loading_file = self.dyld_file
        self.proc_entry = self.parseMachfile(slide, 0, depth+1, isdyld=True)
        self.loading_file = self.macho_file
        self.needs_dynlinker = True


    def make_string(self, argvs, envs, apple_str):
        result = bytes()
        for item in apple_str:
            b = bytes(item, encoding='utf8') + b'\x00'
            result = b +result
        for item in envs:
            b = bytes(item, encoding='utf8') + b'\x00'
            result = b +result 
        for item in argvs:
            b = bytes(item, encoding='utf8') + b'\x00'
            result = b +result
        return result 

    # TODO: add size check
    def loadStack(self):

        argvs_ptr = []
        envs_ptr = []
        apple_ptr = []

        all_str = self.make_string(self.argvs, self.envs, self.apples)
        self.push_stack_string(all_str)
        ptr = self.stack_sp

        for item in self.argvs[::-1]:
            argvs_ptr.append(ptr)  # need pack and tostring
            self.ql.log.debug('add argvs ptr {}'.format(hex(ptr)))
            ptr += len(item) + 1
        
        for item in self.envs[::-1]:
            envs_ptr.append(ptr)
            self.ql.log.debug('add envs ptr {}'.format(hex(ptr)))
            ptr += len(item) + 1

        for item in self.apples[::-1]:
            apple_ptr.append(ptr)
            self.ql.log.debug('add apple ptr {}'.format(hex(ptr)))
            ptr += len(item) + 1

        ptr = self.stack_sp
        self.push_stack_addr(0x0)
        ptr -= 4
        
        for item in apple_ptr:
            self.push_stack_addr(item)
            ptr -= 4
        
        self.push_stack_addr(0x0)
        ptr -= 4
        
        for item in envs_ptr:
            ptr -= 4
            self.push_stack_addr(item)

        self.push_stack_addr(0x0)
        ptr -= 4
        
        for item in argvs_ptr:
            ptr -= 4
            self.push_stack_addr(item)
            self.ql.log.debug("SP 0x%x, content 0x%x" % (self.stack_sp, item))
        argvs_ptr_ptr = ptr 

        self.push_stack_addr(self.argc)
        ptr -= 4
        self.ql.log.debug("SP 0x%x, content 0x%x" % (self.stack_sp, self.argc))
       
        if self.needs_dynlinker:
            ptr -= 4
            #ql.log.info("Binary Dynamic Entry Point: {:X}".format(self.binary_entry))
            self.push_stack_addr(self.seg_page_zero.virtual_size)
            # self.push_stack_addr(self.binary_entry)

        return self.stack_sp

    def push_stack_string(self, data):
        align = self.string_align
        length = len(data)
        
        if length % align != 0:
            for i in range(align - (length % align)):
                data += b'\x00' 
            length = len(data)
        
        self.stack_sp -= length
        self.ql.mem.write(self.stack_sp, data)
        self.ql.log.debug("SP {} write data len {}".format(hex(self.stack_sp), length))
        
        return self.stack_sp
    
    def push_stack_addr(self, data):
        align = self.ptr_align
        
        if data == 0:
            content = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        else:
            content = struct.pack('<Q', data)

        if len(content) != align:
            self.ql.log.info('stack align error')
            return 
        
        self.stack_sp -= align
        self.ql.mem.write(self.stack_sp, content)

        return self.stack_sp
