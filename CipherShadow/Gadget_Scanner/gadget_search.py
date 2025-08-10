from capstone import *
import angr
from angr.exploration_techniques import ExplorationTechnique
import sys
import difflib
import json
import claripy
from angr.sim_procedure import SimProcedure

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.Detail = True

CF_INST = ['jmp', 'je', 'jne', 'js', 'jns', 'jg', 'jge', 'jl', 'jle', 'ja', 'jae', 'jb', 'jbe', 'call', 'ret']

GPR = [
    'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'
]

def disasm(x, base): return [print("%-10s%-25s%-5s%-14s%s" % (hex(i.address), i.bytes.hex(), len(i.bytes.hex()) / 2.0, i.mnemonic, i.op_str)) for i in md.disasm(x, base)]

def get_disasm_text(x, base):
    disasm_list = []
    exist_illegal = False
    code_len = len(x)
    disasm_addr = base
    for i in md.disasm(x, base):
        disasm_list.append("%-10s%-25s%-5s%-14s%s\n" % (hex(i.address), i.bytes.hex(), len(i.bytes.hex()) / 2.0, i.mnemonic, i.op_str))
        disasm_addr = i.address + len(i.bytes)
    if disasm_addr - base != code_len:
        print(f"[-] Illegal disasm: disasm_addr is: {hex(disasm_addr)}, base is: {hex(base)}, len is: {disasm_addr - base}, code_len is: {code_len}")
        exist_illegal = True
        # print(''.join(disasm_list))
    return (disasm_list, exist_illegal)

def print_hex(x): return print("0x"+x.hex())


def print_func(x): return [print("%s:" % i + hex(j[0]) + " " + hex(j[1]))
                           for i, j in x.items()]

def dump_data_flow(d_state, imark_state = None):
    for i, state in enumerate(d_state):
        print(f"New Basic Block!")
        if imark_state:
            imark_mem, imark_var, imark_pointer = imark_state[i]
            print(f"[+] imark reg var is {len(imark_mem)}: {imark_mem}")
            print(f"[+] imark_var is {len(imark_var)}: {imark_var}")
            print(f"[+] imark_pointer is {len(imark_pointer)}: {imark_pointer}")
        print(f"[+] state is {len(state)}: {state}")

def bp_call_hook(state):
    state.project.hook(state.solver.eval(state.regs.ip), CallHook())

class CallHook(SimProcedure):
    def run(self, argc, argv):
        # print(f"[CallHook] Program running with callhook! {argc}, {argv}, {hex(self.addr)}")
        self.state.imark_pointer_trace.append({})
        self.state.imark_reg_var_trace.append({})
        self.state.imark_var_trace.append({})
        return self.state.solver.BVS('rax_return', 64)

class FlowTrace:
    def __init__(self, file_name: str, concret_data: dict):
        self.file_name = file_name
        self.cf_change = 0
        self.cf_change_illegal = 0
        self.cf_target_illegal = 0
        self.cf_real_change = 0

        self.df_change = 0
        self.df_change_illegal = 0 
        self.df_access_illegal = 0
        self.df_real_change = 0
        self.mapped_addr = dict()
        self.main_object = None
        self.add_cf_num = 0
        self.concret_data = concret_data
        self.illegal_rotate = False

        self.original_state = None
        self.original_path = None
        self.original_path_layout = dict()
        self.original_imark_info = None

    def diff_df(self, eval_state, new_state, imark_mem_info, start_diff_bb_idx, illegal_info):
        print(f"Data flow diff:")
        df_illegal = False
        df_access_illegal = False
        df_change = False

        def get_original_wr_info(imark_wr_info):
            original_wr_info = dict()
            for bb_mem_info in imark_wr_info:
                for instr_mem_info in bb_mem_info:
                    for addr, value in instr_mem_info.items():
                        try:
                            addr = int(addr, 16)
                        except:
                            continue
                        if addr not in original_wr_info:
                            original_wr_info[addr] = value[1]
                        elif value[1] not in original_wr_info[addr]:
                            original_wr_info[addr] = 'wr'
            return original_wr_info
        
        original_wr_info = get_original_wr_info([[self._bv_transfer(eval_state, instr_info) for instr_info in imark_info[2]] for imark_info in self.original_imark_info])
        wr_info = get_original_wr_info([[self._bv_transfer(eval_state, instr_info) for instr_info in imark_info[2]] for imark_info in imark_mem_info])
        
        for addr, permission in wr_info.items():
            if addr in original_wr_info:
                if original_wr_info[addr] != permission:
                    print(f"[DF+]data flow access illegal: {hex(addr)} {permission}")
                    df_access_illegal = True
                    break
            else:
                if not self.memory_check(permission, addr):
                    print(f"[DF+]data flow access illegal: {hex(addr)} {permission}")
                    df_access_illegal = True
                    break


        if illegal_info[0]:
            print(f"[DF+] illegal happen!")
            df_illegal = True

        original_var_info = [self._bv_transfer(eval_state, instr_info) for imark_info in self.original_imark_info[start_diff_bb_idx:] for instr_info in imark_info[1]]
        original_state = [self._bv_transfer(eval_state, instr_info) for bb_info in self.original_state[start_diff_bb_idx:] for instr_info in bb_info.values()]
        check_var_info = [self._bv_transfer(eval_state, instr_info) for imark_info in imark_mem_info[start_diff_bb_idx:] for instr_info in imark_info[1]]
        check_state = [self._bv_transfer(eval_state, instr_info) for bb_info in new_state[start_diff_bb_idx:] for instr_info in bb_info.values()]

        min_len = min(len(original_var_info), len(check_var_info))
        for idx, instr_info in enumerate(check_var_info):
            if idx >= min_len:
                print(f"[+] new data flow is less than original data flow!")
                df_change = True
                break
            original_instr_state = original_state[idx]
            original_instr_var = original_var_info[idx]
            check_instr_state = check_state[idx]
            diff_addr = []
            for addr, data in instr_info.items():
                if addr not in original_instr_var and addr != 'rip':
                    diff_addr.append((addr, data))
                    print(f"[DF+]addr: {addr} not in original_var_info, {addr}: {data}")
                elif addr in original_instr_var and original_instr_var[addr] != data and addr != 'rip':
                    print(f"[DF+]addr: {addr} original_var_info different: {original_instr_var[addr]} != {data}")
                    diff_addr.append((addr, data))
                elif addr in original_instr_var and original_instr_var[addr] == data and original_instr_state.get(addr, None) != check_instr_state.get(addr, None) and addr != 'rip':
                    print(f"[DF+]addr: {addr} original_var_info same but state different {original_instr_state.get(addr, None)} != {check_instr_state.get(addr, None)}")
                    diff_addr.append((addr, data, check_instr_state.get(addr, None)))
                else:
                    continue
            if len(diff_addr) > 0:
                print(f"[DF*] diff_addr is: {diff_addr}")
                df_change = True
                break

        if df_change:
            self.df_change += 1
            if df_illegal:
                print(f"[DF+] df change but illegal!")
                self.df_change_illegal += 1
            if df_access_illegal:
                print(f"[DF+] df access illegal!")
                self.df_access_illegal += 1
            if not df_illegal and not df_access_illegal:
                print(f"[DF+] df_real_change!")
                self.df_real_change += 1
        return True

    def check_df_change(self, diff_start_addr, diff_end_addr):
        change_bb = []
        for bb_addr, (start_addr, end_addr) in self.original_path_layout.items():
            if (diff_start_addr >= start_addr and diff_start_addr < end_addr) or (start_addr >= diff_start_addr and start_addr < diff_end_addr) or (diff_end_addr >= start_addr and diff_end_addr < end_addr):
                change_bb.append(bb_addr)
        return change_bb

    def diff_cf(self, orig_asm_text, mod_asm_text):

        add_cf_instrction = []
        cf = False
        cf_illegal_target = False

        orig_asm_list = list()
        mod_asm_list = list()

        for text in orig_asm_text:
            instr_list = list(filter(lambda x: x != "", text.strip('-').strip(' ').strip('\n').strip(' ').split(" ")))
            if len(instr_list) > 3:
                instr_list.insert(4, ' '.join(instr_list[4:]))
                del instr_list[5:]
            orig_asm_list.append(instr_list)

        for text in mod_asm_text:
            instr_list = list(filter(lambda x: x != "", text.strip('+').strip(' ').strip('\n').strip(' ').split(" ")))
            if len(instr_list) > 3:
                instr_list.insert(4, ' '.join(instr_list[4:]))
                del instr_list[5:]
            mod_asm_list.append(instr_list)

        for ori in orig_asm_list:
            if ori[3] in CF_INST:
                print(f"[CF-] {'   '.join(ori)}")
                cf = True
        for mod in mod_asm_list:
            print(f"mod: {mod}")
            if mod[3] in CF_INST:
                add_cf_instrction.append(mod)
                print(f"[CF+] {'   '.join(mod)}")
                cf = True

        if cf:
            print("[*CF*] CF Change!")
            self.cf_change += 1

            if self.illegal_rotate:
                print("[Illegal] CF change, Illegal happen!") 
                self.cf_change_illegal += 1

            if not self.illegal_rotate:
                if len(add_cf_instrction) > 0:
                    self.add_cf_num += 1
                for ccf in add_cf_instrction:
                    if (not ccf[-1].strip().startswith('0x')):
                        continue

                    if not self.memory_check('e', int(ccf[-1].strip(), 16)) and not cf_illegal_target:
                        cf_illegal_target = True

                if not cf_illegal_target:
                    print(f"[*CF+*] CF change! legal target!")
                    for i in add_cf_instrction:
                        print('     '.join(i))
                    self.cf_real_change += 1
                else:
                    self.cf_target_illegal += 1
                    print(f"[Ill Target] CF change! illegal target!")
                    for i in add_cf_instrction:
                        print('    '.join(i))

    def compare_func_asm(self, original_asm, modified_asm):
        orig_diff = list()
        mod_diff = list()
        num_mod = int()
        num_ori = int()
        diff = difflib.ndiff(original_asm[0], modified_asm[0])
        diff_start_addr = 0
        diff_end_addr = 0
        if modified_asm[1]:
            self.illegal_rotate = True
        for text in list(diff):
            if text.startswith('-'):
                if not diff_start_addr:
                    diff_start_addr = int(text.split(' ')[1], 16)
                diff_end_addr = int(text.split(' ')[1], 16)
                orig_diff.append(text)
                num_ori += 1
            if text.startswith('+'):
                mod_diff.append(text)
                num_mod += 1

        # print(f"[+] diff_start_addr is: {hex(diff_start_addr)}, diff_end_addr is: {hex(diff_end_addr)}")
        # print(f"[-] Original num is: {num_ori}")
        # print(''.join(orig_diff))
        # print(f"[-] Modification num is: {num_mod}")
        # print(''.join(mod_diff))
        if num_ori > 0 and num_mod > 0:
            self.diff_cf(orig_diff, mod_diff) 
        return num_ori if num_ori < num_mod else num_mod, diff_start_addr, diff_end_addr

    def rotate_block(self, block, sindex: int, cindex: int):
        if cindex * 16 >= len(block):
            print("The change bit large than the block size!")
            return

        block[sindex*16:sindex*16+16] = block[cindex*16:cindex*16+16]

    def internal_function(self, simgr, func_base, func_end):
        for active_state in simgr.active:
            if (active_state.addr <= func_end and active_state.addr >= func_base) or active_state.history.jumpkinds.hardcopy[-1] == "Ijk_Call":
                return True
        return False

    def map_bound_check(self, loader, addr=0):
        for objs in loader.all_objects:
            print("minaddr is: %x, maxaddr is: %x" %
                (objs.min_addr, objs.max_addr))
            print(objs)
            if addr < objs.min_addr or addr > objs.max_addr:
                return False
            
    def memory_check(self, permission, addr):
        # Check mapping
        for segment in self.main_object.segments:
            if addr >= segment.min_addr and addr <= segment.max_addr:
                all_permissions_met = True
                if 'r' in permission and not segment.is_readable:
                    all_permissions_met = False
                if 'w' in permission and not segment.is_writable:
                    all_permissions_met = False
                if 'e' in permission and not segment.is_executable:
                    all_permissions_met = False
                
                if all_permissions_met:
                    return True
        return False
    
    def _bv_transfer(self, state, bv_var):
        if isinstance(bv_var, claripy.ast.bv.BV) and not bv_var.symbolic:
            return hex(state.solver.eval(bv_var))
        elif isinstance(bv_var, claripy.ast.bv.BV) and bv_var.symbolic:
            return str(bv_var)
        elif isinstance(bv_var, tuple):
            return tuple(self._bv_transfer(state, item) for item in bv_var)
        elif isinstance(bv_var, list):
            return [self._bv_transfer(state, item) for item in bv_var]
        elif isinstance(bv_var, dict):
            return {self._bv_transfer(state, key): self._bv_transfer(state, value) for key, value in bv_var.items()}
        else:
            return bv_var
        
    def extract_memory_addr(self, state, state_info, imark_info):
        legal_mem =  list()
        for bb_idx, bb_state in enumerate(state_info):
            imark_reg_var, imark_var = imark_info[bb_idx][:-1]
            str_imark_reg_var = self._bv_transfer(state, imark_reg_var)
            str_imark_var = self._bv_transfer(state, imark_var)
            str_bb_state = self._bv_transfer(state, bb_state)

            legal_mem.append([])
            if len(imark_reg_var) == 0 and len(imark_var) == 0:
                continue
            bb_state_addr = [[info[0] for info in intr_info] for intr_info in str_bb_state.values()]
            for instr_idx, (instr_addr, instr_info) in enumerate(str_bb_state.items()):
                intr_imark_var = str_imark_var[instr_idx]
                for info in instr_info:
                    if info[0] not in intr_imark_var:
                        print(f"[+]{instr_idx} {info[0]} is not in imark_var")
            for idx, intr_var_info in enumerate(str_imark_var):
                for addr in intr_var_info.keys():
                    if addr not in bb_state_addr[idx]:
                        print(f"[+] {addr} is not in str_bb_state")

    def split_block(self, project, state: angr.sim_state, func: tuple[int], base: int, record, data_record, entry_set: dict):
        # Arguement func[0] is the base addr of funcion, func[1] is the end addr of function, func[2] is the base addr align to 0x40, func[3] is the end addr align to 0x40 + 0x40.
        splited_block: list = []

        print(f"[+] Before split block, func is: {[hex(i) for i in func]}, base is: {hex(base)}")

        # Make Function instruction align to 0x40
        bin_func = project.loader.memory.load(func[2], func[3] - func[2])

        splited_nums = int(len(bin_func) / 64)
        for i in range(1, splited_nums + 1):
            splited_block.append(bytearray(bin_func[64*(i-1):64*i]))
        
        csplited = list(splited_block)
        cov_diff_num = 0.0
        count_rotate = 0

        # disasm(b''.join(splited_block)[func[0] - func[2]: func[1] - func[3]], base)

        for b_idx in range(len(splited_block) - 1, -1, -1):
            cblock = bytearray(splited_block[b_idx])
            csplited[b_idx] = cblock
            for src_idx in range(0, 4):
                for dst_idx in range(0, 4):
                    if src_idx == dst_idx:
                        continue
                    self.rotate_block(cblock, src_idx, dst_idx)

                    # Change the code to rotate block.
                    project.loader.memory.store(func[2], b''.join(csplited))
                    print(len(csplited))
                    count_rotate += 1

                    print(f"[+] replace {hex(func[2] + 64 * b_idx +16 * dst_idx)} -> {hex(func[2] + 64 * b_idx +16 * src_idx)}")
                    self.illegal_rotate = False

                    # Check the control flow change.
                    diff_num, diff_start_addr, diff_end_addr = self.compare_func_asm(get_disasm_text(b''.join(splited_block)[func[0] - func[2]: func[1] - func[3]], base), get_disasm_text(b''.join(csplited)[func[0] - func[2]: func[1] - func[3]], base))
                    cov_diff_num += diff_num

                    # Check the dataflow
                    if data_record:
                        change_bb = self.check_df_change(diff_start_addr, diff_end_addr)
                        if not change_bb:
                            cblock = splited_block[b_idx][:]
                            csplited[b_idx] = cblock
                            continue
                        print(f"Data flow analysis is enabled! replace {hex(func[2] + 64 * b_idx +16 * dst_idx)} -> {hex(func[2] + 64 * b_idx +16 * src_idx)}")
 
                        change_bb_idx = [self.original_path.index(hex(bb)) for bb in change_bb]
                        start_diff_bb_idx = min(change_bb_idx)
                        print(f"change_bb_idx is: {change_bb_idx}, start_diff_bb_idx is: {start_diff_bb_idx}")

                        # Clear block cache for the modified region
                        project.factory.default_engine.clear_cache()

                        # Force re-lifting of the block
                        project.factory.block(func[2], size=func[3] - func[2])
                        
                        entry_state = project.factory.entry_state(addr=base)

                        if entry_set:
                            for mem, value in entry_set.items():
                                if mem in GPR:
                                    entry_state.regs.__setattr__(mem, value)
                                else:
                                    entry_state.memory.store(mem, value, size=64, endness=project.arch.memory_endness)
                        new_path, new_state, new_imark_info, illegal_info = self.extract_df(project, entry_state, (diff_start_addr, diff_end_addr))
                        if not illegal_info[1]:
                            print(f"[+] new_path is: {new_path}")
                            # dump_data_flow(new_state, new_imark_info)
                            self.diff_df(entry_state, new_state, new_imark_info, start_diff_bb_idx, illegal_info)

                    cblock = splited_block[b_idx][:]
                    csplited[b_idx] = cblock

        print("cov num is: ", cov_diff_num / count_rotate)
        return splited_block

    def extract_df(self, project, entry_state, change_addr):
        simgr = project.factory.simgr(entry_state)

        # Breakpoint in a function internal call
        entry_state.inspect.b('call', when=angr.BP_BEFORE, action=bp_call_hook)

        # Analysis the data flow change.
        original_state = list()
        original_imark_info = list()

        block = entry_state.block()
        print(f"[+] change_addr is: {[hex(i) for i in change_addr]}")
        
        # Set DFS strategy
        simgr.use_technique(angr.exploration_techniques.DFS())
        
        # Initialize found stash
        simgr.stashes['found'] = []
        last_addr = entry_state.addr
        path_trace = [hex(entry_state.addr)]
        ret_found = False
        
        while len(simgr.active) > 0:
            simgr.step()

            # Check for errored states
            if len(simgr.errored) > 0:
                print(f"[+] Found {len(simgr.errored)} errored states")
                for errored in simgr.errored:
                    print(f"[+] Error state: {hex(errored.state.addr)}, Error: {errored.error}")

            # Process all active states
            for state in simgr.active:
                if state.history.jumpkinds.hardcopy[-2] == 'Ijk_Call':
                    for addr, value in state.registers.trace_store.items():
                        if addr not in state.trace_store:
                            state.trace_store[addr] = dict()
                        for mem, data in value:
                            state.trace_store[addr][mem] = data
                    for addr, value in state.memory.trace_store.items():
                        if addr not in state.trace_store:
                            state.trace_store[addr] = dict()
                        for mem, data in value:
                            state.trace_store[addr][mem] = data

                # Check for call instruction
                if state.history.jumpkinds.hardcopy[-1] == 'Ijk_Call':
                    addr_trace = f"call {hex(state.addr)}"
                else:
                    addr_trace = hex(state.addr)
                path_trace.append(addr_trace)

                # Store state information
                original_state.append(state.trace_store)
                original_imark_info.append((state.imark_reg_var_trace, state.imark_var_trace, state.imark_pointer_trace))

                if state.history.jumpkinds.hardcopy[-1] == 'Ijk_NoDecode':
                    return path_trace, original_state, original_imark_info, (True, False)
                
                if not self.memory_check('e', state.addr):
                    return path_trace, original_state, original_imark_info, (False, True)

                last_addr = state.addr

                # Get the current block
                block = state.block()

                # Get the last instruction of the block
                if not len(block.capstone.insns):
                    return path_trace, original_state, original_imark_info,(True, False)
                last_insn = block.capstone.insns[-1]

                if last_insn.mnemonic == 'ret' and last_insn.bytes[0] == 0xc3:
                    ret_found = True

            if ret_found:
                break
            
        # If we found any states with explicit ret instructions, stop exploring
        if ret_found:
            simgr.step()
            ret_state = simgr.active[0]
            original_state.append(ret_state.trace_store)
            original_imark_info.append((ret_state.imark_reg_var_trace, ret_state.imark_var_trace, ret_state.imark_pointer_trace))

        # dump_data_flow(original_state, original_imark_info)

        return path_trace, original_state, original_imark_info, (False, False)

    
    def start_trace(self, detect_func):
        record_cf_inst = {}
        func: dict[str, tuple[int]] = {}
        with open(file_name, 'rb') as program:
            project = angr.Project(program, load_options={"auto_load_libs": False})
            text_start = project.loader.main_object.sections_map['.text'].min_addr
            text_end = project.loader.main_object.sections_map['.text'].max_addr

            # Print the beginning and end address of text segment.
            print(hex(text_start), hex(text_end))
            func_num = 0
            for func_name, symbol in project.loader.main_object.symbols_by_name.items():
                if project.is_hooked(func_name) or '@@' in func_name.lower() or '__func__' in func_name.lower() or symbol.size == 0 or not symbol.type == type(symbol.type).TYPE_FUNCTION:
                    continue
                self.main_object = project.loader.main_object

                func[func_name] = (symbol.rebased_addr,
                                symbol.rebased_addr + symbol.size, symbol.rebased_addr & 0xffffffffffffffc0, ((symbol.rebased_addr + symbol.size) & 0xffffffffffffffc0) + 0x40)

                entry_state = project.factory.entry_state(
                addr=func[func_name][0])

            for name, sfunc in func.items():
                if sfunc[0] < text_start or sfunc[0] > text_end:
                    continue
                # Print the block numbers of every function.
                print(name, sfunc, func_num, "block is: ", (sfunc[3] - sfunc[2])/64)
            
            print("total func is: ", func_num)

            if detect_func not in func:
                raise Exception(f"[+] {detect_func} is not in the applications, please check the function name!")

            # Check control flow change using internal function to extract CFG
            entry_state = project.factory.entry_state(
                addr=func[detect_func][0])
            cfg = project.analyses.CFGFast(
                regions=[(func[detect_func][0], func[detect_func][1])])
            function = cfg.functions[func[detect_func][0]]
            basic_blocks = list(function.blocks)

            # Print the IR of every basic block
            bb_mem_layout = dict()
            for bb in basic_blocks:

                # Record the direct or indirect jump instructions.
                record_cf_inst[hex(bb.capstone.insns[-1].address)] = (bb.capstone.insns[-1].mnemonic, bb.capstone.insns[-1].op_str)

                bb_mem_layout[bb.addr] = (bb.addr, bb.addr + bb.size)
                
            entry_set = dict()
            for reg in GPR:
                if reg in self.concret_data:
                    entry_state.regs.__setattr__(reg, int(self.concret_data[reg], 16))
                    entry_set[reg] = int(self.concret_data[reg], 16)
                    print(f"[+] concret_data {reg} is: {self.concret_data[reg]}")
                else:
                    sym_reg = claripy.BVS(f'sym_{reg}', 64)
                    entry_state.regs.__setattr__(reg, sym_reg)
                    entry_set[reg] = sym_reg

            for mem, value in self.concret_data.items():
                if mem not in GPR:
                    entry_state.memory.store(int(mem, 16), int(value, 16), size=64, endness=project.arch.memory_endness)
                    entry_set[int(mem, 16)] = int(value, 16)

            self.original_path, self.original_state, self.original_imark_info = self.extract_df(project, entry_state, (0, 0xffffffffffffffff))[:-1]
            for bb in self.original_path:
                if 'call' not in bb:
                    if int(bb, 16) in bb_mem_layout:
                        self.original_path_layout[int(bb, 16)] = bb_mem_layout[int(bb, 16)]
            print(f"[+] original_path_layout is: {[(hex(i), hex(j), hex(k)) for i, (j, k) in self.original_path_layout.items()]}")

            # dump_data_flow(self.original_state, self.original_imark_info)
            self.split_block(project, entry_state, func[detect_func], func[detect_func][0], record_cf_inst, 1, entry_set)
                
            print(f"[Infor CF] CF change is {self.cf_change}, illegal number is: {self.cf_change_illegal} number_add is: {self.add_cf_num}, target_illegal is: {self.cf_target_illegal}, real cf is: {self.cf_real_change}")
            print(f"[Infor DF] DF change is {self.df_change}, illegal number is: {self.df_change_illegal}, access illegal is: {self.df_access_illegal}, real change is: {self.df_real_change}")

if __name__ == "__main__":
    file_name = sys.argv[1]
    detect_func = sys.argv[2]
    concret_data = dict()
    if len(sys.argv) > 3:
        concret_file = sys.argv[3]
        with open(concret_file, 'r') as file:
            concret_data = json.load(file)

    gadget_search = FlowTrace(file_name, concret_data)
    gadget_search.start_trace(detect_func)
