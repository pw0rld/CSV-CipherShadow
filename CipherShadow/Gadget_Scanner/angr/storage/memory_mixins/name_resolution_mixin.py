from ...errors import SimMemoryError
import claripy
from archinfo.arch_arm import is_arm_arch
from . import MemoryMixin
import traceback

stn_map = {"st%d" % n: n for n in range(8)}
tag_map = {"tag%d" % n: n for n in range(8)}


class NameResolutionMixin(MemoryMixin):
    """
    This mixin allows you to provide register names as load addresses, and will automatically translate this to an
    offset and size.
    """

    def _resolve_location_name(self, name, is_write=False):
        # Delayed load so SimMemory does not rely on SimEngines
        from ...engines.vex.claripy.ccall import _get_flags

        if self.category == "reg":
            if self.state.arch.name in ("X86", "AMD64"):
                if name in stn_map:
                    return (((stn_map[name] + self.load("ftop")) & 7) << 3) + self.state.arch.registers["fpu_regs"][
                        0
                    ], 8
                elif name in tag_map:
                    return ((tag_map[name] + self.load("ftop")) & 7) + self.state.arch.registers["fpu_tags"][0], 1
                elif name in ("flags", "eflags", "rflags"):
                    # we tweak the state to convert the vex condition registers into the flags register
                    if not is_write:  # this work doesn't need to be done if we're just gonna overwrite it
                        # constraints cannot be added by this
                        self.store("cc_dep1", _get_flags(self.state))
                    self.store("cc_op", 0)  # OP_COPY
                    return self.state.arch.registers["cc_dep1"]
            if is_arm_arch(self.state.arch):
                if name == "flags":
                    if not is_write:
                        self.store("cc_dep1", _get_flags(self.state))
                    self.store("cc_op", 0)
                    return self.state.arch.registers["cc_dep1"]

            if name == "sp" and "sp" not in self.state.arch.registers:
                sp_reg_name = self.state.arch.register_names[self.state.arch.sp_offset]
                return self.state.arch.registers[sp_reg_name]
            if name == "lr" and "lr" not in self.state.arch.registers:
                lr_reg_name = self.state.arch.register_names[self.state.arch.lr_offset]
                return self.state.arch.registers[lr_reg_name]

            return self.state.arch.registers[name]
        elif name[0] == "*":
            return self.state.registers.load(name[1:]), None
        else:
            raise SimMemoryError(
                "Trying to address memory with a register name.")

    def store(self, addr, data, size=None, **kwargs):
        if isinstance(addr, str):
            named_addr, named_size = self._resolve_location_name(
                addr, is_write=True)
            # print("addr is:", addr)
            # print("Reg store named_addr is: ", named_addr,
            #       " named_size is: ", named_size)
            if isinstance(data, claripy.ast.BV) and len(data) < named_size * self.state.arch.byte_width:
                data = data.zero_extend(
                    named_size * self.state.arch.byte_width - len(data))
            if isinstance(data, claripy.ast.BV):
                if named_size <= 8:
                    # print("the annotations is: ", data.annotations)
                    base_addr = named_addr & ~0x7
                    size_list = [2**i for i in range(0, 4)]
                    for i in size_list[size_list.index(named_size)+1:]:
                        data.insert_annotations(
                            self.state.registers.load(base_addr, i).annotations)
                        print("%d annotations is:" % i,
                              self.state.registers.load(base_addr, i).annotations)
            return super().store(named_addr, data, size=named_size if size is None else size, **kwargs)
        else:
            return super().store(addr, data, size=size, **kwargs)

    def load(self, addr, size=None, **kwargs):
        if isinstance(addr, str):
            named_addr, named_size = self._resolve_location_name(
                addr, is_write=False)
            # print("[LoadN] addr is: ", named_addr, "size is: ", named_size, kwargs)
            # traceback.print_stack()
            return super().load(named_addr, size=named_size if size is None else size, **kwargs)
        else:
            # print("[LoadN] addr is: ", addr, "size is: ", size, kwargs)
            return super().load(addr, size=size, **kwargs)
