from ...state_plugins.sim_action_object import _raw_ast
from . import MemoryMixin
import claripy
import traceback


class UnwrapperMixin(MemoryMixin):
    """
    This mixin processes SimActionObjects by passing on their .ast field.
    """

    def store(self, addr, data, size=None, condition=None, **kwargs):
        temp = super().store(
            _raw_ast(addr), _raw_ast(data), size=_raw_ast(size), condition=_raw_ast(condition), **kwargs
        )
        return temp

    def load(self, addr, size=None, condition=None, fallback=None, **kwargs):
        reg_index = dict()
        for reg, value in self.state.arch.registers.items():
            if value[0] not in reg_index or reg_index[value[0]][1] < value[1]:
                reg_index[value[0]] = (reg, value[1])
        temp = super().load(
            _raw_ast(addr), size=_raw_ast(size), condition=_raw_ast(condition), fallback=_raw_ast(fallback), **kwargs
        )
        if self.category == 'mem':
            if isinstance(addr, claripy.ast.bv.BV) and addr.symbolic:
                print(f"addr: {addr}, {addr.symbolic}, {addr.variables}")
        return temp

    def find(self, addr, what, max_search, default=None, **kwargs):
        return super().find(_raw_ast(addr), _raw_ast(what), max_search, default=_raw_ast(default), **kwargs)

    def copy_contents(self, dst, src, size, condition=None, **kwargs):
        return super().copy_contents(_raw_ast(dst), _raw_ast(src), _raw_ast(size), _raw_ast(condition), **kwargs)
