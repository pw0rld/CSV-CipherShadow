from . import MemoryMixin
from ... import sim_options as options
import claripy
import traceback
import sys

class SimplificationMixin(MemoryMixin):
    def __init__(self, **kwargs):
        super().__init__(**kwargs) 
        self.trace_store = dict()
        
    def store(self, addr, data, **kwargs):
        reg_size_index = self.state.arch.register_size_names
        reg_index = dict()
        for reg, value in self.state.arch.registers.items():
            if value[0] not in reg_index or reg_index[value[0]][1] < value[1]:
                reg_index[value[0]] = (reg, value[1])
    
        if (self.category == "mem" and options.SIMPLIFY_MEMORY_WRITES in self.state.options) or (
            self.category == "reg" and options.SIMPLIFY_REGISTER_WRITES in self.state.options
        ):
            real_data = self.state.solver.simplify(data)
        else:
            real_data = data

        if not self.trace_store.get(hex(self._BV2Int(self.state.registers.load('ip')))):
            self.trace_store[hex(self._BV2Int(self.state.registers.load('ip')))] = list()

        if (self.category == 'reg'):
            if not kwargs['size']:
                if isinstance(addr, claripy.ast.Base):
                    self.trace_store[hex(self._BV2Int(self.state.registers.load('ip')))].append((reg_index[self._BV2Int(addr)][0], data))
                else:
                    self.trace_store[hex(self._BV2Int(self.state.registers.load('ip')))].append(('reg', addr, data))
            elif isinstance(addr, int):
                self.trace_store[hex(self._BV2Int(self.state.registers.load('ip')))].append((reg_size_index[addr,kwargs['size']], data))

            elif isinstance(addr, claripy.ast.Base):
                self.trace_store[hex(self._BV2Int(self.state.registers.load('ip')))].append((reg_size_index[self._BV2Int(addr),kwargs['size']], data))

        else:
            self.trace_store[hex(self._BV2Int(self.state.registers.load('ip')))].append((addr, data))
            
        super().store(addr, real_data, **kwargs)

    def _BV2Int(self, data):
        return self.state.solver.eval(data)

    @MemoryMixin.memo
    def copy(self, memo):
        o = super().copy(memo)
        o.trace_store = dict()
        return o
