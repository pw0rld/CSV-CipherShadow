from . import MemoryMixin

class TracestoreMixin(MemoryMixin):

    """
    This mixin use to trace the store operation.
    """

    trace_store = dict()

    def __init__(self):
        super().__init__()
        self.reg_index = {j : i for i, j in self.state.arch.registers.items()}

    def _BV2Int(self, data):
        return self.state.solver.eval(data)


    def store(self, addr, data, size=None, condition=None, **kwargs):
        if not trace_store.get(_BV2Int(self.state.load('ip'))):
            trace_store[_BV2Int(self.state.load('ip'))] = list()
        if (self.category == 'reg'):
            trace_store[_BV2Int(self.state.load('ip'))].append((reg_index[(_BV2Int(addr)),size], data))
        else:
            trace_store[_BV2Int(self.state.load('ip'))].append((addr, data))
        return super().store(addr, data, size, condition, **kwargs)

