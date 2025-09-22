#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 
#@runtime PyGhidra


import json
import os
from datetime import datetime
import abc

class BaseStatusHandler(abc.ABC):
    def initialize(self): pass
    def shutdown(self): pass

    def update_step(self, name: str, max_items: int = 0): print(name)
    def update_progress(self, progress: int = 1): pass

    def was_cancelled(self): return False

class BaseDisassemblerInterface(abc.ABC):
    supports_fake_string_segment: bool = False

    @abc.abstractmethod
    def get_script_directory(self) -> str: return ""

    @abc.abstractmethod
    def on_start(self): pass

    @abc.abstractmethod
    def on_finish(self): pass

    @abc.abstractmethod
    def define_function(self, address: int, end: int | None = None): pass

    @abc.abstractmethod
    def define_data_array(self, address: int, type: str, count: int): pass

    @abc.abstractmethod
    def set_data_type(self, address: int, type: str): pass

    @abc.abstractmethod
    def set_function_type(self, address: int, type: str): pass

    @abc.abstractmethod
    def set_data_comment(self, address: int, cmt: str): pass

    @abc.abstractmethod
    def set_function_comment(self, address: int, cmt: str): pass

    @abc.abstractmethod
    def set_data_name(self, address: int, name: str): pass

    @abc.abstractmethod
    def set_function_name(self, address: int, name: str): pass

    @abc.abstractmethod
    def add_cross_reference(self, from_address: int, to_address: int): pass

    @abc.abstractmethod
    def import_c_typedef(self, type_def: str): pass

    # optional
    def add_function_to_group(self, address: int, group: str): pass
    def cache_function_types(self, function_types: list[str]): pass

    # only required if supports_fake_string_segment == True
    def create_fake_segment(self, name: str, size: int) -> int: return 0

    def write_string(self, address: int, value: str) -> int: pass
    def write_address(self, address: int, value: int): pass

class ScriptContext:
    _backend: BaseDisassemblerInterface
    _status: BaseStatusHandler

    def __init__(self, backend: BaseDisassemblerInterface, status: BaseStatusHandler) -> None:
        self._backend = backend
        self._status = status

    def from_hex(self, addr: str): 
        return int(addr, 0)

    def parse_address(self, d: dict): 
        return self.from_hex(d['virtualAddress'])

    def define_il_method(self, definition: dict):
        addr = self.parse_address(definition)
        self._backend.set_function_name(addr, definition['name'])
        self._backend.set_function_type(addr, definition['signature'])
        self._backend.set_function_comment(addr, definition['dotNetSignature'])
        self._backend.add_function_to_group(addr, definition['group'])

    def define_il_method_info(self, definition: dict):
        return
        addr = self.parse_address(definition)
        self._backend.set_data_type(addr, r'struct MethodInfo *')
        self._backend.set_data_name(addr, definition['name'])
        self._backend.set_data_comment(addr, definition['dotNetSignature'])
        if 'methodAddress' in definition:
            method_addr = self.from_hex(definition["methodAddress"])
            self._backend.add_cross_reference(method_addr, addr)
            
    def define_cpp_function(self, definition: dict):
        addr = self.parse_address(definition)
        self._backend.set_function_name(addr, definition['name'])
        self._backend.set_function_type(addr, definition['signature'])

    def define_string(self, definition: dict):
        addr = self.parse_address(definition)
        self._backend.set_data_type(addr, r'struct String *')
        self._backend.set_data_name(addr, definition['name'])
        self._backend.set_data_comment(addr, definition['string'])

    def define_field(self, addr: str, name: str, type: str, il_type: str | None = None):
        address = self.from_hex(addr)
        self._backend.set_data_type(address, type)
        self._backend.set_data_name(address, name)
        if il_type is not None:
            self._backend.set_data_comment(address, il_type)

    def define_field_from_json(self, definition: dict):
        self.define_field(definition['virtualAddress'], definition['name'], definition['type'], definition['dotNetType'])

    def define_array(self, definition: dict):
        addr = self.parse_address(definition)
        self._backend.define_data_array(addr, definition['type'], int(definition['count']))
        self._backend.set_data_name(addr, definition['name'])

    def define_field_with_value(self, definition: dict):
        addr = self.parse_address(definition)
        self._backend.set_data_name(addr, definition['name'])
        self._backend.set_data_comment(addr, definition['value'])

    def process_metadata(self, metadata: dict):
        # Function boundaries
        function_addresses = metadata['functionAddresses']
        function_addresses.sort()
        
        metadata['methodDefinitions'] = [m for m in metadata['methodDefinitions'] if m["group"] == "BlueArchive.dll/MX/NetworkProtocol/ProtocolConverter"]
        for m in metadata['methodDefinitions']:
            idx = function_addresses.index(m['virtualAddress'])
            self._backend.define_function(function_addresses[idx], function_addresses[idx+1])

        # Method definitions
        self._status.update_step('Processing method definitions', len(metadata['methodDefinitions']))
        self._backend.cache_function_types([x["signature"] for x in metadata['methodDefinitions']])
        for d in metadata['methodDefinitions']:
            self.define_il_method(d)
            self._status.update_progress()

    def process(self):
        self._status.initialize()
        
        try:
            start_time = datetime.now()

            self._status.update_step("Running script prologue")
            self._backend.on_start()

            metadata_path = os.path.join(os.getcwd(), "metadata.json")
            with open(metadata_path, "r") as f:
                self._status.update_step("Loading JSON metadata")
                metadata = json.load(f)['addressMap']
                self.process_metadata(metadata)

            self._status.update_step("Running script epilogue")
            self._backend.on_finish()

            self._status.update_step('Script execution complete.')

            end_time = datetime.now()
            print(f"Took: {end_time - start_time}")

        except RuntimeError: 
            pass
        
        finally: 
            self._status.shutdown()
# Ghidra-specific implementation
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.app.util.cparser.C import CParserUtils
from ghidra.program.model.data import ArrayDataType
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.symbol import RefType
from ghidra.app.cmd.label import DemanglerCmd
from ghidra.app.services import DataTypeManagerService
from ghidra.app.util.cparser.C import CParserUtils
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.services import DataTypeManagerService
from ghidra.program.model.data import FileDataTypeManager
import ghidra.framework.Application
import java.io.File as JFile

#try:
#    from typing import TYPE_CHECKING
#    if TYPE_CHECKING:
#        from ..shared_base import BaseStatusHandler, BaseDisassemblerInterface, ScriptContext
#        import json
#        import os
#        import sys
#        from datetime import datetime
#except:
#    pass

class GhidraDisassemblerInterface(BaseDisassemblerInterface):
    supports_fake_string_segment = False

    def get_script_directory(self) -> str: 
        return getSourceFile().getParentFile().toString()

    def on_start(self):
        self.xrefs = currentProgram.getReferenceManager()

        # Check that the user has parsed the C headers first
        if len(getDataTypes('Il2CppObject')) == 0:
            dtm = currentProgram.getDataTypeManager()
            generic_dtm = FileDataTypeManager.openFileArchive(JFile(os.path.join(self.get_script_directory(), "generic_clib.gdt")), False)

            monitor = ConsoleTaskMonitor()
            
            results = CParserUtils.parseHeaderFiles(
                [generic_dtm],
                [os.path.join(os.getcwd(), "il2cpp.h")],
                [],
                dtm,
                monitor
            )

        # Ghidra sets the image base for ELF to 0x100000 for some reason
        # https://github.com/NationalSecurityAgency/ghidra/issues/1020
        # Make sure that the base address is 0
        # Without this, Ghidra may not analyze the binary correctly and you will just waste your time
        # If 0 doesn't work for you, replace it with the base address from the output of the CLI or GUI
        if currentProgram.getExecutableFormat().endswith('(ELF)'):
            currentProgram.setImageBase(toAddr(0), True)
        
        # Don't trigger decompiler
        setAnalysisOption(currentProgram, "Call Convention ID", "false")

    def on_finish(self):
        pass

    def define_function(self, address: int, end: int | None = None):
        address = toAddr(address)
        # Don't override existing functions
        fn = getFunctionAt(address)
        if fn is None:
            # Create new function if none exists
            createFunction(address, None)

    def define_data_array(self, address: int, type: str, count: int):
        if type.startswith('struct '):
            type = type[7:]
        
        t = getDataTypes(type)[0]
        a = ArrayDataType(t, count, t.getLength())
        address = toAddr(address)
        removeDataAt(address)
        createData(address, a)

    def set_data_type(self, address: int, type: str):
        if type.startswith('struct '):
            type = type[7:]
        
        try:
            t = getDataTypes(type)[0]
            address = toAddr(address)
            removeDataAt(address)
            createData(address, t)
        except:
            print("Failed to set type: %s" % type)

    def set_function_type(self, address: int, type: str):
        typeSig = CParserUtils.parseSignature(DataTypeManagerService@None, currentProgram, type)
        ApplyFunctionSignatureCmd(toAddr(address), typeSig, SourceType.USER_DEFINED, False, True).applyTo(currentProgram)

    def set_data_comment(self, address: int, cmt: str):
        setEOLComment(toAddr(address), cmt)

    def set_function_comment(self, address: int, cmt: str):
        setPlateComment(toAddr(address), cmt)

    def set_data_name(self, address: int, name: str):
        address = toAddr(address)

        if len(name) > 2000:
            print("Name length exceeds 2000 characters, skipping (%s)" % name)
            return

        if not name.startswith("_ZN"):
            createLabel(address, name, True)
            return
        
        cmd = DemanglerCmd(address, name)
        if not cmd.applyTo(currentProgram, monitor):
            print(f"Failed to apply demangled name to {name} at {address} due {cmd.getStatusMsg()}, falling back to mangled")
            createLabel(address, name, True)

    def set_function_name(self, address: int, name: str): 
        return self.set_data_name(address, name)

    def add_cross_reference(self, from_address: int, to_address: int): 
        self.xrefs.addMemoryReference(toAddr(from_address), toAddr(to_address), RefType.DATA, SourceType.USER_DEFINED, 0)

    def import_c_typedef(self, type_def: str):
        # Code declarations are not supported in Ghidra
        # This only affects string literals for metadata version < 19
        # TODO: Replace with creating a DataType for enums
        pass

class GhidraStatusHandler(BaseStatusHandler): 
    pass


status = GhidraStatusHandler()
backend = GhidraDisassemblerInterface()

context = ScriptContext(backend, status)

context.process()

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.data import Enum

output_file = os.path.join(os.getcwd(), "TypeConversion.c")
with open(output_file, "w") as f:
    f.write("// Auto-generated by Ghidra Script DO NOT MODIFY\n\n")
    f.write("#include <stdint.h>\n")
    f.write('''
#if __has_include(<Python.h>)
    #define BUILDING_PYTHON_EXTENSION 1
#endif

#ifdef BUILDING_PYTHON_EXTENSION
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#endif
''')
    dtm = currentProgram.getDataTypeManager()
    enums = dtm.getAllDataTypes()
    
    for dt in enums:
        if dt.getName() == "Protocol__Enum": 
            if isinstance(dt, Enum):
                f.write("typedef enum " + dt.getName() + " {\n")
                for name, value in zip(dt.getNames(), dt.getValues()):
                    f.write("    {} = {},\n".format(name, value))
                f.write(f"}} {dt.getName()};\n\n")
                break
    # Setup decompiler
    decompiler = DecompInterface()
    options = DecompileOptions()
    options.setMaxInstructions(1000000)
    decompiler.setOptions(options)
    decompiler.openProgram(currentProgram)

    for func in currentProgram.getFunctionManager().getFunctions(True):
        functionName = func.getName(True)
        if functionName == "MX::NetworkProtocol::ProtocolConverter::ProtocolConverter_TypeConversion":
            print(f"Found {functionName}")
            decompiled = decompiler.decompileFunction(func, 300, ConsoleTaskMonitor())
            code = decompiled.getDecompiledFunction().getC()
            code = code.replace("::", "_")
            code = code.replace("uint ", "uint32_t ")
            code = code.replace("(ProtocolConverter *this,uint32_t crc,Protocol__Enum protocol,MethodInfo *method)", "(uint32_t crc, Protocol__Enum protocol)")
            f.write(code)
            f.write("\n\n")
            f.write('''
#if defined(_WIN32) || defined(__CYGWIN__)
  #define EXPORT __declspec(dllexport)
#else
  #define EXPORT __attribute__((visibility("default")))
#endif

EXPORT int32_t TypeConversion(uint32_t crc, int protocol)
{
    return MX_NetworkProtocol_ProtocolConverter_ProtocolConverter_TypeConversion(crc, (Protocol__Enum)protocol);
}

#ifdef BUILDING_PYTHON_EXTENSION

static PyObject* py_TypeConversion(PyObject* self, PyObject* args) {
    uint32_t crc;
    int protocol;

    if (!PyArg_ParseTuple(args, "Ii", &crc, &protocol)) {
        return NULL;
    }

    int32_t result = TypeConversion(crc, protocol);

    return PyLong_FromLong(result);
}

static PyMethodDef TypeConversionMethods[] = {
    {"TypeConversion", py_TypeConversion, METH_VARARGS,
     "Convert (crc, protocol) using MX_NetworkProtocol converter."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef TypeConversionModule = {
    PyModuleDef_HEAD_INIT,
    "TypeConversion",
    NULL,
    -1,
    TypeConversionMethods
};

PyMODINIT_FUNC PyInit_TypeConversion(void) {
    return PyModule_Create(&TypeConversionModule);
}

#endif
''')
            f.flush()
            break
            