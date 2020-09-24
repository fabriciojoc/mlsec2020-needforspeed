import re
import math
import lief

class PEAttributeExtractor():

    libraries = ""
    functions = ""
    exports = ""

    # initialize extractor
    def __init__(self, bytez):
        # save bytes
        self.bytez = bytez
        # parse using lief
        self.lief_binary = lief.PE.parse(list(bytez))
        # attributes
        self.attributes = {}

    # extract string metadata
    def extract_string_metadata(self):
        # occurances of string 'C:\'
        paths = re.compile(b'c:\\\\', re.IGNORECASE)
        # occurances of http:// or https://
        urls = re.compile(b'https?://', re.IGNORECASE)
        # occurances of string prefix HKEY_
        registry = re.compile(b'HKEY_')
        # evidences of MZ header
        mz = re.compile(b'MZ')
        return {
            'string_paths': len(paths.findall(self.bytez)),
            'string_urls': len(urls.findall(self.bytez)),
            'string_registry': len(registry.findall(self.bytez)),
            'string_MZ': len(mz.findall(self.bytez))
        }

    # extract entropy
    def extract_entropy(self):
        if not self.bytez:
            return 0
        entropy=0
        for x in range(256):
            p_x = float(self.bytez.count(bytes(x)))/len(self.bytez)
            if p_x>0:
                entropy += - p_x*math.log(p_x, 2)
        return entropy

    # extract attributes
    def extract(self):

        # get general info
        self.attributes.update({
            "size": len(self.bytez),
            "virtual_size": self.lief_binary.virtual_size,
            "has_debug": int(self.lief_binary.has_debug),
            "imports": len(self.lief_binary.imports),
            "exports": len(self.lief_binary.exported_functions),
            "has_relocations": int(self.lief_binary.has_relocations),
            "has_resources": int(self.lief_binary.has_resources),
            "has_signature": int(self.lief_binary.has_signature),
            "has_tls": int(self.lief_binary.has_tls),
            "symbols": len(self.lief_binary.symbols),
        })

        # get header info
        self.attributes.update({
            "timestamp": self.lief_binary.header.time_date_stamps,
            "machine": str(self.lief_binary.header.machine),
            "numberof_sections": self.lief_binary.header.numberof_sections,
            "numberof_symbols": self.lief_binary.header.numberof_symbols,
            "pointerto_symbol_table": self.lief_binary.header.pointerto_symbol_table,
            "sizeof_optional_header": self.lief_binary.header.sizeof_optional_header,
            "characteristics": int(self.lief_binary.header.characteristics),
            "characteristics_list": " ".join([str(c).replace("HEADER_CHARACTERISTICS.","") for c in self.lief_binary.header.characteristics_list])
        })

        try:
            baseof_data = self.lief_binary.optional_header.baseof_data
        except:
            baseof_data = 0

        # get optional header
        self.attributes.update({
            "baseof_code": self.lief_binary.optional_header.baseof_code,
            "baseof_data": baseof_data,
            "dll_characteristics": self.lief_binary.optional_header.dll_characteristics,
            "dll_characteristics_list": " ".join([str(d).replace("DLL_CHARACTERISTICS.", "") for d in self.lief_binary.optional_header.dll_characteristics_lists]),
            "file_alignment": self.lief_binary.optional_header.file_alignment,
            "imagebase": self.lief_binary.optional_header.imagebase,
            "magic": str(self.lief_binary.optional_header.magic).replace("PE_TYPE.",""),
            "PE_TYPE": int(self.lief_binary.optional_header.magic),
            "major_image_version": self.lief_binary.optional_header.major_image_version,
            "minor_image_version": self.lief_binary.optional_header.minor_image_version,
            "major_linker_version": self.lief_binary.optional_header.major_linker_version,
            "minor_linker_version": self.lief_binary.optional_header.minor_linker_version,
            "major_operating_system_version": self.lief_binary.optional_header.major_operating_system_version,
            "minor_operating_system_version": self.lief_binary.optional_header.minor_operating_system_version,
            "major_subsystem_version": self.lief_binary.optional_header.major_subsystem_version,
            "minor_subsystem_version": self.lief_binary.optional_header.minor_subsystem_version,
            "numberof_rva_and_size": self.lief_binary.optional_header.numberof_rva_and_size,
            "sizeof_code": self.lief_binary.optional_header.sizeof_code,
            "sizeof_headers": self.lief_binary.optional_header.sizeof_headers,
            "sizeof_heap_commit": self.lief_binary.optional_header.sizeof_heap_commit,
            "sizeof_image": self.lief_binary.optional_header.sizeof_image,
            "sizeof_initialized_data": self.lief_binary.optional_header.sizeof_initialized_data,
            "sizeof_uninitialized_data": self.lief_binary.optional_header.sizeof_uninitialized_data,
            "subsystem": str(self.lief_binary.optional_header.subsystem).replace("SUBSYSTEM.","")
        })

        # get entropy
        self.attributes.update({
            "entropy": self.extract_entropy()
        })

        # get string metadata
        self.attributes.update(self.extract_string_metadata())

        # get imported libraries and functions
        if self.lief_binary.has_imports:
            self.libraries = " ".join([l for l in self.lief_binary.libraries])
            self.functions = " ".join([f.name for f in self.lief_binary.imported_functions])
        self.attributes.update({"functions": self.functions, "libraries": self.libraries})

        # get exports
        if self.lief_binary.has_exports:
            self.exports = " ".join([f.name for f in self.lief_binary.exported_functions])
        self.attributes.update({"exports_list": self.exports})

        return(self.attributes)
