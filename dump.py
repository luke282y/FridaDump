import frida
import pefile
import lief
import pathlib
import binascii

class DUMPER:
    def __init__(self,process_name):
        self.process = process_name
        self.frida_script = "dump.js"
        self.frida_api = self.init_frida()
        self.pe_data = self.get_pe_from_mem()
        self.binary = self.init_lief()

    def init_frida(self):
        session = frida.attach(self.process)
        script_data = open(self.frida_script,"r").read()
        script = session.create_script(script_data)
        script.load()
        api = script.exports_sync
        api.init(self.process)
        return api
    
    def get_pe_from_mem(self):
        filesize = self.frida_api.get_file_size()
        pe_buf = bytearray(filesize)
        data = bytearray(self.frida_api.get_file_header())
        pe_buf[:len(data)]=data
        pe_hdr = pefile.PE(data=data)
        for section in pe_hdr.sections:
            section = section.dump_dict()
            rva = section['VirtualAddress']['Value']
            virtsize = section['Misc_VirtualSize']['Value']
            section_data = self.frida_api.get_mem(rva,virtsize)
            poffset = section['PointerToRawData']['Value']
            psize = section['SizeOfRawData']['Value']
            pe_buf[poffset:poffset+len(section_data)]=bytearray(section_data)
         
        return bytes(pe_buf)
    
    def init_lief(self):
        return lief.parse(self.pe_data)
    
    def write(self,path):
        builder = lief.PE.Builder(self.binary)
        builder.build_imports(True)
        builder.build()
        builder.write(path)

if __name__ == "__main__":
    dumper = DUMPER(r"notepad++.exe")
    dumper.write(r"C:\out.exe")