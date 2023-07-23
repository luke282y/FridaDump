rpc.exports = {
    init: function (target) {
        dump = new DUMPER(target);
    },
    getMem: function (rva,size) {
        if(dump){
            return dump.get_mem(rva,size);
        }
        return 0
    },
    getFileSize(){
        if(dump){
            return dump.size;
        }
        return 0;
    },
    getFileHeader(){
        if(dump){
            return dump.header;
        }
        return 0;
    }
};

//init with a target process name
var dump;

class DUMPER {
    target;
    constructor(target){
        this.target = target;
    }

    get header(){
        const pe_offset = this.base.add(0x3c).readInt();
        const size_headers = this.base.add(pe_offset).add(0x54).readInt()
        const data = this.base.readByteArray(size_headers);
        return data
    }

    get size(){
        return Process.getModuleByName(this.target).size;
    }

    get base(){
        return Process.getModuleByName(this.target).base;
    }

    rva2va(rva){
        return this.base.add(ptr(rva));
    }

    get_mem(rva,size){
        const mem_ptr = this.rva2va(rva);
        const range = Process.getRangeByAddress(mem_ptr);
        if(!range.protection.includes("r")){
            Memory.protection(range.base,range.size,"rwx");
        }
        return mem_ptr.readByteArray(size);
    }
}

