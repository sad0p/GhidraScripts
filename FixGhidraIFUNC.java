/*
    sets plt thunks associated with *_IRELATIVE relocations to the resolver function.
    This works around Ghidra mishandling of *_IRELATIVE relocation types.
*/

import java.util.*;
import com.google.common.io.LittleEndianDataInputStream;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.bin.MemoryByteProvider;
import generic.continues.*;

public class FixGhidraIFUNC extends GhidraScript {
    @Override
    public void run() throws Exception {
        final long R_X86_64_IRELATIVE = 37L;
        final long R_386_IRELATIVE = 42L;
        final long X86_64_REL_ENTRY_SIZE = 24L;
        final long X86_REL_ENTRY_SIZE = 8L;
        
        long relEntrySize; 
        long relSectionSize = 0L;
        String relSectionName;
        boolean is64Bit;

        List<Long> irelativeList = new ArrayList<>();
        List<RelocationRecord> irelativeRelocList = new ArrayList<>();
        List<Address> pltEntryList = new ArrayList<>();


        LittleEndianDataInputStream relSection = null;

        Address baseAddress = currentProgram.getMinAddress();
        Memory memHandler = currentProgram.getMemory();
        MemoryByteProvider elfMemProvider =  new MemoryByteProvider(memHandler, baseAddress);

        ElfHeader elfHdrObj = ElfHeader.createElfHeader(RethrowContinuesFactory.INSTANCE, elfMemProvider);
        
        /*
            On linux under intel so far I've only witnessed 32-bit binaries relocation sections being of type SHT_REL
            and 64-bit binaries being of type SHT_RELA. The elf.h header describes others (SHT_RELA for 32-bit binaries for example), 
            but I believe those are used on other unix like OSes and with non-intel processors.
        */

        is64Bit = elfHdrObj.is64Bit();

        if(is64Bit) {
            println("64-bit Binary Detected");
            relEntrySize = X86_64_REL_ENTRY_SIZE;
            relSectionName = ".rela.plt";
        }else {
            println("32-bit Binary Detected");
            relEntrySize = X86_REL_ENTRY_SIZE;
            relSectionName = ".rel.plt";
        }

        for(MemoryBlock memBlock : currentProgram.getMemory().getBlocks()) {
            if(memBlock.getName().equals(relSectionName)) {
                relSection = new LittleEndianDataInputStream(memBlock.getData());
                relSectionSize = memBlock.getSize();
                break;
            }
        }

        long offset;
        long info = 0; //if this is non-zero then irelative entries were found
        long addend;

        if(relSectionSize == 0) {
            println(relSectionName + " contains 0 entries");
            return;
        }

        while(relSectionSize != 0) {
            relSectionSize = relSectionSize - relEntrySize;
            if(is64Bit) {
                offset = relSection.readLong();
                info = relSection.readLong();
                if(info != R_X86_64_IRELATIVE) continue;
                addend = relSection.readLong();
            }else {
                offset = (long)relSection.readInt();
                info = (long)relSection.readInt();
                if(info != R_386_IRELATIVE) continue;
                addend = (long)currentProgram.getMemory().getInt(currentAddress.getNewAddress(offset));
            }

            if(info != 0) {
                irelativeList.add(offset);
                RelocationRecord relocRecord = new RelocationRecord();
                relocRecord.relocOffset = currentAddress.getNewAddress(offset);
                relocRecord.resolverAddr = currentAddress.getNewAddress(addend);
                irelativeRelocList.add(relocRecord);
            }
        }

        println("Total of " + irelativeList.size() + " irelative relocation types found");

        Long pltStart, pltEnd;
        pltStart = currentProgram.getMemory().getBlock(".plt").getStart().getOffset();
        pltEnd = currentProgram.getMemory().getBlock(".plt").getEnd().getOffset();

        ReferenceManager refManager = currentProgram.getReferenceManager();
        for(Long reloc : irelativeList) {
            Address toAddr = currentAddress.getNewAddress(reloc);
            Long toAddrRef;

            //only interested in references originating from .plt

            do {
                toAddrRef = refManager.getReferencesTo(toAddr).next().getFromAddress().getOffset();
            } while(!(pltStart <= toAddrRef && toAddrRef <= pltEnd));
            pltEntryList.add(currentAddress.getNewAddress(toAddrRef));                
        }

        int pltEntryNum = 0;
        for(RelocationRecord rec : irelativeRelocList) {
            String relocOffString = rec.relocOffset.toString();
            String resolverString = rec.resolverAddr.toString();
            String pltEntryString = pltEntryList.get(pltEntryNum).toString();

            println("irelative reloc offset => " + relocOffString);
            println("resolver => " + resolverString);
            println("plt entry => " + pltEntryString);

            Function pltThunk = currentProgram.getFunctionManager().getFunctionAt(pltEntryList.get(pltEntryNum));
            Function resolverFunc = currentProgram.getFunctionManager().getFunctionAt(rec.resolverAddr);

            if(resolverFunc != null && pltThunk != null) {
                pltThunk.setThunkedFunction(resolverFunc);
            } else {
                println("Error setting thunks on" + pltEntryString + " with resolver " + resolverString);
            }

            println("plt thunk set to resolver @ " + resolverString);
            println((pltEntryNum + 1) + "/" + irelativeList.size());
            println("---------------------------------------------------------");
            pltEntryNum = pltEntryNum + 1;
        }
    }
}

class RelocationRecord {
    Address relocOffset;
    Address resolverAddr;
}