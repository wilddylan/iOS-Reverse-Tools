//
//  M68kCtx.m
//  M68kCPU
//
//  Created by Vincent Bénony on 04/03/2014.
//  Copyright (c) 2014 Cryptic Apps. All rights reserved.
//

#import "M68kCtx.h"
#import "M68kCPU.h"
#import <Hopper/CommonTypes.h>
#import <Hopper/CPUDefinition.h>
#import <Hopper/HPDisassembledFile.h>
#import "desa68/desa68.h"

@implementation M68kCtx {
    M68kCPU *_cpu;
    NSObject<HPDisassembledFile> *_file;
}

- (instancetype)initWithCPU:(M68kCPU *)cpu andFile:(NSObject<HPDisassembledFile> *)file {
    if (self = [super init]) {
        _cpu = cpu;
        _file = file;
    }
    return self;
}

- (NSObject<CPUDefinition> *)cpuDefinition {
    return _cpu;
}

- (void)initDisasmStructure:(DisasmStruct *)disasm withSyntaxIndex:(NSUInteger)syntaxIndex {
    bzero(disasm, sizeof(DisasmStruct));
}

// Analysis

- (Address)adjustCodeAddress:(Address)address {
    // Instructions are always aligned to a multiple of 2.
    return address & ~1;
}

- (uint8_t)cpuModeFromAddress:(Address)address {
    return 0;
}

- (BOOL)addressForcesACPUMode:(Address)address {
    return NO;
}

- (Address)nextAddressToTryIfInstructionFailedToDecodeAt:(Address)address forCPUMode:(uint8_t)mode {
    return ((address & ~1) + 2);
}

- (int)isNopAt:(Address)address {
    uint16_t word = [_file readUInt16AtVirtualAddress:address];
    return (word == 0x4e71) ? 2 : 0;
}

- (BOOL)hasProcedurePrologAt:(Address)address {
    // procedures usually begins with a "movem.l xxx, -(a7)" or "link" instruction
    uint16_t word = [_file readUInt16AtVirtualAddress:address];
    return (word == 0x48e7) || ((word & 0xFFF8) == 0x4e50);
}

- (void)analysisBeginsAt:(Address)entryPoint {

}

- (void)analysisEnded {

}

- (void)procedureAnalysisBeginsForProcedure:(NSObject<HPProcedure> *)procedure atEntryPoint:(Address)entryPoint {

}

- (void)procedureAnalysisOfPrologForProcedure:(NSObject<HPProcedure> *)procedure atEntryPoint:(Address)entryPoint {

}

- (void)procedureAnalysisOfEpilogForProcedure:(NSObject<HPProcedure> *)procedure atEntryPoint:(Address)entryPoint {
    
}

- (void)procedureAnalysisEndedForProcedure:(NSObject<HPProcedure> *)procedure atEntryPoint:(Address)entryPoint {

}

- (void)procedureAnalysisContinuesOnBasicBlock:(NSObject<HPBasicBlock> *)basicBlock {

}

- (Address)getThunkDestinationForInstructionAt:(Address)address {
    return BAD_ADDRESS;
}

- (void)resetDisassembler {

}

- (uint8_t)estimateCPUModeAtVirtualAddress:(Address)address {
    return 0;
}

uint16_t memory_read_callback(uint32_t address, void* private) {
    M68kCtx *ctx = (__bridge M68kCtx *)private;
    return [ctx readWordAt:address];
}

- (uint16_t)readWordAt:(uint32_t)address {
    return [_file readUInt16AtVirtualAddress:address];
}

- (int)disassembleSingleInstruction:(DisasmStruct *)disasm usingProcessorMode:(NSUInteger)mode {
    char instr[1024];

    DESA68parm_t d;
    d.mem_callb = memory_read_callback;
    d.private_data = (__bridge void *)self;
    d.pc = (unsigned int) disasm->virtualAddr;
    d.memmsk = 0xFFFFFF; // 24 bits addressing
    d.flags = 0;
    d.str = instr;
    d.strmax = sizeof(instr);
    desa68(&d);

    if ((d.status & DESA68_INST) == 0) return DISASM_UNKNOWN_OPCODE;

    disasm->instruction.branchType = DISASM_BRANCH_NONE;
    disasm->instruction.addressValue = 0;
    for (int i=0; i<DISASM_MAX_OPERANDS; i++) disasm->operand[i].type = DISASM_OPERAND_NO_OPERAND;

    // Quick and dirty split of the instruction
    char *ptr = instr;
    char *instrPtr = disasm->instruction.mnemonic;
    while (*ptr && *ptr != ' ') *instrPtr++ = tolower(*ptr++);
    *instrPtr = 0;
    while (*ptr == ' ') ptr++;

    int operandIndex = 0;
    char *operand = disasm->operand[operandIndex].mnemonic;
    int p_level = 0;
    while (*ptr) {
        if (*ptr == ',' && p_level == 0) {
            *operand = 0;
            operand = disasm->operand[++operandIndex].mnemonic;
            ptr++;
            while (*ptr == ' ') ptr++;
        }
        else {
            if (*ptr == '(') p_level++;
            if (*ptr == ')') p_level--;
            *operand++ = tolower(*ptr++);
        }
    }
    *operand = 0;

    // In this early version, only branch instructions are analyzed in order to correctly
    // construct basic blocks of procedures.
    //
    // This is the strict minimum!
    //
    // You should also fill the "operand" description for every other instruction to take
    // advantage of the various analysis of Hopper.

    if (d.status & (DESA68_BSR | DESA68_BRA)) {
        if (strncmp(disasm->instruction.mnemonic, "jsr", 3) == 0
         || strncmp(disasm->instruction.mnemonic, "bsr", 3) == 0) {
            disasm->instruction.branchType = DISASM_BRANCH_CALL;
            if (d.branch & d.memmsk) {
                disasm->instruction.addressValue = d.branch & d.memmsk;
                disasm->operand[0].type = DISASM_OPERAND_CONSTANT_TYPE | DISASM_OPERAND_RELATIVE;
                disasm->operand[0].immediateValue = disasm->instruction.addressValue;
            }
        }
        else {
            if (disasm->instruction.mnemonic[0] == 'd') {
                disasm->instruction.branchType = DISASM_BRANCH_JNE;
                if (d.branch & d.memmsk) {
                    disasm->instruction.addressValue = d.branch & d.memmsk;
                    disasm->operand[0].type = DISASM_OPERAND_CONSTANT_TYPE | DISASM_OPERAND_RELATIVE;
                    disasm->operand[0].immediateValue = disasm->instruction.addressValue;
                }
            }
            else {
                if (strncmp(disasm->instruction.mnemonic, "bra", 3) == 0) {
                    disasm->instruction.branchType = DISASM_BRANCH_JMP;
                }
                if (strncmp(disasm->instruction.mnemonic, "bhi", 3) == 0) {
                    disasm->instruction.branchType = DISASM_BRANCH_JA;
                }
                if (strncmp(disasm->instruction.mnemonic, "bls", 3) == 0) {
                    disasm->instruction.branchType = DISASM_BRANCH_JB;
                }
                if (strncmp(disasm->instruction.mnemonic, "bcc", 3) == 0) {
                    disasm->instruction.branchType = DISASM_BRANCH_JNC;
                }
                if (strncmp(disasm->instruction.mnemonic, "bcs", 3) == 0) {
                    disasm->instruction.branchType = DISASM_BRANCH_JC;
                }
                if (strncmp(disasm->instruction.mnemonic, "bne", 3) == 0) {
                    disasm->instruction.branchType = DISASM_BRANCH_JNE;
                }
                if (strncmp(disasm->instruction.mnemonic, "beq", 3) == 0) {
                    disasm->instruction.branchType = DISASM_BRANCH_JE;
                }
                if (strncmp(disasm->instruction.mnemonic, "bvc", 3) == 0) {
                    disasm->instruction.branchType = DISASM_BRANCH_JNO;
                }
                if (strncmp(disasm->instruction.mnemonic, "bvs", 3) == 0) {
                    disasm->instruction.branchType = DISASM_BRANCH_JO;
                }
                if (strncmp(disasm->instruction.mnemonic, "bpl", 3) == 0) {
                    disasm->instruction.branchType = DISASM_BRANCH_JA;
                }
                if (strncmp(disasm->instruction.mnemonic, "bmi", 3) == 0) {
                    disasm->instruction.branchType = DISASM_BRANCH_JB;
                }
                if (strncmp(disasm->instruction.mnemonic, "bge", 3) == 0) {
                    disasm->instruction.branchType = DISASM_BRANCH_JNL;
                }
                if (strncmp(disasm->instruction.mnemonic, "blt", 3) == 0) {
                    disasm->instruction.branchType = DISASM_BRANCH_JL;
                }
                if (strncmp(disasm->instruction.mnemonic, "bgt", 3) == 0) {
                    disasm->instruction.branchType = DISASM_BRANCH_JG;
                }
                if (strncmp(disasm->instruction.mnemonic, "ble", 3) == 0) {
                    disasm->instruction.branchType = DISASM_BRANCH_JNG;
                }
            }
        }
        if (d.branch & d.memmsk) {
            disasm->instruction.addressValue = d.branch & d.memmsk;
            disasm->operand[0].type = DISASM_OPERAND_CONSTANT_TYPE | DISASM_OPERAND_RELATIVE;
            disasm->operand[0].immediateValue = disasm->instruction.addressValue;
        }
    }

    if (d.status & DESA68_RTS) disasm->instruction.branchType = DISASM_BRANCH_RET;

    int len = d.pc - (unsigned int) disasm->virtualAddr;
    return len;
}

- (BOOL)instructionHaltsExecutionFlow:(DisasmStruct *)disasm {
    return NO;
}

- (void)performBranchesAnalysis:(DisasmStruct *)disasm computingNextAddress:(Address *)next andBranches:(NSMutableArray *)branches forProcedure:(NSObject<HPProcedure> *)procedure basicBlock:(NSObject<HPBasicBlock> *)basicBlock ofSegment:(NSObject<HPSegment> *)segment calledAddresses:(NSMutableArray *)calledAddresses callsites:(NSMutableArray *)callSitesAddresses {

}

- (void)performInstructionSpecificAnalysis:(DisasmStruct *)disasm forProcedure:(NSObject<HPProcedure> *)procedure inSegment:(NSObject<HPSegment> *)segment {

}

- (void)performProcedureAnalysis:(NSObject<HPProcedure> *)procedure basicBlock:(NSObject<HPBasicBlock> *)basicBlock disasm:(DisasmStruct *)disasm {

}

- (void)updateProcedureAnalysis:(DisasmStruct *)disasm {

}

// Printing

- (void)buildInstructionString:(DisasmStruct *)disasm forSegment:(NSObject<HPSegment> *)segment populatingInfo:(NSObject<HPFormattedInstructionInfo> *)formattedInstructionInfo {
    const char *spaces = "                ";
    strcpy(disasm->completeInstructionString, disasm->instruction.mnemonic);
    strcat(disasm->completeInstructionString, spaces + strlen(disasm->instruction.mnemonic));
    for (int i=0; i<DISASM_MAX_OPERANDS; i++) {
        if (disasm->operand[i].mnemonic[0] == 0) break;
        if (i) strcat(disasm->completeInstructionString, ", ");
        strcat(disasm->completeInstructionString, disasm->operand[i].mnemonic);
    }
}

// Decompiler

- (BOOL)canDecompileProcedure:(NSObject<HPProcedure> *)procedure {
    return NO;
}

- (Address)skipHeader:(NSObject<HPBasicBlock> *)basicBlock ofProcedure:(NSObject<HPProcedure> *)procedure {
    return basicBlock.from;
}

- (Address)skipFooter:(NSObject<HPBasicBlock> *)basicBlock ofProcedure:(NSObject<HPProcedure> *)procedure {
    return basicBlock.to;
}

- (ASTNode *)rawDecodeArgumentIndex:(int)argIndex
                           ofDisasm:(DisasmStruct *)disasm
                  ignoringWriteMode:(BOOL)ignoreWrite
                    usingDecompiler:(Decompiler *)decompiler {
    return nil;
}

- (ASTNode *)decompileInstructionAtAddress:(Address)a
                                    disasm:(DisasmStruct)d
                                 addNode_p:(BOOL *)addNode_p
                           usingDecompiler:(Decompiler *)decompiler {
    return nil;
}

// Assembler

- (NSData *)assembleRawInstruction:(NSString *)instr atAddress:(Address)addr forFile:(NSObject<HPDisassembledFile> *)file withCPUMode:(uint8_t)cpuMode usingSyntaxVariant:(NSUInteger)syntax error:(NSError **)error {
    return nil;
}

- (BOOL)instructionCanBeUsedToExtractDirectMemoryReferences:(DisasmStruct *)disasmStruct {
    return YES;
}

- (BOOL)instructionMayBeASwitchStatement:(DisasmStruct *)disasmStruct {
    return NO;
}

@end
