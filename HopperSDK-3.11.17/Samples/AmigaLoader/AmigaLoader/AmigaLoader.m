//
//  AmigaLoader.m
//  AmigaLoader
//
//  Created by Vincent Bénony on 03/03/2014.
//  Copyright (c) 2014 Cryptic Apps. All rights reserved.
//

#import "AmigaLoader.h"

typedef NS_ENUM(uint32_t, HUNK_TYPE) {
    HUNK_UNIT = 999,
    HUNK_NAME = 1000,
    HUNK_CODE = 1001,
    HUNK_DATA = 1002,
    HUNK_BSS = 1003,
    HUNK_RELOC32 = 1004,
    HUNK_RELOC16 = 1005,
    HUNK_RELOC8 = 1006,
    HUNK_EXT = 1007,
    HUNK_SYMBOL = 1008,
    HUNK_DEBUG = 1009,
    HUNK_END = 1010,
    HUNK_HEADER = 1011,
    HUNK_OVERLAY = 1013,
    HUNK_BREAK = 1014,
    HUNK_DRELOC32 = 1015,
    HUNK_DRELOC16 = 1016,
    HUNK_DRELOC8 = 1017,
    HUNK_LIB = 1018,
    HUNK_INDEX = 1019,
    HUNK_RELOC32SHORT = 1020,
    HUNK_ABSRELOC16 = 1022,
    HUNK_PPC_CODE = 1257,
    HUNK_RELRELOC26 = 1260
};

@implementation AmigaLoader {
    NSObject<HPHopperServices> *_services;
}

- (instancetype)initWithHopperServices:(NSObject<HPHopperServices> *)services {
    if (self = [super init]) {
        _services = services;
    }
    return self;
}

- (HopperUUID *)pluginUUID {
    return [_services UUIDWithString:@"b92d6db3-1a89-4c48-aff2-2d9e4343cb52"];
}

- (HopperPluginType)pluginType {
    return Plugin_Loader;
}

- (NSString *)pluginName {
    return @"Amiga Hunk";
}

- (NSString *)pluginDescription {
    return @"Amiga Hunk File Loader";
}

- (NSString *)pluginAuthor {
    return @"Vincent Bénony";
}

- (NSString *)pluginCopyright {
    return @"©2014 - Cryptic Apps SARL";
}

- (NSString *)pluginVersion {
    return @"0.0.1";
}

- (CPUEndianess)endianess {
    return CPUEndianess_Big;
}

- (BOOL)canLoadDebugFiles {
    return NO;
}

// Returns an array of DetectedFileType objects.
- (NSArray *)detectedTypesForData:(NSData *)data {
    if ([data length] < 4) return @[];

    const void *bytes = (const void *)[data bytes];
    if (OSReadBigInt32(bytes, 0) == HUNK_HEADER) {
        NSObject<HPDetectedFileType> *type = [_services detectedType];
        [type setFileDescription:@"Amiga Executable"];
        [type setAddressWidth:AW_32bits];
        [type setCpuFamily:@"motorola"];
        [type setCpuSubFamily:@"68000"];
        [type setShortDescriptionString:@"amiga_hunk"];
        return @[type];
    }

    return @[];
}

- (FileLoaderLoadingStatus)loadData:(NSData *)data usingDetectedFileType:(DetectedFileType *)fileType options:(FileLoaderOptions)options forFile:(NSObject<HPDisassembledFile> *)file usingCallback:(FileLoadingCallbackInfo)callback {
    const void *bytes = (const void *)[data bytes];
    const void *lastByte = bytes + [data length];
    if (OSReadBigInt32(bytes, 0) != HUNK_HEADER) return DIS_BadFormat;
    bytes += 4;

    // Read resident library names
    while (bytes < lastByte) {
        uint32_t stringLength = OSReadBigInt32(bytes, 0); bytes += 4;
        if (stringLength == 0) break;
        bytes += stringLength * 4;
    }

    uint32_t tableSize = OSReadBigInt32(bytes, 0); bytes += 4;
    uint32_t firstHunk = OSReadBigInt32(bytes, 0); bytes += 4;
    uint32_t lastHunk = OSReadBigInt32(bytes, 0); bytes += 4;
    const void *sizes = bytes;
    bytes += (lastHunk - firstHunk + 1) * 4;

    uint32_t *loadAddresses = (uint32_t *)alloca(sizeof(uint32_t) * tableSize);
    uint32_t firstAddress = 0x1000;
    uint32_t address = firstAddress;
    for (uint32_t i=0; i<tableSize; i++) {
        loadAddresses[i] = address;
        uint32_t size = OSReadBigInt32(sizes, i * 4);
        address += size * 4;
    }

    uint32_t currentHunkIndex = firstHunk;
    NSObject<HPSegment> *currentSegment = nil;

    while (bytes < lastByte) {
        uint32_t hunk_id = OSReadBigInt32(bytes, 0); bytes += 4;
        hunk_id &= 0x3FFFFFFF;

        if (hunk_id == HUNK_CODE || hunk_id == HUNK_DATA || hunk_id == HUNK_BSS) {
            uint32_t sizeInWords = OSReadBigInt32(bytes, 0); bytes += 4;
            // BOOL inFastMem = ((size & 0x80000000) != 0);
            // BOOL inChipMem = ((size & 0x40000000) != 0);
            sizeInWords &= 0x3FFFFFFF;
            uint32_t sizeInBytes = sizeInWords * 4;

            if (sizeInWords) {
                uint32_t startAddress = loadAddresses[currentHunkIndex];
                uint32_t endAddress = startAddress + sizeInBytes;
                NSLog(@"Create section of %d bytes at [0x%x;0x%x[", sizeInWords * 4, startAddress, endAddress);
                NSObject<HPSegment> *segment = [file addSegmentAt:startAddress size:sizeInBytes];
                NSObject<HPSection> *section = [segment addSectionAt:startAddress size:sizeInBytes];
                currentSegment = segment;

                if (hunk_id == HUNK_CODE) {
                    segment.segmentName = @"CODE";
                    section.sectionName = @"code";
                    section.pureCodeSection = YES;
                }
                if (hunk_id == HUNK_DATA) {
                    segment.segmentName = @"DATA";
                    section.sectionName = @"data";
                }
                if (hunk_id == HUNK_BSS) {
                    segment.segmentName = @"BSS";
                    section.sectionName = @"bss";
                }

                NSString *comment = [NSString stringWithFormat:@"\n\nHunk %@\n\n", segment.segmentName];
                [file setComment:comment atVirtualAddress:startAddress reason:CCReason_Automatic];

                if (hunk_id != HUNK_BSS) {
                    NSData *segmentData = [NSData dataWithBytes:bytes length:sizeInBytes];
                    segment.mappedData = segmentData;
                    segment.fileOffset = bytes - [data bytes];
                    segment.fileLength = sizeInBytes;
                    section.fileOffset = segment.fileOffset;
                    section.fileLength = segment.fileLength;
                    bytes += sizeInBytes;
                }
            }
        }
        else if (hunk_id == HUNK_RELOC32) {
            while (1) {
                uint32_t count = OSReadBigInt32(bytes, 0); bytes += 4;
                if (count == 0) break;
                uint32_t target_hunk_number = OSReadBigInt32(bytes, 0); bytes += 4;
                for (uint32_t i=0; i<count; i++) {
                    uint32_t offset = OSReadBigInt32(bytes, 0); bytes += 4;
                    uint32_t original = OSReadBigInt32([currentSegment.mappedData bytes], offset);
                    original += loadAddresses[target_hunk_number];
                    OSWriteBigInt32((void *)[currentSegment.mappedData bytes], offset, original);
                }
            }
        }
        else if (hunk_id == HUNK_RELOC32SHORT || hunk_id == HUNK_DRELOC32 || hunk_id == HUNK_ABSRELOC16) {
            while (1) {
                uint32_t count = OSReadBigInt16(bytes, 0); bytes += 2;
                if (count == 0) break;
                uint32_t target_hunk_number = OSReadBigInt16(bytes, 0); bytes += 2;
                for (uint32_t i=0; i<count; i++) {
                    uint32_t offset = OSReadBigInt16(bytes, 0); bytes += 2;
                    uint32_t original = OSReadBigInt32([currentSegment.mappedData bytes], offset);
                    if (hunk_id == HUNK_ABSRELOC16) {
                        original -= (uint32_t) (currentSegment.startAddress + offset);
                    }
                    original += loadAddresses[target_hunk_number];
                    OSWriteBigInt32((void *)[currentSegment.mappedData bytes], offset, original);
                }
            }
        }
        else if (hunk_id == HUNK_END) {
            currentHunkIndex++;
            if (currentHunkIndex > lastHunk) break;
        }
    }

    file.cpuFamily = @"motorola";
    file.cpuSubFamily = @"68000";
    [file setAddressSpaceWidthInBits:32];

    [file addEntryPoint:firstAddress];

    return DIS_OK;
}

- (void)fixupRebasedFile:(NSObject<HPDisassembledFile> *)file withSlide:(int64_t)slide originalFileData:(NSData *)fileData {
    
}

- (FileLoaderLoadingStatus)loadDebugData:(NSData *)data forFile:(NSObject<HPDisassembledFile> *)file usingCallback:(FileLoadingCallbackInfo)callback {
    return DIS_NotSupported;
}

- (NSData *)extractFromData:(NSData *)data usingDetectedFileType:(DetectedFileType *)fileType returnAdjustOffset:(uint64_t *)adjustOffset {
    return nil;
}

@end
