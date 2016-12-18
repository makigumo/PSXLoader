//
//  PSXLoader.m
//  PSX
//
//  Created by Makigumo on 2016/12/11.
//    Copyright © 2016年 Makigumo. All rights reserved.
//

#import "PSXLoader.h"

@implementation PSXLoader {
    NSObject <HPHopperServices> *_services;
}

- (instancetype)initWithHopperServices:(NSObject <HPHopperServices> *)services {
    if (self = [super init]) {
        _services = services;
    }
    return self;
}

- (HopperUUID *)pluginUUID {
    return [_services UUIDWithString:@"4F15DEFF-1B73-4538-8579-ABD75456F899"];
}

- (HopperPluginType)pluginType {
    return Plugin_Loader;
}

- (NSString *)pluginName {
    return @"PSX";
}

- (NSString *)pluginDescription {
    return @"PSX Loader";
}

- (NSString *)pluginAuthor {
    return @"Makigumo";
}

- (NSString *)pluginCopyright {
    return @"©2016 - Makigumo";
}

- (NSString *)pluginVersion {
    return @"0.0.1";
}

- (CPUEndianess)endianess {
    return CPUEndianess_Little;
}

- (BOOL)canLoadDebugFiles {
    return NO;
}

// Returns an array of DetectedFileType objects.
- (NSArray<DetectedFileType *> *)detectedTypesForData:(NSData *)data {
    if ([data length] < 4) return @[];

    const void *bytes = [data bytes];
    if (strncmp((const char *) bytes, HEADER_MAGIC_PSX, 8) == 0 ||
            strncmp((const char *) bytes, HEADER_MAGIC_SCE, 7) == 0) {
        NSObject <HPDetectedFileType> *type = [_services detectedType];
        [type setFileDescription:@"PSX Executable"];
        [type setAddressWidth:AW_32bits];
        [type setCpuFamily:@"mips"];
        [type setCpuSubFamily:@"mips32"];
        [type setShortDescriptionString:@"psx_exe"];
        return @[type];
    }

    return @[];
}

- (FileLoaderLoadingStatus)loadData:(NSData *)data
              usingDetectedFileType:(DetectedFileType *)fileType
                            options:(FileLoaderOptions)options
                            forFile:(NSObject <HPDisassembledFile> *)file
                      usingCallback:(FileLoadingCallbackInfo)callback {
    const void *bytes = [data bytes];
    const PsxHeader *header = (PsxHeader *) bytes;
    if (strncmp((const char *) header->psx.id, HEADER_MAGIC_PSX, 8) == 0) {

        [_services logMessage:[NSString stringWithFormat:@"Creating section of %u bytes at [0x%x;0x%x[",
                                                         header->psx.t_size, header->psx.t_addr, header->psx.t_addr + header->psx.t_size]];

        NSObject <HPSegment> *segment = [file addSegmentAt:header->psx.t_addr size:header->psx.t_size];
        NSObject <HPSection> *section = [segment addSectionAt:header->psx.t_addr size:header->psx.t_size];

        segment.segmentName = @"TEXT";
        section.sectionName = @"text";
        section.containsCode = YES;

        NSString *comment = [NSString stringWithFormat:@"\n\nSection %@\n\n", segment.segmentName];
        [file setComment:comment atVirtualAddress:header->psx.t_addr reason:CCReason_Automatic];

        // data starts at 0x800
        NSData *segmentData = [NSData dataWithBytes:bytes + 0x800 length:header->psx.t_size];

        segment.mappedData = segmentData;
        section.fileOffset = 0x800;
        section.fileLength = header->psx.t_size;

        [file addEntryPoint:header->psx.pc0];

        [_services logMessage:@"Searching PSX bios calls"];
        NSObject <HPTag> *biosTag = [file buildTag:@"BIOS function"];
        int bios_calls_found = 0;
        for (int i = 0; i < sizeof(bios_calls); i++) {
            struct bioscall bc = bios_calls[i];
            // li t2, adr; jr t2; li t1, val
            uint8_t bytes_to_find[] = {bc.adr, 0x00, 0x0a, 0x24, 0x08, 0x00, 0x40, 0x01, bc.val, 0x00, 0x09, 0x24};
            NSData *dataToFind = [NSData dataWithBytes:bytes_to_find
                                                length:sizeof(bytes_to_find)];
            NSRange range = [segmentData rangeOfData:dataToFind
                                             options:0
                                               range:NSMakeRange(0, [segmentData length])];
            if (range.location != NSNotFound) {
                //[_services logMessage:[NSString stringWithFormat:@"%s at %0x", bc.name, (unsigned int) range.location]];
                Address address = segment.startAddress + range.location;
                [file setName:@(bc.name) forVirtualAddress:address reason:NCReason_Metadata];
                [file addPotentialProcedure:address];
                [file addTag:biosTag at:address];
                bios_calls_found++;
            }
        }
        [_services logMessage:[NSString stringWithFormat:@"%d PSX bios calls found", bios_calls_found]];

    } else if (strncmp((const char *) header->psx.id, HEADER_MAGIC_SCE, 7) == 0) {

        // create .TEXT
        //
        [_services logMessage:[NSString stringWithFormat:@"Creating section of %u bytes at [0x%x;0x%x[",
                                                         header->sce.t_size, header->sce.t_addr, header->sce.t_addr + header->sce.t_size]];

        NSObject <HPSegment> *textSegment = [file addSegmentAt:header->sce.t_addr size:header->sce.t_size];
        NSObject <HPSection> *textSection = [textSegment addSectionAt:header->sce.t_addr size:header->sce.t_size];

        textSegment.segmentName = @"TEXT";
        textSection.sectionName = @"text";
        textSection.pureCodeSection = YES;

        NSString *textComment = [NSString stringWithFormat:@"\n\nSection %@\n\n", textSegment.segmentName];
        [file setComment:textComment atVirtualAddress:header->sce.t_addr reason:CCReason_Automatic];

        // data starts at 0x800
        NSData *segmentData = [NSData dataWithBytes:bytes + 0x800 length:header->sce.t_size];

        textSegment.mappedData = segmentData;
        textSection.fileOffset = 0x800;
        textSection.fileLength = header->sce.t_size;


        // create .DATA
        //
        NSObject <HPSegment> *dataSegment = [file addSegmentAt:header->sce.d_addr size:header->sce.d_size];
        NSObject <HPSection> *dataSection = [dataSegment addSectionAt:header->sce.d_addr size:header->sce.d_size];

        dataSegment.segmentName = @"DATA";
        dataSection.sectionName = @"data";
        dataSection.pureDataSection = YES;

        NSString *dataComment = [NSString stringWithFormat:@"\n\nSection %@\n\n", dataSegment.segmentName];
        [file setComment:dataComment atVirtualAddress:header->sce.t_addr reason:CCReason_Automatic];

        dataSection.fileOffset = 0x800 + header->sce.d_addr;
        dataSection.fileLength = header->sce.d_size;


        // create .BSS
        //
        NSObject <HPSegment> *bssSegment = [file addSegmentAt:header->sce.b_addr size:header->sce.b_size];
        NSObject <HPSection> *bssSection = [bssSegment addSectionAt:header->sce.b_addr size:header->sce.b_size];

        bssSegment.segmentName = @"BSS";
        bssSection.sectionName = @"bss";
        bssSection.pureDataSection = YES;

        NSString *bssComment = [NSString stringWithFormat:@"\n\nSection %@\n\n", bssSegment.segmentName];
        [file setComment:bssComment atVirtualAddress:header->sce.b_addr reason:CCReason_Automatic];

        bssSection.fileOffset = 0x800 + header->sce.b_addr;
        bssSection.fileLength = header->sce.b_size;

        [file addEntryPoint:header->sce.pc0];
    } else {
        return DIS_BadFormat;
    }

    file.cpuFamily = @"mips";
    file.cpuSubFamily = @"mips32";
    [file setAddressSpaceWidthInBits:32];


    return DIS_OK;
}

- (void)fixupRebasedFile:(NSObject <HPDisassembledFile> *)file withSlide:(int64_t)slide originalFileData:(NSData *)fileData {

}

- (FileLoaderLoadingStatus)loadDebugData:(NSData *)data forFile:(NSObject <HPDisassembledFile> *)file usingCallback:(FileLoadingCallbackInfo)callback {
    return DIS_NotSupported;
}

- (NSData *)extractFromData:(NSData *)data usingDetectedFileType:(NSObject <HPDetectedFileType> *)fileType returnAdjustOffset:(uint64_t *)adjustOffset {
    return nil;
}

@end
