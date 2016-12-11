//
//  PSXLoader.h
//  PSX
//
//  Created by Dan on 2016/12/11.
//    Copyright © 2016年 Makigumo. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Hopper/Hopper.h>

#define HEADER_MAGIC "PS-X EXE"

typedef struct PSX_HEADER_PSX {
    char id[8];
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t pc0;
    uint32_t reserved3;
    uint32_t t_addr;
    uint32_t t_size;
    uint32_t reserved4;
    uint32_t reserved5;
    uint32_t reserved6;
    uint32_t reserved7;
    uint32_t s_addr;
    uint32_t s_size;
    uint32_t SavedSP;
    uint32_t SavedFP;
    uint32_t SavedGP;
    uint32_t SavedRA;
    uint32_t SavedS0;
} PsxHeader_PSX;

typedef struct PSX_HEADER_SCE {
    char id[8];
    uint32_t text;
    uint32_t data;
    uint32_t pc0;
    uint32_t gp0;
    uint32_t t_addr;
    uint32_t t_size;
    uint32_t d_addr;
    uint32_t d_size;
    uint32_t b_addr;
    uint32_t b_size;
    uint32_t s_addr;
    uint32_t s_size;
    uint32_t SavedSP;
    uint32_t SavedFP;
    uint32_t SavedGP;
    uint32_t SavedRA;
    uint32_t SavedS0;
} PsxHeader_SCE;

typedef struct {
    union {
        PsxHeader_PSX psx;
        PsxHeader_SCE sce;
    };
} PsxHeader;

@interface PSXLoader : NSObject <FileLoader>

@end
