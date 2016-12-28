//
//  M68kCtx.h
//  M68kCPU
//
//  Created by Vincent Bénony on 04/03/2014.
//  Copyright (c) 2014 Cryptic Apps. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Hopper/Hopper.h>

@class M68kCPU;

@interface M68kCtx : NSObject<CPUContext>

- (instancetype)initWithCPU:(M68kCPU *)cpu andFile:(NSObject<HPDisassembledFile> *)file;

@end
