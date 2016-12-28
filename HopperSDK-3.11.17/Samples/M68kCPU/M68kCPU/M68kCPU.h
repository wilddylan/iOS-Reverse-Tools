//
//  M68kCPU.h
//  M68kCPU
//
//  Created by Vincent Bénony on 04/03/2014.
//  Copyright (c) 2014 Cryptic Apps. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Hopper/Hopper.h>

typedef NS_ENUM(NSUInteger, M68kRegClass) {
    RegClass_AddressRegister = RegClass_FirstUserClass,
    RegClass_M68k_Cnt
};

@interface M68kCPU : NSObject<CPUDefinition>

@end
