//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "NSObject.h"

@class NSBundle, NSDictionary;

@interface EMPromptManager : NSObject
{
    NSBundle *_sdkBundle;
    NSDictionary *_promptDic;
}

+ (id)shareManager;
+ (id)promptOfKey:(id)arg1;
- (void).cxx_destruct;
- (id)_promptOfKey:(id)arg1;
- (id)init;

@end
