//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "NSObject.h"

@class NSArray;

@interface LeaderPushInfoObj : NSObject
{
    NSArray *_help_content_list;
    long long _surplus_timestamp;
    long long _wait_timestamp;
}

@property(nonatomic) long long wait_timestamp; // @synthesize wait_timestamp=_wait_timestamp;
@property(nonatomic) long long surplus_timestamp; // @synthesize surplus_timestamp=_surplus_timestamp;
@property(retain, nonatomic) NSArray *help_content_list; // @synthesize help_content_list=_help_content_list;
- (void).cxx_destruct;

@end

