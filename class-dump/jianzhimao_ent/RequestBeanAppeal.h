//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "RequestBeanBase.h"

@class NSString;

@interface RequestBeanAppeal : RequestBeanBase
{
    NSString *_trusteeship_id;
    NSString *_content;
}

@property(copy, nonatomic) NSString *content; // @synthesize content=_content;
@property(copy, nonatomic) NSString *trusteeship_id; // @synthesize trusteeship_id=_trusteeship_id;
- (void).cxx_destruct;
- (double)timeout;
- (id)apiPath;

@end

