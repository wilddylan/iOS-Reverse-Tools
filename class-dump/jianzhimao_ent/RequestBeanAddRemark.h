//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "RequestBeanBase.h"

@class NSString;

@interface RequestBeanAddRemark : RequestBeanBase
{
    NSString *_apply_id;
    NSString *_mark;
}

@property(retain, nonatomic) NSString *mark; // @synthesize mark=_mark;
@property(retain, nonatomic) NSString *apply_id; // @synthesize apply_id=_apply_id;
- (void).cxx_destruct;
- (double)timeout;
- (id)apiPath;

@end

