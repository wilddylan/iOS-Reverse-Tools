//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "RequestBeanBase.h"

@class NSString;

@interface RequestBeanGetSalaryList : RequestBeanBase
{
    NSString *_order_id;
    long long _page;
}

@property(nonatomic) long long page; // @synthesize page=_page;
@property(retain, nonatomic) NSString *order_id; // @synthesize order_id=_order_id;
- (void).cxx_destruct;
- (id)apiPath;

@end

