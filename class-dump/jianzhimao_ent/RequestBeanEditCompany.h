//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "RequestBeanBase.h"

@class NSString;

@interface RequestBeanEditCompany : RequestBeanBase
{
    NSString *_compinfoid;
    NSString *_info;
}

@property(copy, nonatomic) NSString *info; // @synthesize info=_info;
@property(copy, nonatomic) NSString *compinfoid; // @synthesize compinfoid=_compinfoid;
- (void).cxx_destruct;
- (double)timeout;
- (id)apiPath;

@end

