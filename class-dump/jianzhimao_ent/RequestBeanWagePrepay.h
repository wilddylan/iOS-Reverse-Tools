//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "RequestBeanHttpsBase.h"

@class NSString;

@interface RequestBeanWagePrepay : RequestBeanHttpsBase
{
    NSString *_order_id;
    NSString *_pwd;
}

@property(copy, nonatomic) NSString *pwd; // @synthesize pwd=_pwd;
@property(copy, nonatomic) NSString *order_id; // @synthesize order_id=_order_id;
- (void).cxx_destruct;
- (double)timeout;
- (id)apiPath;

@end
