//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "RequestBeanBase.h"

@class NSString;

@interface RequestBeanLeaderVerificationCode : RequestBeanBase
{
    long long _method;
    NSString *_phone;
    NSString *_rand_code;
}

@property(retain, nonatomic) NSString *rand_code; // @synthesize rand_code=_rand_code;
@property(retain, nonatomic) NSString *phone; // @synthesize phone=_phone;
@property(nonatomic) long long method; // @synthesize method=_method;
- (void).cxx_destruct;
- (id)apiPath;

@end

