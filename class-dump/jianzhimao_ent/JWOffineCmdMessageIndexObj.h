//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "ObjectBeanBase.h"

@class NSString;

@interface JWOffineCmdMessageIndexObj : ObjectBeanBase
{
    NSString *_job_id;
    long long _count;
    long long _service_type;
    long long _total_num;
    NSString *_content;
}

@property(retain, nonatomic) NSString *content; // @synthesize content=_content;
@property(nonatomic) long long total_num; // @synthesize total_num=_total_num;
@property(nonatomic) long long service_type; // @synthesize service_type=_service_type;
@property(nonatomic) long long count; // @synthesize count=_count;
@property(retain, nonatomic) NSString *job_id; // @synthesize job_id=_job_id;
- (void).cxx_destruct;

@end

