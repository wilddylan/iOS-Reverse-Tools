//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "RequestBeanBase.h"

@class NSString;

@interface RequestBeanCleanList : RequestBeanBase
{
    long long _page;
    NSString *_job_id;
    long long _tag;
    NSString *_content;
}

@property(retain, nonatomic) NSString *content; // @synthesize content=_content;
@property(nonatomic) long long tag; // @synthesize tag=_tag;
@property(copy, nonatomic) NSString *job_id; // @synthesize job_id=_job_id;
@property(nonatomic) long long page; // @synthesize page=_page;
- (void).cxx_destruct;
- (_Bool)needCache;
- (id)apiPath;

@end

