//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "ObjectBeanBase.h"

@class NSString;

@interface JobDutyBean : ObjectBeanBase
{
    NSString *_post_id;
    NSString *_title;
    NSString *_salary;
    NSString *_money;
    long long _num;
}

@property(nonatomic) long long num; // @synthesize num=_num;
@property(copy, nonatomic) NSString *money; // @synthesize money=_money;
@property(copy, nonatomic) NSString *salary; // @synthesize salary=_salary;
@property(copy, nonatomic) NSString *title; // @synthesize title=_title;
@property(copy, nonatomic) NSString *post_id; // @synthesize post_id=_post_id;
- (void).cxx_destruct;

@end

