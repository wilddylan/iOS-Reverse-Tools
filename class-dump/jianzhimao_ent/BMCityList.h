//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "NSObject.h"

@class BMCityInfo, NSArray;

@interface BMCityList : NSObject
{
    long long _resultType;
    long long _cityCount;
    _Bool _currentNull;
    BMCityInfo *_currentCityInfo;
    NSArray *_cities;
}

@property(retain, nonatomic) NSArray *cities; // @synthesize cities=_cities;
@property(retain, nonatomic) BMCityInfo *currentCityInfo; // @synthesize currentCityInfo=_currentCityInfo;
@property(nonatomic) _Bool currentNull; // @synthesize currentNull=_currentNull;
@property(nonatomic) long long cityCount; // @synthesize cityCount=_cityCount;
@property(nonatomic) long long resultType; // @synthesize resultType=_resultType;
- (void).cxx_destruct;
- (id)init;
- (void)dealloc;

@end
