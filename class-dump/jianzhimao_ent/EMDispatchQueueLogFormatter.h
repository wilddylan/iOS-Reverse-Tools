//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "NSObject.h"

#import "EMLogFormatter.h"

@class NSDateFormatter, NSMutableDictionary, NSString;

@interface EMDispatchQueueLogFormatter : NSObject <EMLogFormatter>
{
    NSString *_dateFormatString;
    int _atomicLoggerCount;
    NSDateFormatter *_threadUnsafeDateFormatter;
    int _lock;
    unsigned long long _minQueueLength;
    unsigned long long _maxQueueLength;
    NSMutableDictionary *_replacements;
}

@property unsigned long long maxQueueLength; // @synthesize maxQueueLength=_maxQueueLength;
@property unsigned long long minQueueLength; // @synthesize minQueueLength=_minQueueLength;
- (void).cxx_destruct;
- (void)willRemoveFromLogger:(id)arg1;
- (void)didAddToLogger:(id)arg1;
- (id)formatLogMessage:(id)arg1;
- (id)queueThreadLabelForLogMessage:(id)arg1;
- (id)stringFromDate:(id)arg1;
- (void)setReplacementString:(id)arg1 forQueueLabel:(id)arg2;
- (id)replacementStringForQueueLabel:(id)arg1;
- (id)init;

// Remaining properties
@property(readonly, copy) NSString *debugDescription;
@property(readonly, copy) NSString *description;
@property(readonly) unsigned long long hash;
@property(readonly) Class superclass;

@end

