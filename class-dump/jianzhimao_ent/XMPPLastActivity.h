//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "XMPPModule.h"

@class XMPPIDTracker;

@interface XMPPLastActivity : XMPPModule
{
    _Bool _respondsToQueries;
    XMPPIDTracker *_queryTracker;
}

@property(retain) XMPPIDTracker *queryTracker; // @synthesize queryTracker=_queryTracker;
- (void).cxx_destruct;
- (unsigned long long)delegateNumberOfIdleTimeSecondsWithIQ:(id)arg1;
- (void)delegateDidNotReceiveResponse:(id)arg1 dueToTimeout:(double)arg2;
- (void)delegateDidReceiveResponse:(id)arg1;
- (void)xmppCapabilities:(id)arg1 collectingMyCapabilities:(id)arg2;
- (void)xmppStreamDidDisconnect:(id)arg1 withError:(id)arg2;
- (_Bool)xmppStream:(id)arg1 didReceiveIQ:(id)arg2;
- (id)sendLastActivityQueryToJID:(id)arg1 withTimeout:(double)arg2;
- (id)sendLastActivityQueryToJID:(id)arg1;
@property _Bool respondsToQueries; // @synthesize respondsToQueries=_respondsToQueries;
- (void)deactivate;
- (_Bool)activate:(id)arg1;
- (id)initWithDispatchQueue:(struct dispatch_queue_s *)arg1;
- (id)init;

@end

