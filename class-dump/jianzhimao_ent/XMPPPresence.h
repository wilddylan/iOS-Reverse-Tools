//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "XMPPElement.h"

@interface XMPPPresence : XMPPElement
{
}

+ (id)presenceWithType:(id)arg1 to:(id)arg2;
+ (id)presenceWithType:(id)arg1;
+ (id)presence;
+ (id)presenceFromElement:(id)arg1;
- (_Bool)isErrorPresence;
- (int)intShow;
- (int)priority;
- (id)status;
- (id)show;
- (id)type;
- (id)copyWithZone:(struct _NSZone *)arg1;
- (id)initWithXMLString:(id)arg1 error:(id *)arg2;
- (id)initWithType:(id)arg1 to:(id)arg2;
- (id)initWithType:(id)arg1;
- (id)init;

@end

