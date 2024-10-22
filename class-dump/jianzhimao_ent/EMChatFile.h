//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "NSObject.h"

#import "IEMChatFile.h"

@class EMChatFileInternal, NSString;

@interface EMChatFile : NSObject <IEMChatFile>
{
    EMChatFileInternal *_internal;
}

- (void).cxx_destruct;
@property(readonly, copy) NSString *description;
- (id)initWithFile:(id)arg1 displayName:(id)arg2;
- (id)initWithData:(id)arg1 displayName:(id)arg2;
- (id)init;
@property(nonatomic) __weak id <IEMMessageBody> messageBody; // @dynamic messageBody;
@property(nonatomic) long long fileLength; // @dynamic fileLength;
@property(retain, nonatomic) NSString *localPath; // @dynamic localPath;
@property(retain, nonatomic) NSString *displayName; // @dynamic displayName;

// Remaining properties
@property(readonly, copy) NSString *debugDescription;
@property(readonly) unsigned long long hash;
@property(readonly) Class superclass;

@end

