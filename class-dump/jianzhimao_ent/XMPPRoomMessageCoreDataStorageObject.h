//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "NSManagedObject.h"

#import "XMPPRoomMessage.h"

@class NSDate, NSNumber, NSString, XMPPJID, XMPPMessage;

@interface XMPPRoomMessageCoreDataStorageObject : NSManagedObject <XMPPRoomMessage>
{
}

@property(retain, nonatomic) NSString *messageStr; // @dynamic messageStr;
@property(retain, nonatomic) XMPPMessage *message; // @dynamic message;
@property(nonatomic) _Bool isFromMe; // @dynamic isFromMe;
@property(retain, nonatomic) NSString *jidStr; // @dynamic jidStr;
@property(retain, nonatomic) XMPPJID *jid; // @dynamic jid;
@property(retain, nonatomic) NSString *roomJIDStr; // @dynamic roomJIDStr;
@property(retain, nonatomic) XMPPJID *roomJID; // @dynamic roomJID;

// Remaining properties
@property(retain, nonatomic) NSString *body; // @dynamic body;
@property(readonly, copy) NSString *debugDescription;
@property(readonly, copy) NSString *description;
@property(retain, nonatomic) NSNumber *fromMe; // @dynamic fromMe;
@property(readonly) unsigned long long hash;
@property(retain, nonatomic) NSDate *localTimestamp; // @dynamic localTimestamp;
@property(retain, nonatomic) NSString *nickname; // @dynamic nickname;
@property(retain, nonatomic) XMPPJID *primitiveJid; // @dynamic primitiveJid;
@property(retain, nonatomic) NSString *primitiveJidStr; // @dynamic primitiveJidStr;
@property(retain, nonatomic) XMPPMessage *primitiveMessage; // @dynamic primitiveMessage;
@property(retain, nonatomic) NSString *primitiveMessageStr; // @dynamic primitiveMessageStr;
@property(retain, nonatomic) XMPPJID *primitiveRoomJID; // @dynamic primitiveRoomJID;
@property(retain, nonatomic) NSString *primitiveRoomJIDStr; // @dynamic primitiveRoomJIDStr;
@property(retain, nonatomic) NSDate *remoteTimestamp; // @dynamic remoteTimestamp;
@property(retain, nonatomic) NSString *streamBareJidStr; // @dynamic streamBareJidStr;
@property(readonly) Class superclass;
@property(retain, nonatomic) NSNumber *type; // @dynamic type;

@end

