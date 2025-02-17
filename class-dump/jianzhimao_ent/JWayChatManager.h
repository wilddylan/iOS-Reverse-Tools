//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "NSObject.h"

#import "EMChatManagerDelegate.h"

@class NSString;

@interface JWayChatManager : NSObject <EMChatManagerDelegate>
{
    long long _loginErrorCount;
}

+ (_Bool)groupIsIgnore:(id)arg1;
+ (void)insertMessage:(id)arg1;
+ (void)application:(id)arg1 didFailToRegisterForRemoteNotificationsWithError:(id)arg2;
+ (void)application:(id)arg1 didRegisterForRemoteNotificationsWithDeviceToken:(id)arg2;
+ (id)shareInstance;
- (void)notificationWithOfflineCmdMessage:(long long)arg1 content:(id)arg2;
- (void)didReceiveCmdMessage:(id)arg1;
- (void)didReceiveOfflineCmdMessages:(id)arg1;
- (void)appProtectedDataDidBecomeAvailableNotif:(id)arg1;
- (void)appProtectedDataWillBecomeUnavailableNotif:(id)arg1;
- (void)appWillTerminateNotif:(id)arg1;
- (void)appDidReceiveMemoryWarning:(id)arg1;
- (void)appWillResignActiveNotif:(id)arg1;
- (void)appDidBecomeActiveNotif:(id)arg1;
- (void)appDidFinishLaunching:(id)arg1;
- (void)appWillEnterForeground:(id)arg1;
- (void)appDidEnterBackgroundNotif:(id)arg1;
- (void)setupNotifiers;
- (id)conversations;
- (void)fixMessage:(id)arg1;
- (void)deleteMassChatter;
- (id)refreshChatList;
- (void)insertChatWithKF;
- (void)initChatList;
- (void)loginErrorHandler;
- (void)remoteLoginHandler;
- (void)didAutoLoginWithInfo:(id)arg1 error:(id)arg2;
- (void)willAutoLoginWithInfo:(id)arg1 error:(id)arg2;
- (void)didLoginWithInfo:(id)arg1 error:(id)arg2;
- (void)refreshBadgeValue:(id)arg1;
- (void)showNotificationWithMessage:(id)arg1;
- (void)receiveMessageHandler:(id)arg1;
- (void)showApplicationIconBadgeNumber:(id)arg1;
- (void)didReceiveMessage:(id)arg1;
- (void)didUpdateConversationList:(id)arg1;
- (void)registerHx;
- (void)loginChatWithUsername:(id)arg1 password:(id)arg2;
- (void)didAutoReconnectFinishedWithError:(id)arg1;
- (void)willAutoReconnect;
- (void)didLoginFromOtherDevice;
- (void)didConnectionStateChanged:(unsigned long long)arg1;
- (void)didBindDeviceWithError:(id)arg1;
- (void)unRegisterEaseMobNotification;
- (void)registerEaseMobNotification;
- (void)registerEaseMobSDK:(id)arg1 didFinishLaunchingWithOptions:(id)arg2;

// Remaining properties
@property(readonly, copy) NSString *debugDescription;
@property(readonly, copy) NSString *description;
@property(readonly) unsigned long long hash;
@property(readonly) Class superclass;

@end

