//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "BaseNavViewController.h"

#import "LeaderForgetPasswordDelegate.h"

@class NSString, UIButton, UIImageView, UILabel, UITextField;

@interface LeaderLoginViewController : BaseNavViewController <LeaderForgetPasswordDelegate>
{
    UITextField *_accountTF;
    UITextField *_passwordTF;
    UIButton *_rememberPasswordBtn;
    UILabel *_appNameLabel;
    UIImageView *_logoView;
    id <LoginManagerDelegate> _delegate;
    NSString *_accountStr;
    NSString *_passwordStr;
}

@property(copy, nonatomic) NSString *passwordStr; // @synthesize passwordStr=_passwordStr;
@property(copy, nonatomic) NSString *accountStr; // @synthesize accountStr=_accountStr;
@property(nonatomic) __weak id <LoginManagerDelegate> delegate; // @synthesize delegate=_delegate;
@property(retain, nonatomic) UIImageView *logoView; // @synthesize logoView=_logoView;
@property(retain, nonatomic) UILabel *appNameLabel; // @synthesize appNameLabel=_appNameLabel;
@property(retain, nonatomic) UIButton *rememberPasswordBtn; // @synthesize rememberPasswordBtn=_rememberPasswordBtn;
@property(retain, nonatomic) UITextField *passwordTF; // @synthesize passwordTF=_passwordTF;
@property(retain, nonatomic) UITextField *accountTF; // @synthesize accountTF=_accountTF;
- (void).cxx_destruct;
- (void)leaderApplyBtnHandler:(id)arg1;
- (void)forgetPwBtnHandler:(id)arg1;
- (void)showPopView_Debug;
- (void)startDebugMode;
- (_Bool)isDebugMode:(id)arg1;
- (void)logoTapHandler:(id)arg1;
- (void)passwordDidSet:(id)arg1 account:(id)arg2;
- (void)btnClick:(id)arg1;
- (void)startToLogin:(id)arg1 pwStr:(id)arg2;
- (void)autoLogin;
- (void)readLoginAccount;
- (id)umPageKey;
- (void)initView;
- (void)initData;
- (void)viewDidAppear:(_Bool)arg1;
- (void)viewWillDisappear:(_Bool)arg1;
- (void)viewWillAppear:(_Bool)arg1;
- (void)viewDidLoad;

// Remaining properties
@property(readonly, copy) NSString *debugDescription;
@property(readonly, copy) NSString *description;
@property(readonly) unsigned long long hash;
@property(readonly) Class superclass;

@end

