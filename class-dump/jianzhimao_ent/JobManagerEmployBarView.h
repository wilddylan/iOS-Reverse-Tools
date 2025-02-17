//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "BaseBarView.h"

@class UIButton;

@interface JobManagerEmployBarView : BaseBarView
{
    UIButton *_notifityBtn;
    UIButton *_signinManagerBtn;
    UIButton *_totalPayBtn;
    long long _accountType;
}

@property(nonatomic) long long accountType; // @synthesize accountType=_accountType;
@property(retain, nonatomic) UIButton *totalPayBtn; // @synthesize totalPayBtn=_totalPayBtn;
@property(retain, nonatomic) UIButton *signinManagerBtn; // @synthesize signinManagerBtn=_signinManagerBtn;
@property(retain, nonatomic) UIButton *notifityBtn; // @synthesize notifityBtn=_notifityBtn;
- (void).cxx_destruct;
- (void)setExportHandler:(SEL)arg1 target:(id)arg2;
- (void)setNotifityHandler:(SEL)arg1 target:(id)arg2;
- (void)setSigninManagerHandler:(SEL)arg1 target:(id)arg2;
- (id)initWithFrame:(struct CGRect)arg1;

@end

