//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "BaseWebViewController.h"

#import "AJAlertViewDelegate.h"

@class NSString;

@interface PayFlagViewController : BaseWebViewController <AJAlertViewDelegate>
{
    NSString *_orderId;
    unsigned long long _payResultCode;
    NSString *_jobId;
}

@property(retain, nonatomic) NSString *jobId; // @synthesize jobId=_jobId;
@property(nonatomic) unsigned long long payResultCode; // @synthesize payResultCode=_payResultCode;
@property(retain, nonatomic) NSString *orderId; // @synthesize orderId=_orderId;
- (void).cxx_destruct;
- (void)paySuccessPageTrackWithUrl:(id)arg1;
- (void)popToWillBackViewController;
- (void)popViewController;
- (void)requestShareSuccess;
- (void)shareHandler:(id)arg1;
- (void)getShareInfo;
- (void)alertView:(id)arg1 buttonClick:(long long)arg2;
- (void)showPopView_willBack;
- (void)showPopView_shareError;
- (_Bool)webView:(id)arg1 shouldStartLoadWithRequest:(id)arg2 navigationType:(long long)arg3;
- (void)didReceiveMemoryWarning;
- (void)initBridge;
- (void)initData;
- (id)umPageKey;
- (void)viewDidLoad;

// Remaining properties
@property(readonly, copy) NSString *debugDescription;
@property(readonly, copy) NSString *description;
@property(readonly) unsigned long long hash;
@property(readonly) Class superclass;

@end

