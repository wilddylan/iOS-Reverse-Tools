//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "BaseNavViewController.h"

#import "CommonCellModelBaseGenerator.h"
#import "UITableViewDataSource.h"
#import "UITableViewDelegate.h"

@class HireRequirementView, LeaderOrderBean, NSLayoutConstraint, NSString, PartimeJobBean, TrusteeshipInfoObj, UIButton, UILabel, UITableView, UIView;

@interface LeaderOrderDetailViewController : BaseNavViewController <UITableViewDelegate, UITableViewDataSource, CommonCellModelBaseGenerator>
{
    NSString *_orderID;
    UITableView *_tblOrder;
    LeaderOrderBean *_order;
    UILabel *_lblBonus;
    HireRequirementView *_hrView;
    UIButton *_btnOperation;
    UIView *_bottomPanelView;
    NSLayoutConstraint *_tableBottom;
    PartimeJobBean *_jobBean;
    TrusteeshipInfoObj *_trusteeshipInfo;
}

@property(retain, nonatomic) TrusteeshipInfoObj *trusteeshipInfo; // @synthesize trusteeshipInfo=_trusteeshipInfo;
@property(retain, nonatomic) PartimeJobBean *jobBean; // @synthesize jobBean=_jobBean;
@property(nonatomic) __weak NSLayoutConstraint *tableBottom; // @synthesize tableBottom=_tableBottom;
@property(nonatomic) __weak UIView *bottomPanelView; // @synthesize bottomPanelView=_bottomPanelView;
@property(nonatomic) __weak UIButton *btnOperation; // @synthesize btnOperation=_btnOperation;
@property(retain, nonatomic) HireRequirementView *hrView; // @synthesize hrView=_hrView;
@property(nonatomic) __weak UILabel *lblBonus; // @synthesize lblBonus=_lblBonus;
@property(retain, nonatomic) LeaderOrderBean *order; // @synthesize order=_order;
@property(nonatomic) __weak UITableView *tblOrder; // @synthesize tblOrder=_tblOrder;
@property(retain, nonatomic) NSString *orderID; // @synthesize orderID=_orderID;
- (void).cxx_destruct;
- (id)generatorModelsWithDataSource:(id)arg1;
- (void)tableView:(id)arg1 didSelectRowAtIndexPath:(id)arg2;
- (id)tableView:(id)arg1 cellForRowAtIndexPath:(id)arg2;
- (double)tableView:(id)arg1 heightForRowAtIndexPath:(id)arg2;
- (double)tableView:(id)arg1 heightForFooterInSection:(long long)arg2;
- (double)tableView:(id)arg1 heightForHeaderInSection:(long long)arg2;
- (long long)tableView:(id)arg1 numberOfRowsInSection:(long long)arg2;
- (long long)numberOfSectionsInTableView:(id)arg1;
- (void)acceptOrder;
- (void)btnOrderOperationPressed:(id)arg1;
- (void)lookupJob;
- (void)setupBottomPanel;
- (void)checkLeaderPub;
- (void)getTrusteeshipInfo;
- (void)getJobDetail;
- (void)applyOrder;
- (void)getOrderDetail;
- (void)mj_readData;
- (void)didReceiveMemoryWarning;
- (void)viewDidLayoutSubviews;
- (void)viewDidLoad;
- (void)initView;
- (void)initData;
- (id)initWithOrderID:(id)arg1;

// Remaining properties
@property(readonly, copy) NSString *debugDescription;
@property(readonly, copy) NSString *description;
@property(readonly) unsigned long long hash;
@property(readonly) Class superclass;

@end

