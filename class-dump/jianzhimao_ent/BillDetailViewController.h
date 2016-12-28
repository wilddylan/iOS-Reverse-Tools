//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "BaseNavViewController.h"

#import "UITableViewDataSource.h"
#import "UITableViewDelegate.h"

@class NSMutableArray, NSString, UIImageView, UILabel, UITableView;

@interface BillDetailViewController : BaseNavViewController <UITableViewDataSource, UITableViewDelegate>
{
    NSString *_billId;
    long long _serviceType;
    UITableView *_billTableView;
    UILabel *_dealStatusNameLabel;
    UIImageView *_dealStatusIconImgView;
    long long _cellCount;
    double _moneyCellHeight;
    NSMutableArray *_cellShowContentArray;
    NSMutableArray *_cellReuseIDArray;
    NSString *_moneyStr;
    NSString *_payAccountStr;
    NSString *_paymentInfoStr;
    NSString *_billDetailStr;
    NSString *_businessStr;
    NSString *_dealDateStr;
    NSString *_billNumStr;
    long long _currentDealStatus;
}

@property(nonatomic) long long currentDealStatus; // @synthesize currentDealStatus=_currentDealStatus;
@property(copy, nonatomic) NSString *billNumStr; // @synthesize billNumStr=_billNumStr;
@property(copy, nonatomic) NSString *dealDateStr; // @synthesize dealDateStr=_dealDateStr;
@property(copy, nonatomic) NSString *businessStr; // @synthesize businessStr=_businessStr;
@property(copy, nonatomic) NSString *billDetailStr; // @synthesize billDetailStr=_billDetailStr;
@property(copy, nonatomic) NSString *paymentInfoStr; // @synthesize paymentInfoStr=_paymentInfoStr;
@property(copy, nonatomic) NSString *payAccountStr; // @synthesize payAccountStr=_payAccountStr;
@property(copy, nonatomic) NSString *moneyStr; // @synthesize moneyStr=_moneyStr;
@property(retain, nonatomic) NSMutableArray *cellReuseIDArray; // @synthesize cellReuseIDArray=_cellReuseIDArray;
@property(retain, nonatomic) NSMutableArray *cellShowContentArray; // @synthesize cellShowContentArray=_cellShowContentArray;
@property(nonatomic) double moneyCellHeight; // @synthesize moneyCellHeight=_moneyCellHeight;
@property(nonatomic) long long cellCount; // @synthesize cellCount=_cellCount;
@property(nonatomic) __weak UIImageView *dealStatusIconImgView; // @synthesize dealStatusIconImgView=_dealStatusIconImgView;
@property(nonatomic) __weak UILabel *dealStatusNameLabel; // @synthesize dealStatusNameLabel=_dealStatusNameLabel;
@property(nonatomic) __weak UITableView *billTableView; // @synthesize billTableView=_billTableView;
@property(nonatomic) long long serviceType; // @synthesize serviceType=_serviceType;
@property(copy, nonatomic) NSString *billId; // @synthesize billId=_billId;
- (void).cxx_destruct;
- (void)readBillDetail;
- (id)tableView:(id)arg1 cellForRowAtIndexPath:(id)arg2;
- (double)tableView:(id)arg1 heightForRowAtIndexPath:(id)arg2;
- (long long)tableView:(id)arg1 numberOfRowsInSection:(long long)arg2;
- (void)refreshCellReuseId;
- (void)refreshShowContent;
- (void)refreshDealStatus;
- (id)changeEmailAccount:(id)arg1;
- (void)initView;
- (void)initData;
- (void)viewDidLoad;

// Remaining properties
@property(readonly, copy) NSString *debugDescription;
@property(readonly, copy) NSString *description;
@property(readonly) unsigned long long hash;
@property(readonly) Class superclass;

@end
