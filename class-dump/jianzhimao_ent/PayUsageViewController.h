//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "BaseNavViewController.h"

#import "UITableViewDataSource.h"
#import "UITableViewDelegate.h"

@class JobPrepayInfoBean, NSMutableArray, NSString, PartimeJobBean, UITableView;

@interface PayUsageViewController : BaseNavViewController <UITableViewDataSource, UITableViewDelegate>
{
    NSMutableArray *_listArray;
    UITableView *_tableView;
    PartimeJobBean *_jobBean;
    JobPrepayInfoBean *_jobPrepayInfo;
}

@property(retain, nonatomic) JobPrepayInfoBean *jobPrepayInfo; // @synthesize jobPrepayInfo=_jobPrepayInfo;
@property(retain, nonatomic) PartimeJobBean *jobBean; // @synthesize jobBean=_jobBean;
- (void).cxx_destruct;
- (void)didReceiveMemoryWarning;
- (void)tableView:(id)arg1 didSelectRowAtIndexPath:(id)arg2;
- (id)tableView:(id)arg1 cellForRowAtIndexPath:(id)arg2;
- (long long)tableView:(id)arg1 numberOfRowsInSection:(long long)arg2;
- (long long)numberOfSectionsInTableView:(id)arg1;
- (double)tableView:(id)arg1 heightForRowAtIndexPath:(id)arg2;
- (double)tableView:(id)arg1 heightForHeaderInSection:(long long)arg2;
- (void)configData;
- (void)reloadTableViewData;
- (void)initView;
- (void)initData;
- (void)viewDidLoad;
- (id)initWithNibName:(id)arg1 bundle:(id)arg2;

// Remaining properties
@property(readonly, copy) NSString *debugDescription;
@property(readonly, copy) NSString *description;
@property(readonly) unsigned long long hash;
@property(readonly) Class superclass;

@end
