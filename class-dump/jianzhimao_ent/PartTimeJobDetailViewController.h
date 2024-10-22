//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "BaseNavViewController.h"

#import "AJAlertViewDelegate.h"
#import "CalendarVCDelegate.h"
#import "CommentHeaderViewDelegate.h"
#import "ReplayDeleagate.h"
#import "UITableViewDataSource.h"
#import "UITableViewDelegate.h"

@class NSIndexPath, NSLayoutConstraint, NSMutableArray, NSString, PartimeJobBean, RoundCornerButton, ShareContentObj, UIButton, UILabel, UITableView;

@interface PartTimeJobDetailViewController : BaseNavViewController <UITableViewDataSource, UITableViewDelegate, CommentHeaderViewDelegate, CalendarVCDelegate, ReplayDeleagate, AJAlertViewDelegate>
{
    _Bool _isExpand;
    _Bool _isShowingShareBtn;
    _Bool _isHideReplyBtn;
    PartimeJobBean *_jobBean;
    unsigned long long _jobType;
    UITableView *_tableView;
    NSLayoutConstraint *_footerHeightConstrain;
    RoundCornerButton *_footer_payBtn;
    UILabel *_jobTitleLabel;
    UILabel *_workAddressLabel;
    UILabel *_workTimeLabel;
    UILabel *_workReadCountLabel;
    UIButton *_expandBtn;
    UIButton *_shareBtn;
    ShareContentObj *_shareContent;
    NSMutableArray *_cellIDArray;
    NSMutableArray *_expandIDArray;
    NSMutableArray *_contentArray;
    NSMutableArray *_workDateArray;
    NSMutableArray *_commentArray;
    NSString *_lat;
    NSString *_lon;
    long long _totalCommentCount;
    NSIndexPath *_indexPath_company;
    NSIndexPath *_indexPath_workDesc;
    NSIndexPath *_indexPath_workDate;
    NSIndexPath *_indexPath_workTimeSlot;
    NSIndexPath *_indexPath_workAddr;
    long long _commentSection;
}

@property(nonatomic) long long commentSection; // @synthesize commentSection=_commentSection;
@property(retain, nonatomic) NSIndexPath *indexPath_workAddr; // @synthesize indexPath_workAddr=_indexPath_workAddr;
@property(retain, nonatomic) NSIndexPath *indexPath_workTimeSlot; // @synthesize indexPath_workTimeSlot=_indexPath_workTimeSlot;
@property(retain, nonatomic) NSIndexPath *indexPath_workDate; // @synthesize indexPath_workDate=_indexPath_workDate;
@property(retain, nonatomic) NSIndexPath *indexPath_workDesc; // @synthesize indexPath_workDesc=_indexPath_workDesc;
@property(retain, nonatomic) NSIndexPath *indexPath_company; // @synthesize indexPath_company=_indexPath_company;
@property(nonatomic) _Bool isHideReplyBtn; // @synthesize isHideReplyBtn=_isHideReplyBtn;
@property(nonatomic) long long totalCommentCount; // @synthesize totalCommentCount=_totalCommentCount;
@property(copy, nonatomic) NSString *lon; // @synthesize lon=_lon;
@property(copy, nonatomic) NSString *lat; // @synthesize lat=_lat;
@property(retain, nonatomic) NSMutableArray *commentArray; // @synthesize commentArray=_commentArray;
@property(retain, nonatomic) NSMutableArray *workDateArray; // @synthesize workDateArray=_workDateArray;
@property(retain, nonatomic) NSMutableArray *contentArray; // @synthesize contentArray=_contentArray;
@property(retain, nonatomic) NSMutableArray *expandIDArray; // @synthesize expandIDArray=_expandIDArray;
@property(retain, nonatomic) NSMutableArray *cellIDArray; // @synthesize cellIDArray=_cellIDArray;
@property(retain, nonatomic) ShareContentObj *shareContent; // @synthesize shareContent=_shareContent;
@property(nonatomic) _Bool isShowingShareBtn; // @synthesize isShowingShareBtn=_isShowingShareBtn;
@property(retain, nonatomic) UIButton *shareBtn; // @synthesize shareBtn=_shareBtn;
@property(nonatomic) __weak UIButton *expandBtn; // @synthesize expandBtn=_expandBtn;
@property(nonatomic) __weak UILabel *workReadCountLabel; // @synthesize workReadCountLabel=_workReadCountLabel;
@property(nonatomic) __weak UILabel *workTimeLabel; // @synthesize workTimeLabel=_workTimeLabel;
@property(nonatomic) __weak UILabel *workAddressLabel; // @synthesize workAddressLabel=_workAddressLabel;
@property(nonatomic) __weak UILabel *jobTitleLabel; // @synthesize jobTitleLabel=_jobTitleLabel;
@property(nonatomic) __weak RoundCornerButton *footer_payBtn; // @synthesize footer_payBtn=_footer_payBtn;
@property(nonatomic) __weak NSLayoutConstraint *footerHeightConstrain; // @synthesize footerHeightConstrain=_footerHeightConstrain;
@property(nonatomic) __weak UITableView *tableView; // @synthesize tableView=_tableView;
@property(nonatomic) _Bool isExpand; // @synthesize isExpand=_isExpand;
@property(nonatomic) unsigned long long jobType; // @synthesize jobType=_jobType;
@property(retain, nonatomic) PartimeJobBean *jobBean; // @synthesize jobBean=_jobBean;
- (void).cxx_destruct;
- (void)deleteJob;
- (void)readOrderInfo;
- (void)mj_readData;
- (void)shareBtnHandler:(id)arg1;
- (void)readJobDetailInfo;
- (void)hideShareBtn;
- (void)showShareBtn;
- (void)refreshCommentSection;
- (void)moreBarItemClick:(id)arg1;
- (void)expandBtnClick:(id)arg1;
- (void)continuePayBtnClick:(id)arg1;
- (void)alertView:(id)arg1 buttonClick:(long long)arg2;
- (void)replayActionWith:(_Bool)arg1;
- (void)closePage;
- (void)commentButtonClick:(id)arg1;
- (void)tableView:(id)arg1 didSelectRowAtIndexPath:(id)arg2;
- (id)tableView:(id)arg1 cellForRowAtIndexPath:(id)arg2;
- (id)tableView:(id)arg1 viewForHeaderInSection:(long long)arg2;
- (double)tableView:(id)arg1 heightForFooterInSection:(long long)arg2;
- (double)tableView:(id)arg1 heightForHeaderInSection:(long long)arg2;
- (double)tableView:(id)arg1 heightForRowAtIndexPath:(id)arg2;
- (long long)tableView:(id)arg1 numberOfRowsInSection:(long long)arg2;
- (long long)numberOfSectionsInTableView:(id)arg1;
- (void)showJobFailureAlert;
- (void)toCommentPage:(id)arg1;
- (void)toComment:(id)arg1;
- (void)toWagePaymentPage;
- (void)jumpToPayPage:(id)arg1;
- (id)readWorkTimeSlot:(id)arg1;
- (void)shareJob;
- (void)showMap;
- (id)timeDicFromeTimeArray:(id)arg1;
- (void)showPartTimeJobWorkCalendar;
- (id)readWorkDate;
- (void)resolveJobDetail:(id)arg1;
- (void)configRightBarItem;
- (void)initView;
- (void)initData;
- (void)viewDidLoad;

// Remaining properties
@property(readonly, copy) NSString *debugDescription;
@property(readonly, copy) NSString *description;
@property(readonly) unsigned long long hash;
@property(readonly) Class superclass;

@end

