//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "NSObject.h"

@class JobBaseBean, JobPrepayInfoBean, NSArray, NSMutableArray, NSString, PartimeJobBean, SalaryInfoObj;

@protocol JobAndResumeManagerBaseViewControllerDelegate <NSObject>
- (void)pushToSignManagementViewController:(NSString *)arg1;
- (void)pushToSceneSigninViewController:(NSString *)arg1;
- (void)pushToPayrollBillVC:(PartimeJobBean *)arg1 salaryInfo:(SalaryInfoObj *)arg2;
- (void)pushToFlagShowVCWithFlag:(unsigned long long)arg1;
- (void)pushToNotificationVC:(NSString *)arg1 dataSource:(NSArray *)arg2 jobBean:(PartimeJobBean *)arg3 notificationType:(unsigned long long)arg4;
- (void)pushToCancelReasonVC:(JobBaseBean *)arg1;
- (void)pushToRemarkVC:(JobBaseBean *)arg1;
- (void)pushToJobPayVC:(NSMutableArray *)arg1 jobPayService:(unsigned long long)arg2;
- (void)pushToSignInRecordVC:(JobBaseBean *)arg1;
- (void)pushToResumeVC:(JobBaseBean *)arg1 resumeType:(unsigned long long)arg2 userResumeType:(long long)arg3;
- (void)pushToResumeSelectedViewCtrl:(NSString *)arg1 resumeSelectType:(unsigned long long)arg2 dataSource:(NSArray *)arg3 partimeJobBean:(PartimeJobBean *)arg4;
- (void)pushToPaySelectVCWithDatasource:(NSArray *)arg1;
- (void)pushToPrePayConditionVC:(JobPrepayInfoBean *)arg1 jobBean:(PartimeJobBean *)arg2;
- (void)jobAndResumeManager:(id)arg1 updateTotalCount:(long long)arg2;
@end

