//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "NSObject.h"

@class XLPagerTabStripViewController;

@protocol XLPagerTabStripViewControllerDelegate <NSObject>

@optional
- (void)pagerTabStripViewController:(XLPagerTabStripViewController *)arg1 updateIndicatorFromIndex:(long long)arg2 toIndex:(long long)arg3 withProgressPercentage:(double)arg4 indexWasChanged:(_Bool)arg5;
- (void)pagerTabStripViewController:(XLPagerTabStripViewController *)arg1 updateIndicatorFromIndex:(long long)arg2 toIndex:(long long)arg3;
@end

