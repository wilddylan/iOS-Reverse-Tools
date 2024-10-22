//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "NSObject.h"

@class ITTCalDay, ITTCalMonth, ITTCalendarGridView, ITTCalendarView, ITTCalendarViewFooterView, ITTCalendarViewHeaderView, NSArray, NSString;

@protocol ITTCalendarViewDataSource <NSObject>

@optional
- (ITTCalendarViewFooterView *)footerViewForCalendarView:(ITTCalendarView *)arg1;
- (ITTCalendarViewHeaderView *)headerViewForCalendarView:(ITTCalendarView *)arg1;
- (ITTCalendarGridView *)calendarView:(ITTCalendarView *)arg1 calendarDisableGridViewForRow:(long long)arg2 column:(long long)arg3 calDay:(ITTCalDay *)arg4;
- (ITTCalendarGridView *)calendarView:(ITTCalendarView *)arg1 calendarGridViewForRow:(long long)arg2 column:(long long)arg3 calDay:(ITTCalDay *)arg4;
- (NSString *)calendarView:(ITTCalendarView *)arg1 titleForMonth:(ITTCalMonth *)arg2;
- (NSArray *)weekTitlesForCalendarView:(ITTCalendarView *)arg1;
@end

