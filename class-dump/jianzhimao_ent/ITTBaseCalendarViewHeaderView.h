//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "ITTCalendarViewHeaderView.h"

@class UILabel;

@interface ITTBaseCalendarViewHeaderView : ITTCalendarViewHeaderView
{
    UILabel *monthLabel;
}

@property(retain, nonatomic) UILabel *monthLabel; // @synthesize monthLabel;
- (void).cxx_destruct;
- (void)setTitle:(id)arg1;
- (void)onNextMonthButtonTouched:(id)arg1;
- (void)onPreviousMonthButtonTouched:(id)arg1;
- (void)onChoseDateButtonTouched:(id)arg1;
- (void)onCancelChoseDateButtonTouched:(id)arg1;

@end

