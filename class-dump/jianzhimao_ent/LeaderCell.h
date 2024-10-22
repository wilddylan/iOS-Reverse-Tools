//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "BaseCell.h"

@class JobTypeImageView, UIImageView, UILabel, UIView;

@interface LeaderCell : BaseCell
{
    UIView *_midView;
    UILabel *_priceLab;
    JobTypeImageView *_logoView;
    UILabel *_titleLab;
    UIImageView *_addressLogoView;
    UILabel *_addressLab;
    UIImageView *_timeLogoView;
    UILabel *_timeLab;
}

+ (double)cellHeight;
@property(retain, nonatomic) UILabel *timeLab; // @synthesize timeLab=_timeLab;
@property(retain, nonatomic) UIImageView *timeLogoView; // @synthesize timeLogoView=_timeLogoView;
@property(retain, nonatomic) UILabel *addressLab; // @synthesize addressLab=_addressLab;
@property(retain, nonatomic) UIImageView *addressLogoView; // @synthesize addressLogoView=_addressLogoView;
@property(retain, nonatomic) UILabel *titleLab; // @synthesize titleLab=_titleLab;
@property(retain, nonatomic) JobTypeImageView *logoView; // @synthesize logoView=_logoView;
@property(retain, nonatomic) UILabel *priceLab; // @synthesize priceLab=_priceLab;
@property(retain, nonatomic) UIView *midView; // @synthesize midView=_midView;
- (void).cxx_destruct;
- (void)buildView:(id)arg1;
- (id)initWithStyle:(long long)arg1 reuseIdentifier:(id)arg2;

@end

