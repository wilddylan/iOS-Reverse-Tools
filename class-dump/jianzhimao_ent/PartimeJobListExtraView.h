//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "BaseView.h"

@class UIButton, UIImageView, UILabel, UIView;

@interface PartimeJobListExtraView : BaseView
{
    UIView *_contentView;
    UILabel *_timeLab;
    UILabel *_contentLab;
    UIImageView *_midLineView;
    UIView *_actionView;
    UIButton *_tel_serviceBtn;
    UIImageView *_actionVLineView;
    UIButton *_tel_leaderBtn;
}

@property(retain, nonatomic) UIButton *tel_leaderBtn; // @synthesize tel_leaderBtn=_tel_leaderBtn;
@property(retain, nonatomic) UIImageView *actionVLineView; // @synthesize actionVLineView=_actionVLineView;
@property(retain, nonatomic) UIButton *tel_serviceBtn; // @synthesize tel_serviceBtn=_tel_serviceBtn;
@property(retain, nonatomic) UIView *actionView; // @synthesize actionView=_actionView;
@property(retain, nonatomic) UIImageView *midLineView; // @synthesize midLineView=_midLineView;
@property(retain, nonatomic) UILabel *contentLab; // @synthesize contentLab=_contentLab;
@property(retain, nonatomic) UILabel *timeLab; // @synthesize timeLab=_timeLab;
@property(retain, nonatomic) UIView *contentView; // @synthesize contentView=_contentView;
- (void).cxx_destruct;
- (void)layoutSubviews;
- (double)heightForExtraView;
- (id)init;

@end
