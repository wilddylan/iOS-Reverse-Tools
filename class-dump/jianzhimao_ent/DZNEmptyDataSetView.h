//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "UIView.h"

@class UIButton, UIImageView, UILabel, UITapGestureRecognizer;

@interface DZNEmptyDataSetView : UIView
{
    UIView *_contentView;
    UILabel *_titleLabel;
    UILabel *_detailLabel;
    UIImageView *_imageView;
    UIButton *_button;
    UIView *_customView;
    UITapGestureRecognizer *_tapGesture;
    double _verticalOffset;
    double _verticalSpace;
}

@property(nonatomic) double verticalSpace; // @synthesize verticalSpace=_verticalSpace;
@property(nonatomic) double verticalOffset; // @synthesize verticalOffset=_verticalOffset;
@property(retain, nonatomic) UITapGestureRecognizer *tapGesture; // @synthesize tapGesture=_tapGesture;
@property(retain, nonatomic) UIView *customView; // @synthesize customView=_customView;
- (void).cxx_destruct;
- (id)hitTest:(struct CGPoint)arg1 withEvent:(id)arg2;
- (void)setupConstraints;
- (void)prepareForReuse;
- (void)removeAllConstraints;
- (void)didTapButton:(id)arg1;
- (_Bool)canShowButton;
- (_Bool)canShowDetail;
- (_Bool)canShowTitle;
- (_Bool)canShowImage;
@property(readonly, nonatomic) UIButton *button; // @synthesize button=_button;
@property(readonly, nonatomic) UILabel *detailLabel; // @synthesize detailLabel=_detailLabel;
@property(readonly, nonatomic) UILabel *titleLabel; // @synthesize titleLabel=_titleLabel;
@property(readonly, nonatomic) UIImageView *imageView; // @synthesize imageView=_imageView;
@property(readonly, nonatomic) UIView *contentView; // @synthesize contentView=_contentView;
- (void)didMoveToSuperview;
- (id)init;

@end

