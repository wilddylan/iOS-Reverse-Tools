//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "UITableViewCell.h"

#import "ViewModelAction.h"

@class NSString, UIImageView, ViewModelBase;

@interface BaseCell : UITableViewCell <ViewModelAction>
{
    double _cellHeight;
    UIImageView *_bottomLine;
    UIImageView *_rightArrawView;
    ViewModelBase *_viewModel;
}

+ (id)identifier;
@property(retain, nonatomic) ViewModelBase *viewModel; // @synthesize viewModel=_viewModel;
@property(retain, nonatomic) UIImageView *rightArrawView; // @synthesize rightArrawView=_rightArrawView;
@property(retain, nonatomic) UIImageView *bottomLine; // @synthesize bottomLine=_bottomLine;
@property(nonatomic) double cellHeight; // @synthesize cellHeight=_cellHeight;
- (void).cxx_destruct;
- (void)setSelected:(_Bool)arg1 animated:(_Bool)arg2;
- (void)awakeFromNib;
- (void)layoutSubviews;
- (void)setupUI;
- (void)cleanView;
- (void)buildView:(id)arg1;
- (id)initWithStyle:(long long)arg1 reuseIdentifier:(id)arg2;

// Remaining properties
@property(readonly, copy) NSString *debugDescription;
@property(readonly, copy) NSString *description;
@property(readonly) unsigned long long hash;
@property(readonly) Class superclass;

@end

