//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "UITableViewCell.h"

@class UIButton;

@interface ButtonFooterCell : UITableViewCell
{
    id <ButtonFooterCellDelegate> _delegate;
    UIButton *_footerBtn;
}

@property(nonatomic) __weak UIButton *footerBtn; // @synthesize footerBtn=_footerBtn;
@property(nonatomic) __weak id <ButtonFooterCellDelegate> delegate; // @synthesize delegate=_delegate;
- (void).cxx_destruct;
- (void)footerBtnClick:(id)arg1;
- (void)setSelected:(_Bool)arg1 animated:(_Bool)arg2;
- (void)awakeFromNib;

@end

