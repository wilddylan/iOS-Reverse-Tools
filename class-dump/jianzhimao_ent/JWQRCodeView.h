//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "UIImageView.h"

@interface JWQRCodeView : UIImageView
{
    UIImageView *_iconView;
    struct CGSize _qrSize;
}

@property(nonatomic) struct CGSize qrSize; // @synthesize qrSize=_qrSize;
@property(retain, nonatomic) UIImageView *iconView; // @synthesize iconView=_iconView;
- (void).cxx_destruct;
- (void)updateQRCode:(id)arg1;
- (void)setupView:(struct CGSize)arg1;
- (id)initWithSize:(struct CGSize)arg1;
- (id)initWithFrame:(struct CGRect)arg1;

@end

