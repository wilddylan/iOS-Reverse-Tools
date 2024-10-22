//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "EMChatBaseBubbleView.h"

@class NSArray, NSDataDetector, UIImageView, UILabel;

@interface ChatConsultBubbleView : EMChatBaseBubbleView
{
    NSDataDetector *_detector;
    NSArray *_urlMatches;
    UIImageView *_cousultNewBgView;
    UILabel *_cousultNewLab;
    UIImageView *_contentBgView;
    UILabel *_contentLab;
    UIImageView *_logoView;
}

+ (long long)textLabelLineBreakModel;
+ (double)lineSpacing;
+ (id)textLabelFont;
+ (double)heightForBubbleWithObject:(id)arg1;
@property(retain, nonatomic) UIImageView *logoView; // @synthesize logoView=_logoView;
@property(retain, nonatomic) UILabel *contentLab; // @synthesize contentLab=_contentLab;
@property(retain, nonatomic) UIImageView *contentBgView; // @synthesize contentBgView=_contentBgView;
@property(retain, nonatomic) UILabel *cousultNewLab; // @synthesize cousultNewLab=_cousultNewLab;
@property(retain, nonatomic) UIImageView *cousultNewBgView; // @synthesize cousultNewBgView=_cousultNewBgView;
- (void).cxx_destruct;
- (void)bubbleViewPressed:(id)arg1;
- (long long)characterIndexAtPoint:(struct CGPoint)arg1;
- (void)highlightLinksWithIndex:(long long)arg1;
- (_Bool)isIndex:(long long)arg1 inRange:(struct _NSRange)arg2;
- (void)setModel:(id)arg1;
- (struct CGSize)sizeThatFits:(struct CGSize)arg1;
- (void)layoutSubviews;
- (id)initWithFrame:(struct CGRect)arg1;

@end

