//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "UIView.h"

@class BTGAvatarView, UIButton, UILongPressGestureRecognizer;

@interface BTGContextMenuItem : UIView
{
    _Bool _supportLongPress;
    int _type;
    id <BTGContextMenuItemDelegate> _delegate;
    UIButton *_imageButton;
    BTGAvatarView *_avatarView;
    UILongPressGestureRecognizer *_longPressGesture;
    struct CGPoint _startPoint;
    struct CGPoint _endPoint;
    struct CGPoint _nearPoint;
    struct CGPoint _farPoint;
}

+ (id)itemWithImage:(id)arg1 highlightedImage:(id)arg2;
@property(nonatomic) __weak UILongPressGestureRecognizer *longPressGesture; // @synthesize longPressGesture=_longPressGesture;
@property(retain, nonatomic) BTGAvatarView *avatarView; // @synthesize avatarView=_avatarView;
@property(retain, nonatomic) UIButton *imageButton; // @synthesize imageButton=_imageButton;
@property(nonatomic) struct CGPoint farPoint; // @synthesize farPoint=_farPoint;
@property(nonatomic) struct CGPoint nearPoint; // @synthesize nearPoint=_nearPoint;
@property(nonatomic) struct CGPoint endPoint; // @synthesize endPoint=_endPoint;
@property(nonatomic) struct CGPoint startPoint; // @synthesize startPoint=_startPoint;
@property(nonatomic) _Bool supportLongPress; // @synthesize supportLongPress=_supportLongPress;
@property(nonatomic) int type; // @synthesize type=_type;
@property(nonatomic) __weak id <BTGContextMenuItemDelegate> delegate; // @synthesize delegate=_delegate;
- (void).cxx_destruct;
- (void)onButtonClick:(id)arg1;
- (void)handleGesture:(id)arg1;
- (id)initWithImage:(id)arg1 highlightedImage:(id)arg2;

@end

