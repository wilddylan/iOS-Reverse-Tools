//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "UIView.h"

@interface UIView (Extend)
- (void)distributeSpacingVerticallyWith:(id)arg1;
- (void)distributeSpacingHorizontallyWith:(id)arg1;
- (void)cleanSubViews;
- (void)tapGestureWithTarget:(id)arg1 action:(SEL)arg2;
- (id)addBottomFillLineWithColor:(struct CGColor *)arg1;
- (id)addTopFillLineWithColor:(struct CGColor *)arg1;
- (void)addTopAndBottomLineWithHeight:(float)arg1 color:(struct CGColor *)arg2;
- (void)addTopAndBottomLineWithColor:(struct CGColor *)arg1;
- (id)addSubLayerWithFrame:(struct CGRect)arg1 color:(struct CGColor *)arg2;
- (void)fill;
- (void)fillHeight;
- (void)fillWidth;
- (void)centerInView:(id)arg1;
- (void)centerInVertical:(id)arg1;
- (void)centerInHorizontal:(id)arg1;
- (void)setOrigin:(struct CGPoint)arg1;
- (void)setSize:(struct CGSize)arg1;
- (struct CGPoint)origin;
- (struct CGSize)size;
- (double)width;
- (double)height;
- (double)bottom;
- (double)y;
- (double)right;
- (double)x;
- (void)setY:(double)arg1;
- (void)setX:(double)arg1;
- (void)setHeight:(double)arg1;
- (void)setWidth:(double)arg1;
@end
