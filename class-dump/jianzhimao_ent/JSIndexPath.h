//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "NSObject.h"

@interface JSIndexPath : NSObject
{
    long long _column;
    long long _leftOrRight;
    long long _leftRow;
    long long _row;
}

+ (id)indexPathWithCol:(long long)arg1 leftOrRight:(long long)arg2 leftRow:(long long)arg3 row:(long long)arg4;
@property(nonatomic) long long row; // @synthesize row=_row;
@property(nonatomic) long long leftRow; // @synthesize leftRow=_leftRow;
@property(nonatomic) long long leftOrRight; // @synthesize leftOrRight=_leftOrRight;
@property(nonatomic) long long column; // @synthesize column=_column;
- (id)initWithColumn:(long long)arg1 leftOrRight:(long long)arg2 leftRow:(long long)arg3 row:(long long)arg4;

@end

