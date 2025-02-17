//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "BaseCell.h"

@class CommonCellModelBase, NSIndexPath;

@interface CommonCellBase : BaseCell
{
    id <CommonCellModelBaseGenerator> _generator;
    id _dataSource;
    CommonCellModelBase *_model;
    NSIndexPath *_indexPath;
}

+ (id)modelClassString;
@property(retain, nonatomic) NSIndexPath *indexPath; // @synthesize indexPath=_indexPath;
@property(readonly, nonatomic) CommonCellModelBase *model; // @synthesize model=_model;
@property(retain, nonatomic) id dataSource; // @synthesize dataSource=_dataSource;
@property(nonatomic) __weak id <CommonCellModelBaseGenerator> generator; // @synthesize generator=_generator;
- (void).cxx_destruct;

@end

