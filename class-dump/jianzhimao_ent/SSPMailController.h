//
//     Generated by class-dump 3.5 (64 bit).
//
//     class-dump is Copyright (C) 1997-1998, 2000-2001, 2004-2013 by Steve Nygard.
//

#import "NSObject.h"

@class NSArray, NSString, UIWindow;

@interface SSPMailController : NSObject
{
    NSString *_text;
    NSString *_title;
    NSArray *_attachment;
    NSArray *_recipients;
    NSArray *_cc;
    NSArray *_bcc;
    CDUnknownBlockType _resultHandler;
    UIWindow *_window;
    UIWindow *_lastwindow;
}

@property(retain, nonatomic) UIWindow *lastwindow; // @synthesize lastwindow=_lastwindow;
@property(retain, nonatomic) UIWindow *window; // @synthesize window=_window;
@property(copy, nonatomic) CDUnknownBlockType resultHandler; // @synthesize resultHandler=_resultHandler;
@property(retain, nonatomic) NSArray *bcc; // @synthesize bcc=_bcc;
@property(retain, nonatomic) NSArray *cc; // @synthesize cc=_cc;
@property(retain, nonatomic) NSArray *recipients; // @synthesize recipients=_recipients;
@property(retain, nonatomic) NSArray *attachment; // @synthesize attachment=_attachment;
@property(copy, nonatomic) NSString *title; // @synthesize title=_title;
@property(copy, nonatomic) NSString *text; // @synthesize text=_text;
- (void).cxx_destruct;
- (void)onResult:(CDUnknownBlockType)arg1;
- (void)send;
- (void)dealloc;
- (id)initWithText:(id)arg1 title:(id)arg2 attachment:(id)arg3 recipients:(id)arg4 cc:(id)arg5 bcc:(id)arg6;

@end

