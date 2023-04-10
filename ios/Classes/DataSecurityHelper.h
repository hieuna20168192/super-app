//
//  DataSecurityHelper.h
//  CoreLegacyKit
//
//  Created by Natariannn on 8/26/20.
//  Copyright © 2020 ViettelPay App Team. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface DataSecurityHelper : NSObject

+ (NSData *)base64DecodeString:(NSString *)string;

+ (NSString *)base64EncodeData:(NSData *)data;
+ (NSString * _Nullable)encryptString:(NSString *)string withPublicKeyData:(NSData *)publicKeyData;
+ (NSString * _Nullable)decryptString:(NSString *)string withPrivateKeyData:(NSData *)privateKeyData;
+ (NSString * _Nullable)signString:(NSString *)string withPrivateKeyData:(NSData *)privateKeyData;

+ (BOOL)verifyString:(NSString *)string withPublicKeyData:(NSData *)publicKeyData signature:(NSString *)signature;

@end

NS_ASSUME_NONNULL_END
