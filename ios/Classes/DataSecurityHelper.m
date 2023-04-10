//
//  DataSecurityHelper.m
//  CoreLegacyKit
//
//  Created by Natariannn on 8/26/20.
//  Copyright © 2020 ViettelPay App Team. All rights reserved.
//

#import "DataSecurityHelper.h"
#import <openssl/rsa.h>
#import <openssl/x509.h>
#import <openssl/err.h>

@implementation DataSecurityHelper

+ (NSData *)base64DecodeString:(NSString *)string {
    unsigned long ixtext, lentext;
    unsigned char ch, inbuf[4], outbuf[3];
    short i, ixinbuf;
    Boolean flignore, flendtext = NO;
    const unsigned char *tempcstring;
    NSMutableData *theData;
    
    if (string == nil) {
        return [NSData data];
    }
    
    ixtext = 0;
    
    tempcstring = (const unsigned char *)[string UTF8String];
    
    lentext = [string length];
    
    theData = [NSMutableData dataWithCapacity: lentext];
    
    ixinbuf = 0;
    
    while (YES) {
        if (ixtext >= lentext) {
            break;
        }
        
        ch = tempcstring [ixtext++];
        
        flignore = NO;
        
        if ((ch >= 'A') && (ch <= 'Z')) {
            ch = ch - 'A';
        } else if ((ch >= 'a') && (ch <= 'z')) {
            ch = ch - 'a' + 26;
        } else if ((ch >= '0') && (ch <= '9')) {
            ch = ch - '0' + 52;
        } else if (ch == '+') {
            ch = 62;
        } else if (ch == '=') {
            flendtext = YES;
        } else if (ch == '/') {
            ch = 63;
        } else {
            flignore = YES;
        }
        
        if (!flignore) {
            short ctcharsinbuf = 3;
            Boolean flbreak = NO;
            
            if (flendtext) {
                if (ixinbuf == 0) {
                    break;
                }
                
                if ((ixinbuf == 1) || (ixinbuf == 2)) {
                    ctcharsinbuf = 1;
                } else {
                    ctcharsinbuf = 2;
                }
                
                ixinbuf = 3;
                flbreak = YES;
            }
            
            inbuf [ixinbuf++] = ch;
            
            if (ixinbuf == 4) {
                ixinbuf = 0;
                
                outbuf[0] = (inbuf[0] << 2) | ((inbuf[1] & 0x30) >> 4);
                outbuf[1] = ((inbuf[1] & 0x0F) << 4) | ((inbuf[2] & 0x3C) >> 2);
                outbuf[2] = ((inbuf[2] & 0x03) << 6) | (inbuf[3] & 0x3F);
                
                for (i = 0; i < ctcharsinbuf; i++) {
                    [theData appendBytes: &outbuf[i] length: 1];
                }
            }
            
            if (flbreak) {
                break;
            }
        }
    }
    
    return theData;
}

+ (NSString *)base64EncodeData:(NSData *)data {
    //Point to start of the data and set buffer sizes
    NSInteger inLength = [data length];
    NSInteger outLength = ((((inLength * 4)/3)/4)*4) + (((inLength * 4)/3)%4 ? 4 : 0);
    const char *inputBuffer = [data bytes];
    char *outputBuffer = malloc(outLength);
    outputBuffer[outLength] = 0;
    
    //64 digit code
    static char Encode[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    //start the count
    int cycle = 0;
    int inpos = 0;
    int outpos = 0;
    char temp;
    
    //Pad the last to bytes, the outbuffer must always be a multiple of 4
    outputBuffer[outLength-1] = '=';
    outputBuffer[outLength-2] = '=';
    
    /* http://en.wikipedia.org/wiki/Base64
     Text content   M           a           n
     ASCII          77          97          110
     8 Bit pattern  01001101    01100001    01101110
     
     6 Bit pattern  010011  010110  000101  101110
     Index          19      22      5       46
     Base64-encoded T       W       F       u
     */
    
    
    while (inpos < inLength){
        switch (cycle) {
            case 0:
                outputBuffer[outpos++] = Encode[(inputBuffer[inpos]&0xFC)>>2];
                cycle = 1;
                break;
            case 1:
                temp = (inputBuffer[inpos++]&0x03)<<4;
                outputBuffer[outpos] = Encode[temp];
                cycle = 2;
                break;
            case 2:
                outputBuffer[outpos++] = Encode[temp|(inputBuffer[inpos]&0xF0)>> 4];
                temp = (inputBuffer[inpos++]&0x0F)<<2;
                outputBuffer[outpos] = Encode[temp];
                cycle = 3;
                break;
            case 3:
                outputBuffer[outpos++] = Encode[temp|(inputBuffer[inpos]&0xC0)>>6];
                cycle = 4;
                break;
            case 4:
                outputBuffer[outpos++] = Encode[inputBuffer[inpos++]&0x3f];
                cycle = 0;
                break;
            default:
                cycle = 0;
                break;
        }
    }
    NSString *pictemp = [NSString stringWithUTF8String:outputBuffer];
    free(outputBuffer);
    return pictemp;
}

+ (NSString * _Nullable)encryptString:(NSString *)string withPublicKeyData:(NSData *)publicKeyData {
    if (!publicKeyData || publicKeyData.length < 1) {
        return nil;
    }
    
    const char *msgInChar = [string UTF8String];
    BIO *in1 =  BIO_new_mem_buf((void *)[publicKeyData bytes], [publicKeyData length]);
    RSA *rsa = d2i_RSA_PUBKEY_bio(in1, NULL);
    if (rsa == nil) {
        return nil;
    }
    //    NSLog(@"ErrorCodePublicKey: %ld", ERR_get_error());
    
    BIO_free(in1);
    uint8_t * cipherBuffer = NULL;

    // Calculate the buffer sizes.
    unsigned int cipherBufferSize = RSA_size(rsa); //128
    // unsigned int cipherBufferSize = 10000;
    
    int blocksize = RSA_size(rsa) - 42; //86
    NSInteger maxsize = strlen(msgInChar); //1676
    NSInteger maxindex = maxsize / blocksize; //19
    
    NSMutableString *result = [[NSMutableString alloc] init];
    for (int i = 0; i <= maxindex; i ++)  {
        NSInteger length = maxsize - i * blocksize;
        if (length > blocksize) {
            length = blocksize;
        }
        cipherBuffer = malloc(10000);
        memset((void *)cipherBuffer, 0x0, cipherBufferSize);
        unsigned char * msg = (unsigned char *)(msgInChar + i * blocksize);
        
        int success = RSA_public_encrypt(length, (unsigned char *)(msgInChar + i * blocksize), cipherBuffer, rsa, RSA_PKCS1_PADDING);
        if (success) {
            // NSLog(@"win");
        } else {
            continue;
        }
        
        NSData *signedString = [NSData dataWithBytes:(const void *)cipherBuffer length:cipherBufferSize];
        NSMutableData *data = [[NSMutableData alloc] init];
        
        for (int i = 0; i < [signedString length]; i ++) {
            [data appendData:[signedString subdataWithRange:NSMakeRange([signedString length] - i - 1, 1)]];
        }
        
        NSLog(@"%@",[self base64EncodeData:data]);
        
        [result appendString:[self base64EncodeData:data]];
    }
    
    return result;
}

+ (NSString * _Nullable)decryptString:(NSString *)string withPrivateKeyData:(NSData *)privateKeyData {
    if (!privateKeyData || privateKeyData.length < 1) {
        return nil;
    }
    
    @try {
        BIO *in1 = BIO_new_mem_buf((void *)[privateKeyData bytes], [privateKeyData length]);
        PKCS8_PRIV_KEY_INFO *p8inf = d2i_PKCS8_PRIV_KEY_INFO_bio(in1, NULL);
        EVP_PKEY *pkey = EVP_PKCS82PKEY(p8inf);
        PKCS8_PRIV_KEY_INFO_free(p8inf);
        BIO_free(in1);
        
        uint8_t *cipherBuffer = NULL;
        
        unsigned int cipherBufferSize = RSA_size(pkey->pkey.rsa);
        int base64BlockSize = (cipherBufferSize % 3) != 0 ? ((cipherBufferSize / 3) * 4) + 4 : (cipherBufferSize / 3) * 4;
        NSInteger maxIndex = ([string length]) / base64BlockSize;
        NSMutableString *result = [[NSMutableString alloc] init];
        NSMutableData *mydata = [[NSMutableData alloc] init];
        for (int i = 0; i < maxIndex; i ++) {
            NSString *subString = [string substringWithRange:NSMakeRange(i * base64BlockSize, base64BlockSize)];
            NSData *subStringData = [self base64DecodeString:subString];
            NSMutableData *data = [[NSMutableData alloc] init];
            for (int i = 0; i < [subStringData length]; i ++) {
                [data appendData:[subStringData subdataWithRange:NSMakeRange([subStringData length] - i - 1, 1)]];
            }
            unsigned char* msgInChar = (unsigned char *)[data bytes];
            
            cipherBuffer = malloc(cipherBufferSize);
            memset((void *)cipherBuffer, 0x0, cipherBufferSize);
            int success = RSA_private_decrypt(RSA_size(pkey->pkey.rsa), msgInChar, cipherBuffer, pkey->pkey.rsa, RSA_PKCS1_PADDING);
            
            if (success != -1) {
                if (cipherBuffer != nil) {
                    NSData *signedString = [NSData dataWithBytes:(const void *)cipherBuffer length:success];
                    if (signedString != nil) {
                        [mydata appendData:signedString];
                    }
                }
            }
        }
        if (mydata != nil) {
            NSString *strTemp = [[NSString alloc] initWithData:mydata encoding:NSUTF8StringEncoding];
            [result appendString:strTemp == nil? @"":strTemp];
        }
        
        EVP_PKEY_free(pkey);
        return [result stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@" "]];
    }
    
    @catch (NSException *exception) {
    }
    
    @finally {
    }
}

+ (NSString * _Nullable)signString:(NSString *)string withPrivateKeyData:(NSData *)privateKeyData {
    if (!privateKeyData || privateKeyData.length < 1) {
        return nil;
    }
    NSData *signableData = [string dataUsingEncoding:NSUTF8StringEncoding];
    BIO *in1 =  BIO_new_mem_buf((void *)[privateKeyData bytes], [privateKeyData length]);
    
    PKCS8_PRIV_KEY_INFO *p8inf = d2i_PKCS8_PRIV_KEY_INFO_bio(in1, NULL);
    EVP_PKEY *pkey = EVP_PKCS82PKEY(p8inf);
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    BIO_free(in1);
    
    uint8_t * cipherBuffer = NULL;
    
    unsigned int cipherBufferSize = RSA_size(pkey->pkey.rsa);
    unsigned int signatureLength;
    
    cipherBuffer = malloc(cipherBufferSize);
    memset((void *)cipherBuffer, 0x0, cipherBufferSize);
    
    unsigned char *openSSLHash = SHA1(signableData.bytes, signableData.length, NULL);
    RSA_sign(NID_sha1, openSSLHash, 20, cipherBuffer, &signatureLength, pkey->pkey.rsa);
    
    NSData *signedData = [NSData dataWithBytes:(const void*)cipherBuffer length:signatureLength];
    
    EVP_PKEY_free(pkey);
    return [self base64EncodeData:signedData];
}

+ (BOOL)verifyString:(NSString *)string withPublicKeyData:(NSData *)publicKeyData signature:(NSString *)signature {
    if (!publicKeyData || publicKeyData.length < 1 || !signature || [signature length] < 1) {
        return NO;
    }
    
    NSData *signableData = [string dataUsingEncoding:NSUTF8StringEncoding];
    BIO *in1 = BIO_new(BIO_s_mem());
    BIO_write(in1, publicKeyData.bytes, publicKeyData.length);
    RSA *rsa = d2i_RSA_PUBKEY_bio(in1, NULL);
    BIO_free(in1);
    
    const unsigned char *openSSLHash = SHA1(signableData.bytes, signableData.length, NULL);
    NSInteger result = RSA_verify(NID_sha1, openSSLHash, 20, [[self base64DecodeString:signature] bytes], [[self base64DecodeString:signature] length], rsa);
    return result;
}

@end
