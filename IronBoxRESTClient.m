//
//  IronBoxRESTClient.m
//  ClientDemo
//
//  Created by Weipin Xia on 11/30/13.
//  Copyright (c) 2013 IronBox. All rights reserved.
//

#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

#import "IronBoxRESTClient.h"

NSString *const IronBoxErrorDomain = @"IronBoxError";

NSString *EscapeStringForURLArgument(NSString *str) {
    CFStringRef escaped =
    CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault,
                                            (CFStringRef)str,
                                            NULL,
                                            (CFStringRef)@"!*'();:@&=+$,/?%#[]",
                                            kCFStringEncodingUTF8);
    return CFBridgingRelease(escaped);
}

NSString *FormencodeDictionary(NSDictionary *dict) {
    NSMutableArray *result = [NSMutableArray array];
    [dict enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
        NSString *str = [NSString stringWithFormat:@"%@=%@", key, EscapeStringForURLArgument(obj)];
        [result addObject:str];
    }];

    return [result componentsJoinedByString:@"&"];
}


//------------------------------------------------------------------
//   IronBox key data class
//------------------------------------------------------------------
@interface IronBoxKeyData : NSObject

@property (readwrite, retain) NSData *symmetricKey;
@property (readwrite, retain) NSData *IV;

// Symmetric key strength 0 = none, 1 = 128 and 2 = 256
@property (readwrite, assign) int keyStrength;

- (BOOL)encryptFile:(NSString *)inFilename
        outFilename:(NSString *)outFilename
              error:(NSError **)error;

@end


@implementation IronBoxKeyData

- (instancetype)init {
    if (self = [super init]) {
        self.keyStrength = 2;
    }
    return self;
}

- (BOOL)encryptFile:(NSString *)inFilename
        outFilename:(NSString *)outFilename
              error:(NSError **)error {
    CCCryptorRef cryptor = NULL;
    CCCryptorStatus status = kCCSuccess;

    status = CCCryptorCreate(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
                             [self.symmetricKey bytes], [self.symmetricKey length],
                             [self.IV bytes], &cryptor);
    if ( status != kCCSuccess ) {
        return NO;
    }

    NSFileHandle *inHandle = [NSFileHandle fileHandleForReadingFromURL:[NSURL fileURLWithPath:inFilename] error:error];
    if (inHandle == nil) {
        CCCryptorRelease(cryptor);
        return NO;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    [fm removeItemAtPath:outFilename error:NULL];
    if (![fm createFileAtPath:outFilename contents:[NSData data] attributes:nil]) {
        NSError *e = [NSError errorWithDomain:IronBoxErrorDomain
                                         code:IronBoxErrorFileCannotCreateType
                                     userInfo:nil];
        if (error) {
            *error = e;
        }
        return NO;
    }

    NSFileHandle *outHandle = [NSFileHandle fileHandleForWritingToURL:[NSURL fileURLWithPath:outFilename] error:error];
    if (outHandle == nil) {
        CCCryptorRelease(cryptor);
        return NO;
    }

    BOOL ret = NO;
    unsigned long long offset = 0;
    while (1) {
        [inHandle seekToFileOffset:offset];
        NSData *inData = [inHandle readDataOfLength:1024];

        if (0 == [inData length]) {
            size_t size = CCCryptorGetOutputLength(cryptor, 0, true);
            if (0 == size) {
                ret = YES;
                break;
            }

            void *buf = malloc(size);
            size_t movedSize = 0;
            status = CCCryptorFinal(cryptor, buf, size, &movedSize);
            if (status != kCCSuccess) {
                break;
            }
            NSData *outData = [[NSData alloc] initWithBytes:buf length:size];
            [outHandle writeData:outData];
            ret = YES;
            break;
        }

        size_t size = CCCryptorGetOutputLength(cryptor, [inData length], false);
        void *buf = malloc(size);
        size_t movedSize = 0;
        status = CCCryptorUpdate(cryptor, [inData bytes], [inData length], buf, size, &movedSize);
        if (status != kCCSuccess) {
            break;
        }
        NSData *outData = [[NSData alloc] initWithBytes:buf length:size];
        [outHandle writeData:outData];

        offset += [inData length];
    }

    CCCryptorRelease(cryptor);
    return ret;
}

@end


//------------------------------------------------------------------
//   Class to hold IronBox blob check out data
//------------------------------------------------------------------
@interface IronBoxBlobCheckOutData : NSObject

@property (readwrite, copy) NSString *sharedAccessSignature;
@property (readwrite, copy) NSString *SharedAccessSignatureURI;
@property (readwrite, copy) NSString *checkInToken;
@property (readwrite, copy) NSString *storageURI;
@property (readwrite, assign) int storageType; // # always set to 1
@property (readwrite, copy) NSString *containerStorageName;

@end

@implementation IronBoxBlobCheckOutData

@end



@interface IronBoxRESTClient () {
    NSURLSession *_dataSession;
    NSURLSession *_uploadSession;
}

@property (readwrite, copy) NSString *version;
@property (readonly) NSURLSession *dataSession;
@property (readonly) NSURLSession *uploadSession;

@end


@implementation IronBoxRESTClient

@dynamic dataSession;
@dynamic uploadSession;

- (instancetype)init {
    return [self initWithEntity:nil password:nil];
}

- (instancetype)initWithEntity:(NSString *)entity password:(NSString *)password {
    if ( (self = [super init])) {
        _entity = entity;
        _password = password;
        _type = 0;
        _version = @"latest";
        _contentFormat = @"application/json";
        _verbose = NO;
        _blockSizeMB = 4.0;

        _APIServerURL = @"https://api.goironcloud.com/latest/";
    }
    return self;
}

#pragma mark - Accessor

- (NSURLSession *)dataSession {
    if (_dataSession) {
        return _dataSession;
    }

    NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration defaultSessionConfiguration];
    _dataSession = [NSURLSession sessionWithConfiguration:configuration];
    return _dataSession;
}

- (NSURLSession *)uploadSession {
    if (_uploadSession) {
        return _uploadSession;
    }

    NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration defaultSessionConfiguration];
    _uploadSession = [NSURLSession sessionWithConfiguration:configuration];
    return _uploadSession;
}

#pragma mark - Major Methods

- (void)upload:(NSString *)filePath
   containerID:(NSString *)containerID
      blobName:(NSString *)blobName
            completionHandler:(void (^)(NSError *error, NSString *reason))completionHandler {
    if (self.entity == nil || self.password == nil) {
        NSError *e = [NSError errorWithDomain:IronBoxErrorDomain
                                         code:IronBoxErrorInvalidCredentialsType
                                     userInfo:nil];
        completionHandler(e, @"Entity and password cannot be empty.");
        return;
    }
//----------------------------
//   Step 1:
//   Test to make sure that the API server is accessible
//----------------------------
    [self ping:^(NSURLResponse *response, NSError *error) {
        if (error != nil) {
            NSLog(@"IronBox API server is not responding, or is not accessible from this network location");
            completionHandler(error, @"IronBox API server is not accessible from this network location");
            return;
        }
        [self consoleLog:@"IronBox API is up, starting transfer"];

//----------------------------
//   Step 2:
//   Get the container key data
//----------------------------
        [self keyData:containerID
           completion:^(NSURLResponse *response, IronBoxKeyData *keyData, NSError *error) {
               if (error != nil) {
                   completionHandler(error, @"Unable to retrieve container key data");
                   return;
               }

               [self consoleLog:@"Retrieving container symmetric key data"];

//----------------------------
//   Step 3:
//   Create a container blob and check it out.
//   This doesn't actually upload the contents, just
//   creates the entry, and does a "check out" which
//   lets IronBox know you're going to upload contents
//   soon.  As part of the checkout process you'll get a
//   check in token that is your way to check the
//   blob back in.
//----------------------------
               [self createBlobName:blobName
                        containerID:containerID
                         completion:^(NSURLResponse *response, NSString *blobIDName, NSError *error) {
                             if (error != nil) {
                                 completionHandler(error, @"Unable to create blob in container");
                                 return;
                             }

                             [self checkout:containerID
                                 blobIDName:blobIDName
                                 completion:^(NSURLResponse *response, IronBoxBlobCheckOutData *checkoutData, NSError *error) {
                                     if (error != nil) {
                                         completionHandler(error, @"Unable to checkout container blob");
                                         return;
                                     }

//----------------------------
//   Step 4:
//   Make a copy of the file and encrypt it
//----------------------------
                                     [self consoleLog:[NSString stringWithFormat:@"Encrypting a copy of %@", filePath]];
                                     NSFileManager *fm = [NSFileManager defaultManager];
                                     NSError *e = nil;
                                     NSDictionary *dict = [fm attributesOfItemAtPath:filePath error:&e];
                                     if (dict == nil) {
                                         completionHandler(e, @"Unable to get attributes of file");
                                         return;
                                     }
                                     unsigned long long originalFileSize = [dict fileSize];
                                     NSString *encryptedFilePath = [filePath stringByAppendingPathExtension:@".ironbox"];
                                     BOOL result = [keyData encryptFile:filePath outFilename:encryptedFilePath error:&e];
                                     if (!result) {
                                         completionHandler(e, @"Unable to encrypt local copy of file");
                                         return;
                                     }

//----------------------------
//   Step 5:
//   Upload the encrypted file using the shared
//   acccess signature we got at checkout
//   Use python-requests, since it's file upload is
//   more advanced.
//----------------------------
                                     [self consoleLog:[NSString stringWithFormat:@"Uploading encrypted copy of %@", filePath]];
                                     [self upload:encryptedFilePath
                                           sasURI:checkoutData.SharedAccessSignatureURI
                                       completion:^(NSURLResponse *response, NSError *error) {
                                           if (error != nil) {
                                               completionHandler(error, @"Unable to upload encrypted file");
                                               return;
                                           }
//----------------------------
//   Step 6:
//   Mark the file as ready to download by
//   checking it back in
//----------------------------
                                           [self checkin:containerID
                                              blobIDName:blobIDName
                                           blobSizeBytes:originalFileSize
                                            checkinToken:checkoutData.checkInToken
                                              completion:^(NSURLResponse *response, NSError *error) {
                                                  if (error != nil) {
                                                      completionHandler(error, @"Unable to finalize upload");
                                                      return;
                                                  }

                                                  [self consoleLog:@"Upload completed, cleaning up"];
                                                  [fm removeItemAtPath:encryptedFilePath error:NULL];
                                                  completionHandler(nil, nil);
                                                  return;
                                              }]; // checkin
                                       }]; // upload
                                 }]; // checkout
                         }]; // createBlob
           }]; // KeyData
    }]; // ping
}

#pragma mark - Core REST Methods

- (void)upload:(NSFileHandle *)inHandle
    blockIndex:(int)blockIndex
      blockIDs:(NSMutableArray *)blockIDs
        sasURI:(NSString *)sasURI
    completion:(void (^)(NSURLResponse *response, NSError *error))completionHandler {
    float blockSizeMB = self.blockSizeMB;
    unsigned long long blockSizeBytes = blockSizeMB * 1024 * 1024;
    [self consoleLog:[NSString stringWithFormat:@"Starting send in %.2fMB increments", blockSizeMB]];

    NSData *data = nil;
    [inHandle seekToFileOffset:blockSizeBytes * blockIndex];
    @try {
        data = [inHandle readDataOfLength:(NSUInteger)blockSizeBytes];
    }
    @catch (NSException *exception) {
        NSError *e = [NSError errorWithDomain:IronBoxErrorDomain
                                         code:IronBoxErrorFileCannotReadType
                                     userInfo:nil];
        completionHandler(nil, e);
        return;
    }

    if ([data length] == 0) {
        // Done sending blocks, so commit the blocks into a single one
        // do the final re-assembly on the storage server side
        NSString *commitBlockSASURL = [sasURI stringByAppendingString:@"&comp=blockList"];
        NSDictionary *commitHeaders = @{@"content-type": @"text/xml",
                                        @"x-ms-version": @"2012-02-12"};
        NSMutableString *blockListBody = [NSMutableString string];
        [blockIDs enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
            NSString *encodedBlockID = [[obj dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];
            // build list of block ids as xml elements
            NSString *str = [NSString stringWithFormat:@"<Latest>%@</Latest>", encodedBlockID];
            [blockListBody appendString:str];
        }];
        NSString *commitBody = [NSString stringWithFormat:@"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                                @"<BlockList>%@</BlockList>", blockListBody];

        NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:commitBlockSASURL]];
        [commitHeaders enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
            [request setValue:obj forHTTPHeaderField:key];
        }];
        [request setHTTPMethod:@"PUT"];
        NSURLSessionUploadTask *task = [self.uploadSession
                                        uploadTaskWithRequest:request
                                        fromData:[commitBody dataUsingEncoding:NSUTF8StringEncoding]
                                        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                                            NSHTTPURLResponse *r = (NSHTTPURLResponse *)response;
                                            if (r.statusCode != 201) {
                                                NSError *e = [NSError errorWithDomain:IronBoxErrorDomain
                                                                                 code:IronBoxErrorInvalidResponseType
                                                                             userInfo:nil];
                                                completionHandler(response, e);
                                                return;
                                            }
                                            completionHandler(response, error);
                                            return;
                                        }]; // final
        [task resume];
        return;
    }

    NSDictionary *headers = @{@"content-type": @"application/octet-stream",
                              @"x-ms-blob-type": @"BlockBlob",
                              @"x-ms-version": @"2012-02-12"};
    NSString *sasURIBlockPrefix = [sasURI stringByAppendingString:@"&comp=block&blockid="];

    // block IDs all have to be the same length, which was NOT
    // documented by MSFT
    NSString *blockID = [NSString stringWithFormat:@"block%08d", blockIndex];
    NSString *base64BlockID = [[blockID dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];
    NSString *blockSASURI = [sasURIBlockPrefix stringByAppendingString:base64BlockID];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:blockSASURI]];
    [headers enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
        [request setValue:obj forHTTPHeaderField:key];
    }];
    [request setHTTPMethod:@"PUT"];
    NSURLSessionUploadTask *task = nil;
    task = [self.uploadSession
            uploadTaskWithRequest:request
            fromData:data
            completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                if (error) {
                    completionHandler(response, error);
                    return;
                }

                NSHTTPURLResponse *r = (NSHTTPURLResponse *)response;
                if (r.statusCode != 201) {
                    NSError *e = [NSError errorWithDomain:IronBoxErrorDomain
                                                     code:IronBoxErrorInvalidResponseType
                                                 userInfo:nil];
                    completionHandler(response, e);
                    return;
                }

                [blockIDs addObject:blockID];
                if (self.isVerbose) {
                    //TODO:
                    NSLog(@"+++");
                }

                [self upload:inHandle
                  blockIndex:blockIndex + 1
                    blockIDs:blockIDs
                      sasURI:sasURI
                  completion:completionHandler];

            }]; // upload block
    [task resume];
}

//-------------------------------------------------------------
//	Uploads an encrypted file to cloud storage using the
//	shared access signature provided.  This function uploads
//	blocks in (blockSizeMB) blocks with max 50k blocks
//
//-------------------------------------------------------------
- (void)upload:(NSString *)inFilename
        sasURI:(NSString *)sasURI
    completion:(void (^)(NSURLResponse *response, NSError *error))completionHandler {
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL exists = [fm fileExistsAtPath:inFilename];
    if (!exists) {
        NSError *e = [NSError errorWithDomain:IronBoxErrorDomain
                                         code:IronBoxErrorFileNotFoundType
                                     userInfo:nil];
        completionHandler(nil, e);
        return;
    }

    NSMutableArray *blockIDs = [NSMutableArray array];
    int blockIndex = 0;

    NSError *e = nil;
    NSFileHandle *inHandle = [NSFileHandle fileHandleForReadingFromURL:[NSURL fileURLWithPath:inFilename]
                                                                 error:&e];
    if (nil == inHandle) {
        completionHandler(nil, e);
        return;
    }

    [self upload:inHandle
      blockIndex:blockIndex
        blockIDs:blockIDs
          sasURI:sasURI
      completion:completionHandler];

    return;
}


//-------------------------------------------------------------
//   Checks if the IronBox API server is responding
//-------------------------------------------------------------
- (void)ping:(void (^)(NSURLResponse *response, NSError *error))completionHandler {
    NSString *URLString = [self.APIServerURL stringByAppendingPathComponent:@"Ping"];
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:URLString]];
    NSURLSessionDataTask *task = [self.dataSession dataTaskWithRequest:request
                                                     completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                                                         NSHTTPURLResponse *r = (NSHTTPURLResponse *)response;
                                                         if (r.statusCode != 200) {
                                                             NSError *e = [NSError errorWithDomain:IronBoxErrorDomain
                                                                                              code:IronBoxErrorInvalidResponseType
                                                                                          userInfo:nil];
                                                             completionHandler(response, e);
                                                             return;
                                                         }
                                                         completionHandler(response, error);
                                                         return;
                                                     }];
    [task resume];
    return;
}

//-------------------------------------------------------------
//   Fetches an IronBox container key data
//-------------------------------------------------------------
- (void)keyData:(NSString *)containerID
     completion:(void (^)(NSURLResponse *response, IronBoxKeyData *keyData, NSError *error))completionHandler {
    NSString *URLString = [self.APIServerURL stringByAppendingPathComponent:@"ContainerKeyData"];
    NSDictionary *dict = @{@"Entity": self.entity,
                           @"EntityType": [NSString stringWithFormat:@"%d", self.type],
                           @"EntityPassword": self.password,
                           @"ContainerID": containerID};
    NSString *POSTString = FormencodeDictionary(dict);
    NSData *POSTData = [POSTString dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:[NSURL URLWithString:URLString]];
    [request setValue:self.contentFormat forHTTPHeaderField:@"Accept"];
    [request setHTTPMethod:@"POST"];
    NSURLSessionDataTask *task = nil;
    task = [self.dataSession
            uploadTaskWithRequest:request
            fromData:POSTData
            completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                NSHTTPURLResponse *r = (NSHTTPURLResponse *)response;
                if (r.statusCode != 200) {
                    completionHandler(response, nil, error);
                    return;
                }

                NSError *e = nil;
                NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:data options:0 error:&e];
                if (dict == nil) {
                    completionHandler(response, nil, e);
                    return;
                }

                IronBoxKeyData *keyData = [[IronBoxKeyData alloc] init];
                NSString *sessionKeyBase64 = [dict objectForKey:@"SessionKeyBase64"];
                if (sessionKeyBase64 == nil) {
                    NSError *e = [NSError errorWithDomain:IronBoxErrorDomain
                                                     code:IronBoxErrorInvalidResponseType
                                                 userInfo:nil];
                    completionHandler(response, nil, e);
                    return;
                }
                keyData.symmetricKey = [[NSData alloc] initWithBase64EncodedString:sessionKeyBase64 options:0];

                NSString *IV = [dict objectForKey:@"SessionIVBase64"];
                if (IV == nil) {
                    NSError *e = [NSError errorWithDomain:IronBoxErrorDomain
                                                     code:IronBoxErrorInvalidResponseType
                                                 userInfo:nil];
                    completionHandler(response, nil, e);
                    return;
                }
                keyData.IV = [[NSData alloc] initWithBase64EncodedString:IV options:0];

                NSNumber *keyStrength = [dict objectForKey:@"SymmetricKeyStrength"];
                if (keyStrength == nil) {
                    NSError *e = [NSError errorWithDomain:IronBoxErrorDomain
                                                     code:IronBoxErrorInvalidResponseType
                                                 userInfo:nil];
                    completionHandler(response, nil, e);
                    return;
                }
                keyData.keyStrength = [keyStrength intValue];

                completionHandler(response, keyData, nil);
                return;
            }];
    [task resume];
    return;
}

//-------------------------------------------------------------
//	Creates an IronBox blob in an existing container
//-------------------------------------------------------------
- (void)createBlobName:(NSString *)blobName
           containerID:(NSString *)containerID
        completion:(void (^)(NSURLResponse *response, NSString *blobIDName, NSError *error))completionHandler {
    NSString *URLString = [self.APIServerURL stringByAppendingPathComponent:@"CreateEntityContainerBlob"];
    NSDictionary *dict = @{@"Entity": self.entity,
                           @"EntityType": [NSString stringWithFormat:@"%d", self.type],
                           @"EntityPassword": self.password,
                           @"ContainerID": containerID,
                           @"BlobName": blobName};
    NSString *POSTString = FormencodeDictionary(dict);
    NSData *POSTData = [POSTString dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:[NSURL URLWithString:URLString]];
    [request setValue:self.contentFormat forHTTPHeaderField:@"Accept"];
    [request setHTTPMethod:@"POST"];
    NSURLSessionDataTask *task = [self.dataSession uploadTaskWithRequest:request
                                                                fromData:POSTData
                                                       completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                                                           NSHTTPURLResponse *r = (NSHTTPURLResponse *)response;
                                                           if (r.statusCode != 200) {
                                                               NSError *e = [NSError errorWithDomain:IronBoxErrorDomain
                                                                                                code:IronBoxErrorInvalidResponseType
                                                                                            userInfo:nil];
                                                               completionHandler(response, nil, e);
                                                               return;
                                                           }

                                                           NSString *name = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                                                           if (nil == name) {
                                                               NSError *e = [NSError errorWithDomain:IronBoxErrorDomain
                                                                                                code:IronBoxErrorInvalidResponseType
                                                                                            userInfo:nil];
                                                               completionHandler(response, nil, e);
                                                               return;
                                                           }

                                                           completionHandler(response, name, nil);
                                                           return;
                                                       }];
    [task resume];
    return;
}

//-------------------------------------------------------------
//	Checks outs an entity container blob, so that the caller
//	can begin uploading the contents of the blob.
//-------------------------------------------------------------
- (void)checkout:(NSString *)containerID
      blobIDName:(NSString *)blobIDName
      completion:(void (^)(NSURLResponse *response, IronBoxBlobCheckOutData *checkoutData, NSError *error))completionHandler {
    NSString *URLString = [self.APIServerURL stringByAppendingPathComponent:@"CheckOutEntityContainerBlob"];
    NSDictionary *dict = @{@"Entity": self.entity,
                           @"EntityType": [NSString stringWithFormat:@"%d", self.type],
                           @"EntityPassword": self.password,
                           @"ContainerID": containerID,
                           @"BlobIDName": blobIDName};
    NSString *POSTString = FormencodeDictionary(dict);
    NSData *POSTData = [POSTString dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:[NSURL URLWithString:URLString]];
    [request setValue:self.contentFormat forHTTPHeaderField:@"Accept"];
    [request setHTTPMethod:@"POST"];
    NSURLSessionDataTask *task = [self.dataSession uploadTaskWithRequest:request
                                                                fromData:POSTData
                                                       completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                                                           NSHTTPURLResponse *r = (NSHTTPURLResponse *)response;
                                                           if (r.statusCode != 200) {
                                                               NSError *e = [NSError errorWithDomain:IronBoxErrorDomain
                                                                                                code:IronBoxErrorInvalidResponseType
                                                                                            userInfo:nil];
                                                               completionHandler(response, nil, e);
                                                               return;
                                                           }

                                                           NSError *e = nil;
                                                           NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:data options:0 error:&e];
                                                           if (dict == nil) {
                                                               completionHandler(response, nil, e);
                                                               return;
                                                           }

                                                           IronBoxBlobCheckOutData *checkoutData = [[IronBoxBlobCheckOutData alloc] init];
                                                           NSString *sharedAccesSignature = [dict objectForKey:@"SharedAccessSignature"];
                                                           if (sharedAccesSignature == nil) {
                                                               NSError *e = [NSError errorWithDomain:IronBoxErrorDomain
                                                                                                code:IronBoxErrorInvalidResponseType
                                                                                            userInfo:nil];
                                                               completionHandler(response, nil, e);
                                                               return;
                                                           }

                                                           checkoutData.sharedAccessSignature = sharedAccesSignature;
                                                           checkoutData.SharedAccessSignatureURI = dict[@"SharedAccessSignatureUri"];
                                                           checkoutData.checkInToken = dict[@"CheckInToken"];
                                                           checkoutData.storageURI = dict[@"StorageUri"];
                                                           checkoutData.storageType =[dict[@"StorageType"] integerValue];
                                                           checkoutData.containerStorageName = dict[@"ContainerStorageName"];
                                                           completionHandler(response, checkoutData, nil);

                                                           return;
                                                       }];
    [task resume];
    return;
}

//-------------------------------------------------------------
//	Checks in a checked out entity container blob
//-------------------------------------------------------------
- (void)checkin:(NSString *)containerID
     blobIDName:(NSString *)blobIDName
  blobSizeBytes:(unsigned long long)blobSizeBytes
   checkinToken:(NSString *)checkinToken
     completion:(void (^)(NSURLResponse *response, NSError *error))completionHandler {
    NSString *URLString = [self.APIServerURL stringByAppendingPathComponent:@"CheckInEntityContainerBlob"];
    NSDictionary *dict = @{@"Entity": self.entity,
                           @"EntityType": [NSString stringWithFormat:@"%d", self.type],
                           @"EntityPassword": self.password,
                           @"ContainerID": containerID,
                           @"BlobIDName": blobIDName,
                           @"BlobSizeBytes": [NSString stringWithFormat:@"%llu", blobSizeBytes],
                           @"BlobCheckInToken": checkinToken};
    NSString *POSTString = FormencodeDictionary(dict);
    NSData *POSTData = [POSTString dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:[NSURL URLWithString:URLString]];
    [request setHTTPMethod:@"POST"];
    [request setValue:self.contentFormat forHTTPHeaderField:@"Accept"];
    NSURLSessionDataTask *task = [self.dataSession uploadTaskWithRequest:request
                                                                fromData:POSTData
                                                       completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                                                           NSHTTPURLResponse *r = (NSHTTPURLResponse *)response;
                                                           if (r.statusCode != 200) {
                                                               NSError *e = [NSError errorWithDomain:IronBoxErrorDomain
                                                                                                code:IronBoxErrorInvalidResponseType
                                                                                            userInfo:nil];
                                                               completionHandler(response, e);
                                                               return;
                                                           }

                                                           completionHandler(response, nil);
                                                           return;
                                                       }];
    [task resume];
    return;
}

#pragma mark - Helper Methods

- (void)consoleLog:(NSString *)message {
    if (!self.isVerbose) {
        return;
    }
    NSDate *now = [NSDate date];
    NSLog(@"%@: %@", now, message);
}

@end

