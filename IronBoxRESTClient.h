//------------------------------------------------------------------------
//   IronBox REST API Objective-C wrapper
//   Version: 1.0 (12/02/2013)
//   Author: weipin
//   Website: www.goironbox.com
//   Dependencies: iOS 7+
//
//   Change History:
//	 12/2/2013  -	v1.0 first version
//
//------------------------------------------------------------------------

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSUInteger, IronBoxErrorType)  {
    IronBoxErrorUnknownType = 0,
    IronBoxErrorInvalidCredentialsType,
    IronBoxErrorFileNotFoundType,
    IronBoxErrorFileCannotCreateType,
    IronBoxErrorFileCannotReadType,
    IronBoxErrorInvalidResponseType,
};

extern NSString *const IronBoxErrorDomain;

@interface IronBoxRESTClient : NSObject

// Actual entity identifier, this can be email address,
// name identifier (mostly internal use only) or an entity
// ID which is a 64-bit integer that identifies the specific
// user
@property (readwrite, copy) NSString *entity;

// Entity password
@property (readwrite, copy) NSString *password;

// Entity type, 0 = email address, 1 = name identifier, 2 = entity ID
@property (readwrite, assign) int type;

// Accept format
@property (readwrite, copy) NSString *contentFormat;

// API server URL, default however can be changed
// to test servers
@property (readwrite, copy) NSString *APIServerURL;

// Flag that indicates whether or not to be verbose or not
@property (readwrite, assign, getter=isVerbose) BOOL verbose;

@property (readwrite, assign) float blockSizeMB;

- (instancetype)initWithEntity:(NSString *)entity password:(NSString *)password;

//-------------------------------------------------------------
//	Uploads a given file to an IronBox container
//
//	In:
//	    filePath = local file path of file to upload
//	    containerID = IronBox container ID
//	    blobName = name of the file to use on cloud storage
//      completionHandler = a block with code to execute
//                          after the upload operation concludes,
//                          and is NOT ganranteed to be executed
//                          in the main queue
//-------------------------------------------------------------
- (void)upload:(NSString *)filePath
   containerID:(NSString *)containerID
      blobName:(NSString *)blobName
completionHandler:(void (^)(NSError *error, NSString *reason))completionHandler;

@end


