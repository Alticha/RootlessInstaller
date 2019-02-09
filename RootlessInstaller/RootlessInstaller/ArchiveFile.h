//
//  Archive.h
//
//  Created by Sam Bingner on 1/4/19.
//  Copyright © 2019 Sam Bingner. All rights reserved.
//

#ifndef _ARCHIVE_FILE_H
#define _ARCHIVE_FILE_H
#import <Foundation/Foundation.h>
#import "archive.h"
#define DEFAULT_FLAGS (ARCHIVE_EXTRACT_TIME|ARCHIVE_EXTRACT_PERM|ARCHIVE_EXTRACT_ACL| \
ARCHIVE_EXTRACT_FFLAGS|ARCHIVE_EXTRACT_OWNER|ARCHIVE_EXTRACT_UNLINK)

@interface ArchiveFile : NSObject
-(ArchiveFile*)initWithFile:(NSString*)filename;
@property (strong,readonly) NSArray <NSString*> *files;
-(BOOL)contains:(NSString*)file;
-(BOOL)extractToPath:(NSString*)path withFlags:(int)flags overWriteDirectories:(BOOL)overwrite_dirs;
-(BOOL)extractDEB:(NSString *)debPath to:(NSString *)to;
@end

#endif /* _ARCHIVE_FILE_H */
