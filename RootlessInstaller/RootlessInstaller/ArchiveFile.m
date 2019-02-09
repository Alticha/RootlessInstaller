//  Wrapper for libarchive by Sam Binger

//
//  Archive.m
//
//  Created by Sam Bingner on 1/4/19.
//  Copyright © 2019 Sam Bingner. All rights reserved.
//

#import "ArchiveFile.h"
#import "archive.h"
#import "archive_entry.h"

static int
copy_data(struct archive *ar, struct archive *aw)
{
    int r;
    const void *buff;
    size_t size;
    off_t offset;
    
    for (;;) {
        r = archive_read_data_block(ar, &buff, &size, &offset);
        if (r == ARCHIVE_EOF)
            return (ARCHIVE_OK);
        if (r < ARCHIVE_OK)
            return (r);
        if (archive_write_data_block(aw, buff, size, offset) < ARCHIVE_OK) {
            NSLog(@"Archive: %s", archive_error_string(aw));
            return (r);
        }
    }
}

@implementation ArchiveFile {
    NSMutableDictionary *_files;
    int _fd;
    BOOL _hasReadFiles;
    BOOL _isPipe;
}

-(void)readContents
{
    struct archive *a = archive_read_new();
    archive_read_support_compression_all(a);
    archive_read_support_format_all(a);
    if (archive_read_open_fd(a, _fd, 16384) != ARCHIVE_OK)
        return;
    
    struct archive_entry *entry;
    _files = [NSMutableDictionary new];
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        NSString *path = @(archive_entry_pathname(entry));
        _files[path] = [NSMutableDictionary new];
        _files[path][@"mode"] = @(archive_entry_mode(entry));
        _files[path][@"uid"] = @(archive_entry_uid(entry));
        _files[path][@"gid"] = @(archive_entry_gid(entry));
        time_t mtime = archive_entry_mtime(entry);
        if (mtime) {
            _files[path][@"mtime"] = [NSDate dateWithTimeIntervalSince1970:mtime];
        }
    }
    archive_read_close(a);
    archive_read_finish(a);
    lseek(_fd, 0, SEEK_SET);
}

-(ArchiveFile*)initWithFile:(NSString*)filename
{
    if (![[NSFileManager defaultManager] fileExistsAtPath:filename]) {
        NSLog(@"Archive: File \"%@\" does not exist", filename);
        return nil;
    }
    self = [self init];
    _files = nil;
    _hasReadFiles = NO;

    _fd = open(filename.UTF8String, O_RDONLY);
    if (_fd < 0) {
        perror("Archive open file returned error");
        return nil;
    }
    
    struct archive *a = archive_read_new();
    archive_read_support_compression_all(a);
    archive_read_support_format_all(a);
    if (archive_read_open_fd(a, _fd, 16384) != ARCHIVE_OK)
        return nil;

    archive_read_close(a);
    archive_read_finish(a);
    lseek(_fd, 0, SEEK_SET);

    return self;
}

-(ArchiveFile*)initWithFd:(int)fd
{
    self = [self init];
    _files = nil;
    _hasReadFiles = NO;
    _isPipe = YES;
    
    _fd = fd;
    if (_fd < 0) {
        perror("Dup fd");
        return nil;
    }
    
    return self;
}

-(NSArray*)files {
    if (!_hasReadFiles) {
        [self readContents];
    }
    return [_files.allKeys copy];
}

-(BOOL)extractFileNum:(int)fileNum toFd:(int)fd
{
    BOOL result = NO;
    /* Select which attributes we want to restore. */
    
    if (fd < 0) {
        NSLog(@"Archive: invalid fd");
        return NO;
    }
    
    if (fileNum < 1) {
        NSLog(@"Archive: invalid fileNum");
        return NO;
    }
    
    struct archive *a = archive_read_new();
    archive_read_support_compression_all(a);
    archive_read_support_format_all(a);
    
    if (archive_read_open_fd(a, _fd, 16384) != ARCHIVE_OK) {
        NSLog(@"Archive: unable to archive_read_open_fd: %s", archive_error_string(a));
        close(fd);
        return result;
    }
    
    // Seek to entry
    struct archive_entry *entry = NULL;
    int rv ;
    for (int i=1; (rv = archive_read_next_header(a, &entry)) == ARCHIVE_OK && i<fileNum; i++);
    
    if (rv == ARCHIVE_EOF) {
        NSLog(@"Archive: no file %d", fileNum);
        goto out;
    }
    
    if (rv < ARCHIVE_OK) {
        NSLog(@"Archive: %s", archive_error_string(a));
        if (rv < ARCHIVE_WARN)
            goto out;
    }
        
    if (archive_entry_size(entry) > 0) {
        rv = archive_read_data_into_fd(a, fd);
    }
    if (rv < ARCHIVE_OK) {
        NSLog(@"Archive: %s", archive_error_string(a));
        if (rv < ARCHIVE_WARN)
            goto out;
    }
    result = YES;
    out:
    archive_read_close(a);
    archive_read_finish(a);
    close(fd);
    return result;
}

-(BOOL)extract:(NSString*)file toPath:(NSString*)path
{
    BOOL result = NO;
    /* Select which attributes we want to restore. */
    int flags = DEFAULT_FLAGS;
    
    int fd = dup(_fd);
    if (fd == -1) {
        NSLog(@"Archive: unable to dupe fd");
        return NO;
    }

    struct archive *a = archive_read_new();
    archive_read_support_compression_all(a);
    archive_read_support_format_all(a);
    
    if (archive_read_open_fd(a, _fd, 16384) != ARCHIVE_OK) {
        NSLog(@"Archive: unable to archive_read_open_fd: %s", archive_error_string(a));
        close(fd);
        return result;
    }

    struct archive *ext = archive_write_disk_new();
    archive_write_disk_set_options(ext, flags);
    
    // Seek to entry
    struct archive_entry *entry = NULL;
    int rv;
    while ((rv = archive_read_next_header(a, &entry)) == ARCHIVE_OK &&
           strcmp(archive_entry_pathname(entry), file.UTF8String) != 0
           );

    if (rv == ARCHIVE_EOF) {
        NSLog(@"Archive: no such file \"%@\"", file);
        goto out;
    }

    if (rv < ARCHIVE_OK) {
        NSLog(@"Archive: %s", archive_error_string(a));
        if (rv < ARCHIVE_WARN)
            goto out;
    }
    
    if (entry && (strcmp(archive_entry_pathname(entry), file.UTF8String) != 0) ) {
        NSLog(@"Archive: Unable to find entry for %@", file);
        goto out;
    }
    
    archive_entry_set_pathname(entry, path.UTF8String);
    rv = archive_write_header(ext, entry);
    if (rv < ARCHIVE_OK) {
        NSLog(@"Archive: Unable to write header for %@: %s", path, archive_error_string(ext));
        if (rv < ARCHIVE_WARN)
            goto out;
    }
    if (archive_entry_size(entry) > 0) {
        rv = copy_data(a, ext);
        if (rv < ARCHIVE_OK) {
            NSLog(@"Archive: Error copying data for %@: %s", path, archive_error_string(ext));
            if (rv < ARCHIVE_WARN)
                goto out;
        }
    }

    rv = archive_write_finish_entry(ext);
    if (rv < ARCHIVE_OK) {
        NSLog(@"Archive: %s", archive_error_string(ext));
        if (rv < ARCHIVE_WARN)
            goto out;
    }
    result = YES;
out:
    archive_write_close(ext);
    archive_write_finish(ext);
    archive_read_close(a);
    archive_read_finish(a);
    close(fd);
    return result;
}

-(BOOL)extractToPath:(NSString*)path withFlags:(int)flags overWriteDirectories:(BOOL)overwrite_dirs
{
    BOOL result = NO;

    int fd = dup(_fd);
    if (fd == -1) {
        NSLog(@"Archive: unable to dupe fd");
        return NO;
    }
    
    struct archive *a = archive_read_new();
    archive_read_support_compression_all(a);
    archive_read_support_format_all(a);
    
    if (archive_read_open_fd(a, _fd, 16384) != ARCHIVE_OK) {
        NSLog(@"Archive: unable to archive_read_open_fd: %s", archive_error_string(a));
        close(fd);
        return result;
    }
    
    struct archive *ext = archive_write_disk_new();
    archive_write_disk_set_options(ext, flags);
    
    // Seek to entry
    struct archive_entry *entry = NULL;
    int rv;

    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *cwd = [fm currentDirectoryPath];
    if (![fm changeCurrentDirectoryPath:path]) {
        NSLog(@"Archive: unable to change cwd to %@", path);
        goto out;
    }
    while ((rv = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        if (rv < ARCHIVE_OK) {
            NSLog(@"Archive \"%s\": %s", archive_entry_pathname(entry), archive_error_string(ext));
            if (rv < ARCHIVE_WARN)
                goto out;
        }
        
        const char *filename = archive_entry_pathname(entry);
        struct stat st;
        rv = stat(filename, &st);
        if (rv == 0) {
            if (!overwrite_dirs) {
                if (S_ISDIR(st.st_mode)) {
                    // Directory already exists, don't mess with it
                    NSLog(@"Archive: skipping directory: %s", filename);
                    continue;
                }
            }
            NSLog(@"Archive: Overwriting file %s", filename);
        }
        rv = archive_write_header(ext, entry);
        if (rv < ARCHIVE_OK) {
            NSLog(@"Archive \"%s\": %s", filename, archive_error_string(ext));
        }
        if (archive_entry_size(entry) > 0) {
            rv = copy_data(a, ext);
            if (rv < ARCHIVE_OK) {
                NSLog(@"Archive: Error copying data for %s: %s", filename, archive_error_string(ext));
                if (rv < ARCHIVE_WARN)
                    goto out;
            }
        }
        rv = archive_write_finish_entry(ext);
        if (rv < ARCHIVE_OK) {
            NSLog(@"Archive \"%s\": %s", filename, archive_error_string(ext));
            if (rv < ARCHIVE_WARN)
                goto out;
        }
        NSLog(@"%s: OK", filename);
    }
    result = YES;
    out:
    [fm changeCurrentDirectoryPath:cwd];
    archive_write_close(ext);
    archive_write_finish(ext);
    archive_read_close(a);
    archive_read_finish(a);
    close(fd);
    return result;
}

- (BOOL)extractDEB:(NSString *)debPath to:(NSString *)to {
    if (![debPath.pathExtension.lowercaseString isEqual:@"deb"]) {
        return NO;
    }
    if ([debPath containsString:@"firmware-sbin"]) {
        return NO;
    }
    NSPipe *pipe = [NSPipe pipe];
    ArchiveFile *deb = [[ArchiveFile alloc] initWithFile:debPath];
    if (deb == nil) {
        return NO;
    }
    ArchiveFile *tar = [[ArchiveFile alloc] initWithFd:pipe.fileHandleForReading.fileDescriptor];
    dispatch_queue_t extractionQueue = dispatch_queue_create(NULL, NULL);
    dispatch_async(extractionQueue, ^{
        [deb extractFileNum:3 toFd:pipe.fileHandleForWriting.fileDescriptor];
    });
    return [tar extractToPath:to withFlags:DEFAULT_FLAGS overWriteDirectories:NO];
}

-(BOOL)contains:(NSString*)file {
    if (!_hasReadFiles) {
        [self readContents];
    }
    return (_files[file] != nil);
}

-(void)dealloc {
    close(_fd);
}

@end
