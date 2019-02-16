#import <UIKit/UIKit.h>
#include <spawn.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include "ArchiveFile.h"
#include "jbd.h"

// definitions
#define hex(hex, alphaVal) [UIColor colorWithRed:((float)((hex & 0xFF0000) >> 16))/255.0 green:((float)((hex & 0xFF00) >> 8))/255.0 blue:((float)(hex & 0xFF))/255.0 alpha:alphaVal]
#define isConnectedToInternet !([[Reachability reachabilityForInternetConnection] currentReachabilityStatus] == NotReachable)
#define bgDisabledColour hex(0xB8B8B8, 1.0)
#define setBgDisabledColour setBackgroundColor:hex(0xB8B8B8, 1.0)
#define bgEnabledColour [UIColor colorWithRed:1 green:0.57637232540000005 blue:0 alpha:1]
#define setBgEnabledColour setBackgroundColor:[UIColor colorWithRed:1 green:0.57637232540000005 blue:0 alpha:1]
#define execute(ARGS) \
{\
     pid_t _____PID_____;\
     posix_spawn(&_____PID_____, ARGS[0], NULL, NULL, (char **)&ARGS, NULL);\
     waitpid(_____PID_____, NULL, 0);\
}
#define retrn(why) \
{\
    [self dismissableController:@"Failed" text:@(why)];\
    return;\
}
#define SYSTEM_VERSION_EQUAL_TO(v) ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedSame)
#define SYSTEM_VERSION_GREATER_THAN(v) ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedDescending)
#define SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(v) ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedAscending)
#define SYSTEM_VERSION_LESS_THAN(v) ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedAscending)
#define SYSTEM_VERSION_LESS_THAN_OR_EQUAL_TO(v) ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedDescending)

// uibutton stuff
@interface UIButton(enableDisable)
- (void)enableButton;
- (void)disableButton;

@end

@implementation UIButton(enableDisable)
- (void)enableButton {
    [self setBgEnabledColour];
    [self setEnabled:YES];
}
- (void)disableButton {
    [self setBgDisabledColour];
    [self setEnabled:NO];
}

@end

// view
@interface ViewController : UIViewController

@end

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UIButton *rootbtn;
@property (weak, nonatomic) IBOutlet UIButton *unsandboxbtn;
@property (weak, nonatomic) IBOutlet UIButton *installbtn;
@property (weak, nonatomic) IBOutlet UIButton *uninstallbtn;
@property (weak, nonatomic) IBOutlet UITextField *debURL;
@property (weak, nonatomic) IBOutlet UIButton *respringbtn;

@end

@implementation ViewController

static NSString *ldid2;
static NSString *Resources;

// GUI stuff

- (void)viewDidLoad {
    // set up our view
    [super viewDidLoad];
    // for the "Done" button to actually dismiss the keyboard
    _debURL.delegate = (id<UITextFieldDelegate> _Nullable)self;
    // disable buttons until we can get root
    [_installbtn disableButton];
    [_uninstallbtn disableButton];
    [_respringbtn disableButton];
    // set up paths
    Resources = [[NSBundle mainBundle] bundlePath];
    ldid2 = @"/var/containers/Bundle/iosbinpack64/usr/bin/ldid2";
}

- (void)dismissableController:(NSString *)title text:(NSString *)text {
    // convenience method to display a simple UIAlertController
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title message:text preferredStyle:UIAlertControllerStyleAlert];
    UIAlertAction *dismiss = [UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleCancel handler:nil];
    [alert addAction:dismiss];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)undismissableController:(NSString *)title text:(NSString *)text {
    // convenience method to display a simple UIAlertController
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title message:text preferredStyle:UIAlertControllerStyleAlert];
    [self presentViewController:alert animated:YES completion:nil];
}

- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    [textField resignFirstResponder];
    return YES;
}

- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event{
    [self.view endEditing:YES];
}

// exploitation etc

- (pid_t)pid_for_name:(NSString *)name {
    static int maxArgumentSize = 0;
    size_t size = sizeof(maxArgumentSize);
    sysctl((int[]){ CTL_KERN, KERN_ARGMAX }, 2, &maxArgumentSize, &size, NULL, 0);
    int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };
    struct kinfo_proc *info;
    size_t length;
    sysctl(mib, 3, NULL, &length, NULL, 0);
    info = malloc(length);
    sysctl(mib, 3, info, &length, NULL, 0);
    for (int i = 0; i < length / sizeof(struct kinfo_proc); i++) {
        pid_t pid = info[i].kp_proc.p_pid;
        if (pid == 0) {
            continue;
        }
        size_t size = maxArgumentSize;
        char *buffer = (char *)malloc(length);
        sysctl((int[]){ CTL_KERN, KERN_PROCARGS2, pid }, 3, buffer, &size, NULL, 0);
        NSString *executable = [NSString stringWithCString:buffer + sizeof(int) encoding:NSUTF8StringEncoding];
        free(buffer);
        if ([executable isEqual:name]) {
            free(info);
            return pid;
        } else if ([[executable lastPathComponent] isEqual:name]) {
            free(info);
            return pid;
        }
    }
    free(info);
    return -1;
}

- (bool)isJailbroken {
    if (![[NSFileManager defaultManager] fileExistsAtPath:@"/var/LIB/"]) return false;
    if ([self pid_for_name:@"/var/containers/Bundle/iosbinpack64/bin/jailbreakd"] == -1) return false;
    return true;
}

- (bool)isUnsandboxed {
    [[NSFileManager defaultManager] createFileAtPath:@"/var/TESTF" contents:nil attributes:nil];
    if (![[NSFileManager defaultManager] fileExistsAtPath:@"/var/TESTF"]) return false;
    [[NSFileManager defaultManager] removeItemAtPath:@"/var/TESTF" error:nil];
    return true;
}

- (IBAction)run_exploit:(id)sender { // cba renaming leave me alone
    if (!(SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"12.0") && SYSTEM_VERSION_LESS_THAN_OR_EQUAL_TO(@"12.1.2"))) {
        [self undismissableController:@"Failed" text:@"Unfortunately, your iOS version is unsupported."];
        return;
    }
    
    calljailbreakd(getpid(), 6);
    calljailbreakd(getpid(), 7);
    static int tries = 0;
    sleep(1);
    setuid(0);
    seteuid(0);
    setgid(0);
    setegid(0);
    if (![self isUnsandboxed] || getuid()) {
        if (tries < 10) {
            tries++;
            [self run_exploit:sender];
            return;
        } else {
            [self dismissableController:@"Error" text:@"RootlessInstaller hasn't been installed properly. To correct this, SSH into your device and run the following command:\nsh \"$(find /var/containers/Bundle/Application | grep RootlessInstaller.app/install.sh)\""];
            return;
        }
    }
    
    // install and trust ldid2
    if ([[NSFileManager defaultManager] fileExistsAtPath:ldid2]) unlink(ldid2.UTF8String);
    ArchiveFile *tar = [[ArchiveFile alloc] initWithFile:[Resources stringByAppendingString:@"/ldid2.tar.gz"]];
    [tar extractToPath:ldid2.stringByDeletingLastPathComponent];
    [self trust:ldid2];
    
    // aaaand we're done
    [_rootbtn setEnabled:NO];
    [_rootbtn setTitle:@"Got root" forState:UIControlStateDisabled];
    [UIView animateWithDuration:0.5f animations:^{
        [self->_rootbtn setBgDisabledColour];
        if (!self->_unsandboxbtn.enabled) {
            [self->_installbtn enableButton];
            [self->_uninstallbtn enableButton];
            [self->_respringbtn enableButton];
        }
    }];
}

// inject & sh /var/LIB/patchTweaks.sh

- (void)trust:(NSString *)path {
    // trustcache
    const char *args[] = {"/var/containers/Bundle/iosbinpack64/usr/bin/inject", path.UTF8String, NULL};
    execute(args);
}

- (void)patch {
    // patch tweaks to work with rootlessJB and inject them into trustcache
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/LIB/patchTweaks.sh"]) [[NSFileManager defaultManager] removeItemAtPath:@"/var/LIB/patchTweaks.sh" error:nil];
    [[NSFileManager defaultManager] copyItemAtPath:[Resources stringByAppendingString:@"/patch.sh"] toPath:@"/var/LIB/patchTweaks.sh" error:nil];
    chmod("/var/LIB/patchTweaks.sh", 0755);
    chown("/var/LIB/patchTweaks.sh", 501, 20);
    const char *args[] = {"/var/containers/Bundle/iosbinpack64/bin/sh", "/var/LIB/patchTweaks.sh", NULL};
    execute(args)
    [[NSFileManager defaultManager] removeItemAtPath:@"/var/LIB/patchTweaks.sh" error:nil];
}

//

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
    ArchiveFile *tar = [ArchiveFile archiveWithFd:pipe.fileHandleForReading.fileDescriptor];
    dispatch_queue_t extractionQueue = dispatch_queue_create(NULL, NULL);
    dispatch_async(extractionQueue, ^{
        [deb extractFileNum:3 toFd:pipe.fileHandleForWriting.fileDescriptor];
    });
    return [tar extractToPath:to];
}

// installer

- (IBAction)installDEB:(id)sender {
    // download the DEB
    NSString *deb = [Resources stringByAppendingString:@"/DEB.deb"];
    NSURL *url = [NSURL URLWithString:_debURL.text];
    if (!_debURL.text) retrn("No URL was provided.");
    if (![url.pathExtension.lowercaseString isEqual:@"deb"]) retrn(([NSString stringWithFormat:@"%@ files are unsupported.", url.pathExtension.uppercaseString]).UTF8String);
    if (!url) retrn("No valid URL was provided.");
    NSData *data = [NSData dataWithContentsOfURL:url];
    if (data) {
        [data writeToFile:deb atomically:YES];
    } else {
        retrn("The DEB file couldn't be downloaded.");
    }
    
    // so things install correctly
    BOOL LIBRARY_EXISTS = false;
    BOOL VAR_EXISTS = false;
    BOOL PRIVATE_EXISTS = false;
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/Library"]) {
        LIBRARY_EXISTS = true;
        [[NSFileManager defaultManager] moveItemAtPath:@"/var/Library" toPath:@"/var/TMP_ROOTLESSINSTALLER_LIBRARY" error:nil];
    }
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/var"]) {
        VAR_EXISTS = true;
        [[NSFileManager defaultManager] moveItemAtPath:@"/var/var" toPath:@"/var/TMP_ROOTLESSINSTALLER_VAR" error:nil];
    }
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/private"]) {
        PRIVATE_EXISTS = true;
        [[NSFileManager defaultManager] moveItemAtPath:@"/var/private" toPath:@"/var/TMP_ROOTLESSINSTALLER_PRIVATE" error:nil];
    }
    
    {
        NSString *pkg = [Resources stringByAppendingString:@"/Package/"];
        [[NSFileManager defaultManager] removeItemAtPath:pkg error:nil];
        mkdir(pkg.UTF8String, 0777);
        
        [self extractDEB:deb to:[Resources stringByAppendingString:@"/Package/"]];
        
        NSArray *arr = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:pkg error:nil];
        NSArray *root = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/" error:nil];
        NSArray *whitelist = @[@"Library", @"var", @".DS_Store", @"private"];
        
        for (int i = 0; i < arr.count; i++) {
            if ([root containsObject:[arr objectAtIndex:i]] && ![whitelist containsObject:[arr objectAtIndex:i]]) {
                NSLog(@"%@ %@ %@ %@", arr, root, whitelist, [arr objectAtIndex:i]);
                [[NSFileManager defaultManager] removeItemAtPath:pkg error:nil];
                retrn("DEB failed to pass check 1.");
            }
            if ([[arr objectAtIndex:i] isEqual:@"private"]) {
                NSArray *a = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:[pkg stringByAppendingString:@"/private"] error:nil];
                if (![a isEqual:@[@"var"]] && ![a isEqual:@[@".DS_Store", @"var"]]) {
                    [[NSFileManager defaultManager] removeItemAtPath:pkg error:nil];
                    retrn("DEB failed to pass check 2.");
                }
            }
        }
        
        [[NSFileManager defaultManager] removeItemAtPath:pkg error:nil];
    }
    
    [[NSFileManager defaultManager] createSymbolicLinkAtPath:@"/var/Library" withDestinationPath:@"/var/LIB/" error:nil];
    mkdir("/var/private", 0777);
    [[NSFileManager defaultManager] createSymbolicLinkAtPath:@"/var/private/var" withDestinationPath:@"/var/" error:nil];
    [[NSFileManager defaultManager] createSymbolicLinkAtPath:@"/var/var" withDestinationPath:@"/var/" error:nil];
    
    // extract then delete the deb
    [self extractDEB:deb to:@"/var/"];
    unlink(deb.UTF8String);
    
    // patch tweaks so they work with rootlessJB
    [self patch];
    
    // remove our symlink
    unlink("/var/Library");
    unlink("/var/var");
    [[NSFileManager defaultManager] removeItemAtPath:@"/var/private" error:nil];
    if (LIBRARY_EXISTS) {
        [[NSFileManager defaultManager] moveItemAtPath:@"/var/TMP_ROOTLESSINSTALLER_LIBRARY" toPath:@"/var/Library" error:nil];
    }
    if (VAR_EXISTS) {
        [[NSFileManager defaultManager] moveItemAtPath:@"/var/TMP_ROOTLESSINSTALLER_VAR" toPath:@"/var/var" error:nil];
    }
    if (LIBRARY_EXISTS) {
        [[NSFileManager defaultManager] moveItemAtPath:@"/var/TMP_ROOTLESSINSTALLER_PRIVATE" toPath:@"/var/private" error:nil];
    }
    
    // success!
    [self dismissableController:@"Success" text:@"Installed tweak."];
}

// uninstaller

- (IBAction)uninstallDEB:(id)sender {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Sorry" message:@"This feature has been temporarily disabled until I'm certain it's safe.  If you really must use this or if you'd like to test, tap the Ignore button below." preferredStyle:UIAlertControllerStyleAlert];
    UIAlertAction *dismiss = [UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil];
    UIAlertAction *ignore = [UIAlertAction actionWithTitle:@"Ignore" style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
        [self reallyUninstallDEB];
    }];
    [alert addAction:dismiss];
    [alert addAction:ignore];
    [self presentViewController:alert animated:YES completion:nil];
}
    
- (void)reallyUninstallDEB {
    // download the DEB
    NSString *deb = [Resources stringByAppendingString:@"/DEB.deb"];
    NSURL *url = [NSURL URLWithString:_debURL.text];
    if (!_debURL.text) retrn("No URL was provided.");
    if (![_debURL.text.pathExtension.lowercaseString isEqual:@"deb"]) retrn(([NSString stringWithFormat:@"%@ files are unsupported.", url.pathExtension.uppercaseString]).UTF8String);;
    if (!url) retrn("No valid URL was provided.");
    NSData *data = [NSData dataWithContentsOfURL:url];
    if (data) {
        [data writeToFile:deb atomically:YES];
    } else {
        retrn("The DEB file couldn't be downloaded.");
    }
    
    // create Package in our app's bundle
    NSString *pkg = [Resources stringByAppendingString:@"/Package/"];
    BOOL LIBRARY_EXISTS = false;
    BOOL VAR_EXISTS = false;
    BOOL PRIVATE_EXISTS = false;
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/Library"]) {
        LIBRARY_EXISTS = true;
        [[NSFileManager defaultManager] moveItemAtPath:@"/var/Library" toPath:@"/var/TMP_ROOTLESSINSTALLER_LIBRARY" error:nil];
    }
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/var"]) {
        VAR_EXISTS = true;
        [[NSFileManager defaultManager] moveItemAtPath:@"/var/var" toPath:@"/var/TMP_ROOTLESSINSTALLER_VAR" error:nil];
    }
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/private"]) {
        PRIVATE_EXISTS = true;
        [[NSFileManager defaultManager] moveItemAtPath:@"/var/private" toPath:@"/var/TMP_ROOTLESSINSTALLER_PRIVATE" error:nil];
    }
    
    [[NSFileManager defaultManager] createSymbolicLinkAtPath:@"/var/Library" withDestinationPath:@"/var/LIB/" error:nil];
    mkdir("/var/private", 0777);
    [[NSFileManager defaultManager] createSymbolicLinkAtPath:@"/var/private/var" withDestinationPath:@"/var/" error:nil];
    [[NSFileManager defaultManager] createSymbolicLinkAtPath:@"/var/var" withDestinationPath:@"/var/" error:nil];
    
    {
        NSString *pkg = [Resources stringByAppendingString:@"/Package/"];
        [[NSFileManager defaultManager] removeItemAtPath:pkg error:nil];
        mkdir(pkg.UTF8String, 0777);
        
        [self extractDEB:deb to:[Resources stringByAppendingString:@"/Package/"]];
        
        NSArray *arr = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:pkg error:nil];
        NSArray *root = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/" error:nil];
        NSArray *whitelist = @[@"Library", @"var", @".DS_Store", @"private"];
        
        for (int i = 0; i < arr.count; i++) {
            if ([root containsObject:[arr objectAtIndex:i]] && ![whitelist containsObject:[arr objectAtIndex:i]]) {
                [[NSFileManager defaultManager] removeItemAtPath:pkg error:nil];
                retrn("DEB failed to pass checks.");
            }
            if ([[arr objectAtIndex:i] isEqual:@"private"]) {
                NSArray *a = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:[pkg stringByAppendingString:@"/private"] error:nil];
                if (![a isEqual:@[@"var"]] && ![a isEqual:@[@".DS_Store", @"var"]]) {
                    [[NSFileManager defaultManager] removeItemAtPath:pkg error:nil];
                    retrn("DEB failed to pass checks.");
                }
            }
        }
        
        [[NSFileManager defaultManager] removeItemAtPath:pkg error:nil];
    }
    
    // extract the DEB to Package then delete it
    mkdir(pkg.UTF8String, 0777);
    [self extractDEB:deb to:pkg];
    unlink(deb.UTF8String);
    
    // get files in Package
    NSMutableArray *files = [[NSMutableArray alloc] init];
    NSURL *directoryURL = [NSURL URLWithString:pkg];
    NSDirectoryEnumerator *enumerator = [[NSFileManager defaultManager] enumeratorAtURL:directoryURL includingPropertiesForKeys:@[NSURLIsDirectoryKey] options:0 errorHandler:^(NSURL *url, NSError *error) {
        return YES;
    }];
    for (NSURL *url in enumerator) {
        NSString *path = [[url.path componentsSeparatedByString:@"/RootlessInstaller.app/Package/"] lastObject];
        path = [@"/var/" stringByAppendingString:path];
        BOOL isDir;
        [[NSFileManager defaultManager] fileExistsAtPath:path isDirectory:&isDir];
        if (!isDir) [files addObject:path];
    }
    
    // we're done with Package
    [[NSFileManager defaultManager] removeItemAtPath:pkg error:nil];
    
    // remove the files in the DEB from the filesystem
    for (int i = 0; i < files.count; i++) {
        NSArray *blacklist = @[@"/private/var/containers/Bundle/tweaksupport/Library", @"/private/var/containers/Bundle/tweaksupport/Library/PreferenceLoader", @"/private/var/containers/Bundle/tweaksupport/Library/Frameworks", @"/private/var/containers/Bundle/tweaksupport/Library/MobileSubstrate", @"/private/var/containers/Bundle/tweaksupport/Library/MobileSubstrate/DynamicLibraries", @"/private/var/containers/Bundle/tweaksupport/Library/TweakInject", @"/private/var/containers/Bundle/tweaksupport/Library/LaunchDaemons", @"/private/var/containers/Bundle/tweaksupport/Library/PreferenceBundles", @"/private/var/containers/Bundle/tweaksupport/Library/PreferenceLoader/Preferences", @"/private/var/containers/Bundle/tweaksupport/Library/LaunchDaemons", @"/private/var/containers/Bundle/tweaksupport/Library/Frameworks", @"/private/var/containers/Bundle/tweaksupport/Library/TweakInject", @"/private/var/containers/Bundle/tweaksupport/Library", @"/private/var/LIB", @"/private/var", @"/private/var/mobile", @"/private/var/root", @"/private/var/containers/Bundle/tweaksupport/Library"];
        NSString *to = @(realpath(((NSString *)[files objectAtIndex:i]).UTF8String, 0));
        
        // make sure we don't delete important things
        bool remove = true;
        for (NSString *str in blacklist) {
            if ([to isEqual:str] || [to isEqual:[str stringByAppendingString:@"/"]]) {
                remove = false;
            }
        }
        
        if (remove && [[NSFileManager defaultManager] fileExistsAtPath:to]) unlink(to.UTF8String);
        NSString *TO = [to.stringByDeletingLastPathComponent stringByAppendingString:@""];
        NSLog(@"%@", TO);
        while (true) {
            if (remove && [[[NSFileManager defaultManager] contentsOfDirectoryAtPath:TO error:nil] isEqual:@[]]) {
                bool remove2 = true;
                for (NSString *str in blacklist) {
                    if ([TO isEqual:str] || [TO isEqual:[str stringByAppendingString:@"/"]]) {
                        remove2 = false;
                        break;
                    }
                }
                if (remove2) {
                    NSLog(@"removing: %@", TO);
                    [[NSFileManager defaultManager] removeItemAtPath:TO error:nil];
                    TO = TO.stringByDeletingLastPathComponent;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }
    
    unlink("/var/Library");
    unlink("/var/var");
    [[NSFileManager defaultManager] removeItemAtPath:@"/var/private" error:nil];
    if (LIBRARY_EXISTS) {
        [[NSFileManager defaultManager] moveItemAtPath:@"/var/TMP_ROOTLESSINSTALLER_LIBRARY" toPath:@"/var/Library" error:nil];
    }
    if (VAR_EXISTS) {
        [[NSFileManager defaultManager] moveItemAtPath:@"/var/TMP_ROOTLESSINSTALLER_VAR" toPath:@"/var/var" error:nil];
    }
    if (LIBRARY_EXISTS) {
        [[NSFileManager defaultManager] moveItemAtPath:@"/var/TMP_ROOTLESSINSTALLER_PRIVATE" toPath:@"/var/private" error:nil];
    }
    
    // success!
    [self dismissableController:@"Success" text:@"Removed tweak."];
}

// respring

- (IBAction)respring:(id)sender {
    // pretty simple; find SpringBoard's PID and SIGTERM it
    kill([self pid_for_name:@"/System/Library/CoreServices/SpringBoard.app/SpringBoard"], SIGTERM);
}

@end
