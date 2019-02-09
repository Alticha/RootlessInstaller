#import <UIKit/UIKit.h>
#include <spawn.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include "kernel_memory.h"
#include <sys/utsname.h>
#include "post.h"
#include "voucher_swap.h"
#include "ArchiveFile.h"

// definitions
#define hex(hex, alphaVal) [UIColor colorWithRed:((float)((hex & 0xFF0000) >> 16))/255.0 green:((float)((hex & 0xFF00) >> 8))/255.0 blue:((float)(hex & 0xFF))/255.0 alpha:alphaVal]
#define isConnectedToInternet !([[Reachability reachabilityForInternetConnection] currentReachabilityStatus] == NotReachable)
#define bgDisabledColour hex(0xB8B8B8, 1.0)
#define setBgDisabledColour setBackgroundColor:hex(0xB8B8B8, 1.0)
#define bgEnabledColour [UIColor colorWithRed:1 green:0.57637232540000005 blue:0 alpha:1]
#define setBgEnabledColour setBackgroundColor:[UIColor colorWithRed:1 green:0.57637232540000005 blue:0 alpha:1]
#define Utilities [[Post alloc] init]
#define execute(ARGS) \
{\
     pid_t _____PID_____;\
     posix_spawn(&_____PID_____, ARGS[0], NULL, NULL, (char **)&ARGS, NULL);\
     waitpid(_____PID_____, NULL, 0);\
}
#define retrn \
{\
     [self dismissableController:@"Failed" text:nil];\
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

// exploitation etc

- (bool)isJailbroken {
    if (![[NSFileManager defaultManager] fileExistsAtPath:@"/var/LIB/"]) return false;
    if ([Utilities pid_for_name:@"/var/containers/Bundle/iosbinpack64/bin/jailbreakd"] == -1) return false;
    return true;
}

- (bool)voucher_swap {
    if (![Utilities is16KAndIsNotA12]) {
        printf("non-16k and a12 devices are unsupported.\n");
        return false;
    }
    // Run voucher_swap
    voucher_swap();
    if (!MACH_PORT_VALID(kernel_task_port)) {
        // Failed
        return false;
    }
    return true;
}

- (IBAction)run_exploit:(id)sender {
    if (!(SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"12.0") && SYSTEM_VERSION_LESS_THAN_OR_EQUAL_TO(@"12.1.2"))) {
        [self undismissableController:@"Failed" text:@"Unfortunately, your iOS version is unsupported."];
        return;
    }
    
    // SORRY - iSuperSU doesn't have an option to give root.
    if (![self voucher_swap]) {
        [self undismissableController:@"Failed" text:@"Unfortunately, your device is unsupported."];
        return;
    }
    
    // Basic post-exploitation
    [Utilities go];
    
    if (![self isJailbroken]) {
        [Utilities mobile];
        [Utilities sandbox];
        [self undismissableController:@"Failed" text:@"Please jailbreak with rootlessJB."];
        return;
    }
    
    // install and trust ldid2
    if ([[NSFileManager defaultManager] fileExistsAtPath:ldid2]) unlink(ldid2.UTF8String);
    ArchiveFile *tar = [[ArchiveFile alloc] initWithFile:[Resources stringByAppendingString:@"/ldid2.tar.gz"]];
    [tar extractToPath:ldid2.stringByDeletingLastPathComponent withFlags:DEFAULT_FLAGS overWriteDirectories:NO];
    [self trust:ldid2];
    
    // mobile & sandbox
    [Utilities mobile];
    [Utilities sandbox];
    
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

// installer

- (IBAction)installDEB:(id)sender {
    // root & unsandbox
    [Utilities root];
    [Utilities unsandbox];
    
    // symlink /var/LIB/Library to /var/LIB/ so things install correctly
    [[NSFileManager defaultManager] createSymbolicLinkAtPath:@"/var/LIB/Library" withDestinationPath:@"/var/LIB/" error:nil];
    
    // download the DEB
    NSString *deb = [Resources stringByAppendingString:@"/DEB.deb"];
    NSURL *url = [NSURL URLWithString:_debURL.text];
    if (![_debURL.text.pathExtension.lowercaseString isEqual:@"deb"]) retrn;
    if (!url) retrn;
    NSData *data = [NSData dataWithContentsOfURL:url];
    if (data) {
        [data writeToFile:deb atomically:YES];
    } else {
        retrn;
    }
    
    // checks
    {
        NSString *pkg = [Resources stringByAppendingString:@"/Package/"];
        mkdir(pkg.UTF8String, 0777);
        
        [[[ArchiveFile alloc] init] extractDEB:deb to:[Resources stringByAppendingString:@"/Package/"]];
        
        NSArray *arr = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:pkg error:nil];
        
        if (arr.count == 1 || (arr.count == 2 && [arr containsObject:@".DS_Store"])) {
            if (![arr containsObject:@"Library"]) {
                [[NSFileManager defaultManager] removeItemAtPath:pkg error:nil];
                retrn;
            }
        } else {
            [[NSFileManager defaultManager] removeItemAtPath:pkg error:nil];
            retrn;
        }
        
        [[NSFileManager defaultManager] removeItemAtPath:pkg error:nil];
    }
    
    // extract then delete the deb
    [[[ArchiveFile alloc] init] extractDEB:deb to:@"/var/LIB"];
    unlink(deb.UTF8String);
    
    // patch tweaks so they work with rootlessJB
    [self patch];
    
    // remove our symlink
    unlink("/var/LIB/Library");
    
    // mobile & sandbox
    [Utilities mobile];
    [Utilities sandbox];
    
    // success!
    [self dismissableController:@"Success" text:@"Installed tweak."];
}

// uninstaller

- (IBAction)uninstallDEB:(id)sender {
    // root & unsandbox
    [Utilities root];
    [Utilities unsandbox];
    
    // download the DEB
    NSString *deb = [Resources stringByAppendingString:@"/DEB.deb"];
    NSURL *url = [NSURL URLWithString:_debURL.text];
    if (![_debURL.text.pathExtension.lowercaseString isEqual:@"deb"]) retrn;
    if (!url) retrn;
    NSData *data = [NSData dataWithContentsOfURL:url];
    if (data) {
        [data writeToFile:deb atomically:YES];
    } else {
        retrn;
    }
    
    // create Package in our app's bundle
    NSString *pkg = [Resources stringByAppendingString:@"/Package/"];
    mkdir(pkg.UTF8String, 0777);
    
    // extract the DEB to Package then delete it
    [[[ArchiveFile alloc] init] extractDEB:deb to:pkg];
    unlink(deb.UTF8String);
    
    // get files in Package
    NSString *sourcePath = [pkg stringByAppendingString:@"Library/"];
    NSMutableArray *files = [[NSMutableArray alloc] init];
    NSURL *directoryURL = [NSURL URLWithString:sourcePath];
    NSDirectoryEnumerator *enumerator = [[NSFileManager defaultManager] enumeratorAtURL:directoryURL includingPropertiesForKeys:@[NSURLIsDirectoryKey] options:0 errorHandler:^(NSURL *url, NSError *error) {
        return YES;
    }];
    for (NSURL *url in enumerator) {
        NSString *path = [[url.path componentsSeparatedByString:@"/RootlessInstaller.app/Package/Library/"] lastObject];
        path = [@"/var/LIB/" stringByAppendingString:path];
        [files addObject:path];
    }
    
    // we're done with Package
    [[NSFileManager defaultManager] removeItemAtPath:pkg error:nil];
    
    // remove the files in the DEB from the filesystem
    for (int i = 0; i < files.count; i++) {
        NSArray *blacklist = @[@"/var/LIB/Library", @"/var/LIB/PreferenceLoader", @"/var/LIB/Frameworks", @"/var/LIB/MobileSubstrate", @"/var/LIB/MobileSubstrate/DynamicLibraries", @"/var/LIB/TweakInject", @"/var/LIB/LaunchDaemons", @"/var/LIB/PreferenceBundles", @"/var/LIB/PreferenceLoader/Preferences", @"/var/LIB/LaunchDaemons", @"/var/LIB/Frameworks", @"/var/LIB/TweakInject", @"/var/LIB", @"/var"];
        NSString *to = (NSString *)[files objectAtIndex:i];
        
        // make sure we don't delete important things
        bool remove = true;
        for (NSString *str in blacklist) {
            if ([to isEqual:str] || [to isEqual:[str stringByAppendingString:@"/"]]) {
                remove = false;
            }
        }
        
        if (remove && [[NSFileManager defaultManager] fileExistsAtPath:to]) [[NSFileManager defaultManager] removeItemAtPath:to error:nil]; // delete the file/directory
    }
    
    // idk fix a crash
    chmod([Resources stringByAppendingString:@"/RootlessInstaller"].UTF8String, 0755);
    chown([Resources stringByAppendingString:@"/RootlessInstaller"].UTF8String, 33, 33);
    
    // mobile & sandbox
    [Utilities mobile];
    [Utilities sandbox];
    
    // success!
    [self dismissableController:@"Success" text:@"Removed tweak."];
}

// respring

- (IBAction)respring:(id)sender {
    // pretty simple; unsandbox and SIGTERM SpringBoard
    [Utilities respring];
}

@end
