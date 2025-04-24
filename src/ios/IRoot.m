//
//  IRoot.m
//  Original Copyright (c) 2014 Lee Crossley - http://ilee.co.uk
//  Techniques from http://highaltitudehacks.com/2013/12/17/ios-application-security-part-24-jailbreak-detection-and-evasion/
//

#import "Cordova/CDV.h"
#import "Cordova/CDVViewController.h"
#import "IRoot.h"

#import <sys/stat.h>
#import <sys/sysctl.h>
#import <arpa/inet.h>
#import <netinet/in.h>
#import <sys/socket.h>
#import <sys/types.h>
#import <unistd.h>

#import <mach-o/dyld.h>
#import <mach/mach_time.h>
#import <mach/task.h>
#import <mach/mach_init.h>
#import <mach/vm_map.h>
#import <pthread/pthread.h>
#import <mach/vm_map.h>
#import <dlfcn.h>
#import <sys/syscall.h>

#if __has_include(<sys/ptrace.h>)
    #include <sys/ptrace.h>
    #define HAS_PTRACE 1
#else
    #define HAS_PTRACE 0
#endif



#define NOTJAIL 4783242

// Failed jailbroken checks
enum {
    // Failed the Jailbreak Check
    KFJailbroken = 3429542,
    // Failed the OpenURL Check
    KFOpenURL = 321,
    // Failed the Cydia Check
    KFCydia = 432,
    // Failed the Inaccessible Files Check
    KFIFC = 47293,
    // Failed the plist check
    KFPlist = 9412,
    // Failed the Processes Check with Cydia
    KFProcessesCydia = 10012,
    // Failed the Processes Check with other Cydia
    KFProcessesOtherCydia = 42932,
    // Failed the Processes Check with other other Cydia
    KFProcessesOtherOCydia = 10013,
    // Failed the FSTab Check
    KFFSTab = 9620,
    // Failed the System() Check
    KFSystem = 47475,
    // Failed the Symbolic Link Check
    KFSymbolic = 34859,
    // Failed the File Exists Check
    KFFileExists = 6625,
} JailbrokenChecks;

// Define the filesystem check
#define FILECHECK [NSFileManager defaultManager] fileExistsAtPath:
// Define the exe path
#define EXEPATH [[NSBundle mainBundle] executablePath]
// Define the plist path
#define PLISTPATH [[NSBundle mainBundle] infoDictionary]

// Jailbreak Check Definitions
#define CYDIA       @"MobileCydia"
#define OTHERCYDIA  @"Cydia"
#define OOCYDIA     @"afpd"
#define CYDIAPACKAGE    @"cydia://package/com.fake.package"
#define CYDIALOC        @"/Applications/Cydia.app"
#define HIDDENFILES     [NSArray arrayWithObjects:@"/Applications/RockApp.app",@"/Applications/Icy.app",@"/usr/sbin/sshd",@"/usr/bin/sshd",@"/usr/libexec/sftp-server",@"/Applications/WinterBoard.app",@"/Applications/SBSettings.app",@"/Applications/MxTube.app",@"/Applications/IntelliScreen.app",@"/Library/MobileSubstrate/DynamicLibraries/Veency.plist",@"/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",@"/private/var/lib/apt",@"/private/var/stash",@"/System/Library/LaunchDaemons/com.ikey.bbot.plist",@"/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",@"/private/var/tmp/cydia.log",@"/private/var/lib/cydia", @"/etc/clutch.conf", @"/var/cache/clutch.plist", @"/etc/clutch_cracked.plist", @"/var/cache/clutch_cracked.plist", @"/var/lib/clutch/overdrive.dylib", @"/var/root/Documents/Cracked/", nil]

/* End Jailbreak Definitions */

//nabil 4
#import <mach-o/dyld.h>
static NSString * const JMJailbreakTextFile = @"/private/jailbreak.txt";
static NSString * const JMisJailBronkenKey = @"isJailBroken";
static NSString * const JMCanMockLocationKey = @"canMockLocation";
static NSString * const JMJailBrokenMessageKey = @"jailBrokenMessage";


@implementation IRoot

- (void) isRooted:(CDVInvokedUrlCommand*)command;
{
    CDVPluginResult *pluginResult;

    @try
    {
        [IRoot denyDebugger]; // prevent debugger attachment

        if ([IRoot isSecurityViolationDetected]) {
            [self handleSecurityViolation:@"Frida/Objection or instrumentation detected"];
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsBool:YES];
            [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
            return;
        }

        bool jailbroken = [self jailbroken];
		//nabil 3
		bool jailMonkeybroken = [self isJailMonkeyBroken];
        bool finalJailBroken = jailbroken || jailMonkeybroken;
		
		//NSLog(TARGET_OS_SIMULATOR ? @" nabil TARGET_OS_SIMULATOR true" : @" nabil TARGET_OS_SIMULATOR false");
		//NSLog(TARGET_IPHONE_SIMULATOR ? @" nabil TARGET_IPHONE_SIMULATOR true" : @" nabil TARGET_IPHONE_SIMULATOR false");
		//NSLog(jailbroken ? @" nabil jailbroken true" : @" nabil jailbroken false");
		//NSLog(jailMonkeybroken ? @" nabil jailMonkeybroken true" : @" nabil jailMonkeybroken false");
		//NSLog(finalJailBroken ? @" nabil finalJailBroken true" : @" nabil finalJailBroken false");
		
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsBool:finalJailBroken];
    }
    @catch (NSException *exception)
    {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:exception.reason];
    }
    @finally
    {
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
}

- (BOOL)isShadowToolPresent {
    // Check for common Shadow tool files or processes
    NSArray *shadowPaths = @[
        @"/usr/libexec/shadow",
        @"/usr/local/bin/shadow",
        @"/Applications/Shadow.app",
        @"/Library/MobileSubstrate/DynamicLibraries/Shadow.dylib",
        @"/Library/MobileSubstrate/DynamicLibraries/ShadowHide.dylib",
        @"/var/lib/shadow",
        @"/var/mobile/Library/Preferences/com.shadowapp.shadow.plist",
        @"/private/var/tmp/shadow.log"
    ];

    for (NSString *path in shadowPaths) {
        if (access([path UTF8String], F_OK) != -1) {
            NSLog(@"Shadow tool detected at path: %@", path);
            return YES;
        }
    }

    // Check for Shadow running processes
    NSArray *runningProcesses = [self runningProcesses];
    NSArray *shadowProcesses = @[@"shadow", @"ShadowProcess", @"com.shadowapp.shadow"];
    for (NSDictionary *process in runningProcesses) {
        NSString *processName = process[@"ProcessName"];
        for (NSString *shadowProcess in shadowProcesses) {
            if ([processName rangeOfString:shadowProcess options:NSCaseInsensitiveSearch].location != NSNotFound) {
                NSLog(@"Shadow tool process detected: %@", processName);
                return YES;
            }
        }
    }

    // Check for Shadow tool injected libraries
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *imageName = _dyld_get_image_name(i);
        if (strstr(imageName, "Shadow") || strstr(imageName, "shadow")) {
            NSLog(@"Shadow tool library loaded: %s", imageName);
            return YES;
        }
    }

    // Use system calls to detect process injection
    struct kinfo_proc info;
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    size_t size = sizeof(info);
    sysctl(mib, 4, &info, &size, NULL, 0);
    if (info.kp_proc.p_flag & P_TRACED) {
        NSLog(@"Shadow tool detected via process tracing!");
        return YES;
    }


    NSLog(@"Shadow tool not detected.");
    return NO; // Shadow tool not detected
}

- (bool) jailbroken {
//nabil 2 TARGET_OS_SIMULATOR
//NSLog(@"nabil in jailbroken");

#if !(TARGET_IPHONE_SIMULATOR)

	if ([self isShadowToolPresent]) {
        return YES; // Device is considered jailbroken
    }

    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/Applications/Cydia.app"])
    {
        return YES;
    }
    else if ([[NSFileManager defaultManager] fileExistsAtPath:@"/Library/MobileSubstrate/MobileSubstrate.dylib"])
    {
        return YES;
    }
    else if ([[NSFileManager defaultManager] fileExistsAtPath:@"/bin/bash"])
    {
        return YES;
    }
    else if ([[NSFileManager defaultManager] fileExistsAtPath:@"/usr/sbin/sshd"])
    {
        return YES;
    }
    else if ([[NSFileManager defaultManager] fileExistsAtPath:@"/etc/apt"])
    {
        return YES;
    }

    FILE *f = NULL ;
    if ((f = fopen("/bin/bash", "r")) ||
        (f = fopen("/Applications/Cydia.app", "r")) ||
        (f = fopen("/Library/MobileSubstrate/MobileSubstrate.dylib", "r")) ||
        (f = fopen("/usr/sbin/sshd", "r")) ||
        (f = fopen("/etc/apt", "r")) ||

        (f = fopen("/private/var/stash", "r")) ||
        (f = fopen("/private/var/lib/apt", "r")) ||
        (f = fopen("/private/var/tmp/cydia.log", "r")) ||
        (f = fopen("/private/var/lib/cydia", "r")) ||
        (f = fopen("/private/var/mobile/Library/SBSettings/Themes", "r")) ||

        (f = fopen("/Library/MobileSubstrate/MobileSubstrate.dylib", "r")) ||
        (f = fopen("/Library/MobileSubstrate/DynamicLibraries/Veency.plist", "r")) ||
        (f = fopen("/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist", "r")) ||
        (f = fopen("/System/Library/LaunchDaemons/com.ikey.bbot.plist", "r")) ||
        (f = fopen("/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist", "r")) ||

        (f = fopen("/var/cache/apt", "r")) ||
        (f = fopen("/var/lib/apt", "r")) ||
        (f = fopen("/var/lib/cydia", "r")) ||
        (f = fopen("/var/log/syslog", "r")) ||
        (f = fopen("/var/tmp/cydia.log", "r")) ||

        (f = fopen("/bin/bash", "r")) ||
        (f = fopen("/bin/sh", "r")) ||
        (f = fopen("/usr/libexec/ssh-keysign", "r")) ||
        (f = fopen("/usr/bin/sshd", "r")) ||
        (f = fopen("/usr/libexec/sftp-server", "r")) ||

        (f = fopen("/etc/ssh/sshd_config", "r")) ||
        (f = fopen("/etc/apt", "r")) ||
        (f = fopen("/Applications/Cydia.app", "r")) ||
        (f = fopen("/Applications/RockApp.app", "r")) ||
        (f = fopen("/Applications/Icy.app", "r")) ||

        (f = fopen("/Applications/WinterBoard.app", "r")) ||
        (f = fopen("/Applications/SBSettings.app", "r")) ||
        (f = fopen("/Applications/MxTube.app", "r")) ||
        (f = fopen("/Applications/IntelliScreen.app", "r")) ||
        (f = fopen("/Applications/FakeCarrier.app", "r")) ||

        (f = fopen("/Applications/blackra1n.app", "r")) ||
        (f = fopen("/Applications/IntelliScreen.app", "r")) ||
        (f = fopen("/Applications/FakeCarrier.app", "r")) ||
        (f = fopen("/usr/bin/frida-server", "r")) ||
        (f = fopen("/usr/local/bin/cycript", "r")) ||

        (f = fopen("/usr/lib/libcycript.dylib", "r"))
        )  {
        fclose(f);
        return YES;
    }
    fclose(f);


    NSError *error;
    NSString *testWriteText = @"Jailbreak test";
    NSString *testWritePath = @"/private/jailbreaktest.txt";

    [testWriteText writeToFile:testWritePath atomically:YES encoding:NSUTF8StringEncoding error:&error];

    if (error == nil)
    {
        [[NSFileManager defaultManager] removeItemAtPath:testWritePath error:nil];
        return YES;
    }
    else
    {
        [[NSFileManager defaultManager] removeItemAtPath:testWritePath error:nil];
    }

    if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"cydia://package/com.example.package"]])
    {
        return YES;
    }

    //Symbolic link verification
    struct stat s;
    if(lstat("/Applications", &s) || lstat("/var/stash/Library/Ringtones", &s) || lstat("/var/stash/Library/Wallpaper", &s)
       || lstat("/var/stash/usr/include", &s) || lstat("/var/stash/usr/libexec", &s)  || lstat("/var/stash/usr/share", &s) || lstat("/var/stash/usr/arm-apple-darwin9", &s))
    {
        if(s.st_mode & S_IFLNK){
            return YES;
        }
    }

    //Try to write file in private

    [[NSString stringWithFormat:@"test string"]
     writeToFile:@"/private/test_jb.txt"
     atomically:YES
     encoding:NSUTF8StringEncoding error:&error];

    if(nil==error){
        //Wrote?: JB device
        //cleanup what you wrote
        [[NSFileManager defaultManager] removeItemAtPath:@"/private/test_jb.txt" error:nil];
        return YES;
    }

    //New Plugin
    // Make an int to monitor how many checks are failed
    int motzart = 0;

    // URL Check
    if ([self urlCheck] != NOTJAIL) {
        // Jailbroken
        motzart += 3;
    }

    // Cydia Check
    if ([self cydiaCheck] != NOTJAIL) {
        // Jailbroken
        motzart += 3;
    }

    // Inaccessible Files Check
    if ([self inaccessibleFilesCheck] != NOTJAIL) {
        // Jailbroken
        motzart += 2;
    }

    // Plist Check
    if ([self plistCheck] != NOTJAIL) {
        // Jailbroken
        motzart += 2;
    }

    // Processes Check
    if ([self processesCheck] != NOTJAIL) {
        // Jailbroken
        motzart += 2;
    }

    // FSTab Check
    if ([self fstabCheck] != NOTJAIL) {
        // Jailbroken
        motzart += 1;
    }

    // Shell Check
    if ([self systemCheck] != NOTJAIL) {
        // Jailbroken
        motzart += 2;
    }

    // Symbolic Link Check
    if ([self symbolicLinkCheck] != NOTJAIL) {
        // Jailbroken
        motzart += 2;
    }

    // FilesExist Integrity Check
    if ([self filesExistCheck] != NOTJAIL) {
        // Jailbroken
        motzart += 2;
    }
	
	if ([self checkFork] != NOTJAIL) {
        // Frida
        motzart += 2;
    }

    if ([self isFridaRunning] != NOTJAIL) {
        // Frida
        motzart += 2;
    }

    if ([self isFridaInjected] != NOTJAIL) {
        // Frida
        motzart += 2;
    }

    if ([self isDebugged] != NOTJAIL) {
        // Jailbroken
        motzart += 2;
    }

    // Check if the Jailbreak Integer is 3 or more
    if (motzart >= 3) {
        // Jailbroken
        return YES;
    }

#endif

    return NO;
}


#pragma mark - Static Jailbreak Checks

// Detect if the process is being debugged
- (int)isDebugged {
    @try {
        struct kinfo_proc info;
        int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
        size_t size = sizeof(info);
        sysctl(mib, 4, &info, &size, NULL, 0);
        return (info.kp_proc.p_flag & P_TRACED) != 0 ? KFSystem : NOTJAIL;
    }

    @catch (NSException *exception) {
        // Error, return false
        return NOTJAIL;
    }
}


// Detect FridaGadget
- (int)isFridaInjected {
    @try {
        for (uint32_t i = 0; i < _dyld_image_count(); i++) {
            const char *dyld = _dyld_get_image_name(i);
            if (strstr(dyld, "FridaGadget")) {
                return KFSystem;
            }
        }
        return NOTJAIL;
    }

    @catch (NSException *exception) {
        // Error, return false
        return NOTJAIL;
    }
}

// Check Frida port
- (int)isFridaRunning {
    @try {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(27042); // Frida default port
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        BOOL isOpen = connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0;
        close(sock);
        return isOpen ? KFSystem : NOTJAIL;
    }

    @catch (NSException *exception) {
        // Error, return false
        return NOTJAIL;
    }
}

// Fork function is desabled in normal system
- (int)checkFork {
    @try {
        int pid = fork();
        if (pid >= 0) {
            return KFSystem;
        }
        return NOTJAIL;
    }

    @catch (NSException *exception) {
        // Error, return false
        return NOTJAIL;
    }
}

// UIApplication CanOpenURL Check
- (int)urlCheck {
    @try {
        // Create a fake url for cydia
        NSURL *FakeURL = [NSURL URLWithString:CYDIAPACKAGE];
        // Return whether or not cydia's openurl item exists
        if ([[UIApplication sharedApplication] canOpenURL:FakeURL])
            return KFOpenURL;
        else
            return NOTJAIL;
    }
    @catch (NSException *exception) {
        // Error, return false
        return NOTJAIL;
    }
}

// Cydia Check
- (int)cydiaCheck {
    @try {
        // Create a file path string
        NSString *filePath = CYDIALOC;
        // Check if it exists
        if ([[NSFileManager defaultManager] fileExistsAtPath:filePath]) {
            // It exists
            return KFCydia;
        } else {
            // It doesn't exist
            return NOTJAIL;
        }
    }
    @catch (NSException *exception) {
        // Error, return false
        return NOTJAIL;
    }
}

// Inaccessible Files Check
- (int)inaccessibleFilesCheck {
    @try {
        // Run through the array of files
        for (NSString *key in HIDDENFILES) {
            // Check if any of the files exist (should return no)
            if ([[NSFileManager defaultManager] fileExistsAtPath:key]) {
                // Jailbroken
                return KFIFC;
            }
        }

        // Shouldn't get this far, return jailbroken
        return NOTJAIL;
    }
    @catch (NSException *exception) {
        // Error, return false
        return NOTJAIL;
    }
}

// Plist Check
- (int)plistCheck {
    @try {
        // Define the Executable name
        NSString *ExeName = EXEPATH;
        NSDictionary *ipl = PLISTPATH;
        // Check if the plist exists
        if ([FILECHECK ExeName] == FALSE || ipl == nil || ipl.count <= 0) {
            // Executable file can't be found and the plist can't be found...hmmm
            return KFPlist;
        } else {
            // Everything is good
            return NOTJAIL;
        }
    }
    @catch (NSException *exception) {
        // Error, return false
        return NOTJAIL;
    }
}

// Running Processes Check
- (int)processesCheck {
    @try {
        // Make a processes array
        NSArray *processes = [self runningProcesses];

        // Check for Cydia in the running processes
        for (NSDictionary * dict in processes) {
            // Define the process name
            NSString *process = [dict objectForKey:@"ProcessName"];
            // If the process is this executable
            if ([process isEqualToString:CYDIA]) {
                // Return Jailbroken
                return KFProcessesCydia;
            } else if ([process isEqualToString:OTHERCYDIA]) {
                // Return Jailbroken
                return KFProcessesOtherCydia;
            } else if ([process isEqualToString:OOCYDIA]) {
                // Return Jailbroken
                return KFProcessesOtherOCydia;
            }
        }

        // Not Jailbroken
        return NOTJAIL;
    }
    @catch (NSException *exception) {
        // Error
        return NOTJAIL;
    }
}

// FSTab Size
- (int)fstabCheck {
    @try {
        struct stat sb;
        stat("/etc/fstab", &sb);
        long long size = sb.st_size;
        if (size == 80) {
            // Not jailbroken
            return NOTJAIL;
        } else
            // Jailbroken
            return KFFSTab;
    }
    @catch (NSException *exception) {
        // Not jailbroken
        return NOTJAIL;
    }
}

// System() available
- (int)systemCheck {
    @try {
        // See if the system call can be used
        /*if (system(0)) {
            // Jailbroken
            return KFSystem;
        } else*/
            // Not Jailbroken
            return NOTJAIL;
    }
    @catch (NSException *exception) {
        // Not Jailbroken
        return NOTJAIL;
    }
}

// Symbolic Link available
- (int)symbolicLinkCheck {
    @try {
        // See if the Applications folder is a symbolic link
        struct stat s;
        if (lstat("/Applications", &s) != 0) {
            if (s.st_mode & S_IFLNK) {
                // Device is jailbroken
                return KFSymbolic;
            } else
                // Not jailbroken
                return NOTJAIL;
        } else {
            // Not jailbroken
            return NOTJAIL;
        }
    }
    @catch (NSException *exception) {
        // Not Jailbroken
        return NOTJAIL;
    }
}

// FileSystem working correctly?
- (int)filesExistCheck {
    @try {
        // Check if filemanager is working
        if (![FILECHECK [[NSBundle mainBundle] executablePath]]) {
            // Jailbroken and trying to hide it
            return KFFileExists;
        } else
            // Not Jailbroken
            return NOTJAIL;
    }
    @catch (NSException *exception) {
        // Not Jailbroken
        return NOTJAIL;
    }
}

// Get the running processes
- (NSArray *)runningProcesses {
    // Define the int array of the kernel's processes
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t miblen = 4;

    // Make a new size and int of the sysctl calls
    size_t size;
    int st = sysctl(mib, miblen, NULL, &size, NULL, 0);

    // Make new structs for the processes
    struct kinfo_proc * process = NULL;
    struct kinfo_proc * newprocess = NULL;

    // Do get all the processes while there are no errors
    do {
        // Add to the size
        size += size / 10;
        // Get the new process
        newprocess = realloc(process, size);
        // If the process selected doesn't exist
        if (!newprocess){
            // But the process exists
            if (process){
                // Free the process
                free(process);
            }
            // Return that nothing happened
            return nil;
        }

        // Make the process equal
        process = newprocess;

        // Set the st to the next process
        st = sysctl(mib, miblen, process, &size, NULL, 0);

    } while (st == -1 && errno == ENOMEM);

    // As long as the process list is empty
    if (st == 0){

        // And the size of the processes is 0
        if (size % sizeof(struct kinfo_proc) == 0){
            // Define the new process
            int nprocess = size / sizeof(struct kinfo_proc);
            // If the process exists
            if (nprocess){
                // Create a new array
                NSMutableArray * array = [[NSMutableArray alloc] init];
                // Run through a for loop of the processes
                for (int i = nprocess - 1; i >= 0; i--){
                    // Get the process ID
                    NSString * processID = [[NSString alloc] initWithFormat:@"%d", process[i].kp_proc.p_pid];
                    // Get the process Name
                    NSString * processName = [[NSString alloc] initWithFormat:@"%s", process[i].kp_proc.p_comm];
                    // Get the process Priority
                    NSString *processPriority = [[NSString alloc] initWithFormat:@"%d", process[i].kp_proc.p_priority];
                    // Get the process running time
                    NSDate   *processStartDate = [NSDate dateWithTimeIntervalSince1970:process[i].kp_proc.p_un.__p_starttime.tv_sec];
                    // Create a new dictionary containing all the process ID's and Name's
                    NSDictionary *dict = [[NSDictionary alloc] initWithObjects:[NSArray arrayWithObjects:processID, processPriority, processName, processStartDate, nil]
                                                                       forKeys:[NSArray arrayWithObjects:@"ProcessID", @"ProcessPriority", @"ProcessName", @"ProcessStartDate", nil]];

                    // Add the dictionary to the array
                    [array addObject:dict];
                }
                // Free the process array
                free(process);

                // Return the process array
                return array;

            }
        }
    }

    // If no processes are found, return nothing
    return nil;
}


// nabil 1 jailMonkey ////////////////////////////////////////////////////// 
////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////


- (NSArray *)pathsToCheck
{
    return @[
            @"/.bootstrapped_electra",
            @"/.cydia_no_stash",
            @"/.installed_unc0ver",
            @"/Applications/Cydia.app",
            @"/Applications/FakeCarrier.app",
            @"/Applications/Icy.app",
            @"/Applications/IntelliScreen.app",
            @"/Applications/MxTube.app",
            @"/Applications/RockApp.app",
            @"/Applications/SBSettings.app",
            @"/Applications/Sileo.app",
            @"/Applications/Snoop-itConfig.app",
            @"/Applications/WinterBoard.app",
            @"/Applications/blackra1n.app",
            @"/Library/MobileSubstrate/CydiaSubstrate.dylib",
            @"/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
            @"/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
            @"/Library/MobileSubstrate/MobileSubstrate.dylib",
            @"/Library/PreferenceBundles/ABypassPrefs.bundle",
            @"/Library/PreferenceBundles/FlyJBPrefs.bundle",
            @"/Library/PreferenceBundles/LibertyPref.bundle",
            @"/Library/PreferenceBundles/ShadowPreferences.bundle",
            @"/System/Library/LaunchDaemons/com.ikey.bbot.plist",
            @"/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
            @"/bin/bash",
            @"/bin/sh",
            @"/etc/apt",
            @"/etc/apt/sources.list.d/electra.list",
            @"/etc/apt/sources.list.d/sileo.sources",
            @"/etc/apt/undecimus/undecimus.list",
            @"/etc/ssh/sshd_config",
            @"/jb/amfid_payload.dylib",
            @"/jb/jailbreakd.plist",
            @"/jb/libjailbreak.dylib",
            @"/jb/lzma",
            @"/jb/offsets.plist",
            @"/private/etc/apt",
            @"/private/etc/dpkg/origins/debian",
            @"/private/etc/ssh/sshd_config",
            @"/private/var/Users/",
            @"/private/var/cache/apt/",
            @"/private/var/lib/apt",
            @"/private/var/lib/cydia",
            @"/private/var/log/syslog",
            @"/private/var/mobile/Library/SBSettings/Themes",
            @"/private/var/stash",
            @"/private/var/tmp/cydia.log",
            @"/usr/bin/cycript",
            @"/usr/bin/sshd",
            @"/usr/lib/libcycript.dylib",
            @"/usr/lib/libhooker.dylib",
            @"/usr/lib/libjailbreak.dylib",
            @"/usr/lib/libsubstitute.dylib",
            @"/usr/lib/substrate",
            @"/usr/lib/TweakInject",
            @"/usr/libexec/cydia",
            @"/usr/libexec/cydia/firmware.sh",
            @"/usr/libexec/sftp-server",
            @"/usr/libexec/ssh-keysign",
            @"/usr/local/bin/cycript",
            @"/usr/sbin/frida-server",
            @"/usr/sbin/sshd",
            @"/usr/share/jailbreak/injectme.plist",
            @"/var/binpack",
            @"/var/cache/apt",
            @"/var/checkra1n.dmg",
            @"/var/lib/apt",
            @"/var/lib/cydia",
            @"/var/lib/dpkg/info/mobilesubstrate.md5sums",
            @"/var/log/apt"
            ];
}

- (NSArray *)schemesToCheck
{
    return @[
            @"activator://package/com.example.package",
            @"cydia://package/com.example.package",
            @"filza://package/com.example.package",
            @"sileo://package/com.example.package",
            @"undecimus://package/com.example.package",
            @"zbra://package/com.example.package"
            ];
}

- (NSArray *)symlinksToCheck
{
    return @[
            @"/var/lib/undecimus/apt",
            @"/Applications",
            @"/Library/Ringtones",
            @"/Library/Wallpaper",
            @"/usr/arm-apple-darwin9",
            @"/usr/include",
            @"/usr/libexec",
            @"/usr/share"
            ];
}

- (NSArray *)dylibsToCheck
{
    return @[
            @"...!@#",
            @"/.file",
            @"/usr/lib/Cephei.framework/Cephei",
            @"0Shadow.dylib",
            @"ABypass",
            @"Cephei",
            @"CustomWidgetIcons",
            @"CydiaSubstrate",
            @"Electra",
            @"FlyJB",
            @"FridaGadget",
            @"MobileSubstrate.dylib",
            @"PreferenceLoader",
            @"RocketBootstrap",
            @"SSLKillSwitch.dylib",
            @"SSLKillSwitch2.dylib",
            @"Substitute",
            @"SubstrateBootstrap",
            @"SubstrateInserter",
            @"SubstrateInserter.dylib",
            @"SubstrateLoader.dylib",
            @"TweakInject.dylib",
            @"WeeLoader",
            @"cyinject",
            @"libcycript",
            @"libhooker",
            @"libsparkapplist.dylib",
            @"zzzzLiberty.dylib",
            @"zzzzzzUnSub.dylib"
            ];
}

- (BOOL)checkPaths
{
    BOOL existsPath = NO;

    for (NSString *path in [self pathsToCheck]) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:path]){
            existsPath = YES;
            break;
        }
    }

    return existsPath;
}

- (BOOL)checkSchemes
{
    BOOL canOpenScheme = NO;

    for (NSString *scheme in [self schemesToCheck]) {
        if([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:scheme]]){
            canOpenScheme = YES;
            break;
        }
    }

    return canOpenScheme;
}

- (BOOL)checkDylibs
{
    NSString *imagePath;

    for (int i=0; i < _dyld_image_count(); i++) {
        imagePath = [NSString stringWithUTF8String:_dyld_get_image_name(i)];

        for (NSString *dylibPath in [self dylibsToCheck]) {
            if([imagePath localizedCaseInsensitiveContainsString:dylibPath]) {
                return YES;
            }
        }
    }

    return NO;
}

- (BOOL)canViolateSandbox{
	NSError *error;
    BOOL grantsToWrite = NO;
	NSString *stringToBeWritten = @"This is an anti-spoofing test.";
	[stringToBeWritten writeToFile:JMJailbreakTextFile atomically:YES
						  encoding:NSUTF8StringEncoding error:&error];
	if(!error){
		//Device is jailbroken
		grantsToWrite = YES;
	}

    [[NSFileManager defaultManager] removeItemAtPath:JMJailbreakTextFile error:nil];

    return grantsToWrite;
}

- (BOOL)canFork
{
    int pid = fork();
    if(!pid) {
        exit(1);
    }
    if(pid >= 0) {
        return YES;
    }

    return NO;
}

- (BOOL)checkSymlinks
{
    for (NSString *symlink in [self symlinksToCheck]) {
        NSString* result = [[NSFileManager defaultManager] destinationOfSymbolicLinkAtPath:symlink error:nil];
        if([result length] > 0) {
            return YES;
        }
    }

    return NO;
}


- (BOOL)isJailMonkeyBroken{
	//NSLog(@"nabil in isJailMonkeyBroken");
    #if TARGET_OS_SIMULATOR
      return NO;
    #endif
    BOOL isiOSAppOnMac = false;

    #if defined(__IPHONE_14_0) && __IPHONE_OS_VERSION_MAX_ALLOWED >= 140000
        if (@available(iOS 14.0, *)) {
            // Early iOS 14 betas do not include isiOSAppOnMac
            isiOSAppOnMac = (
                [[NSProcessInfo processInfo] respondsToSelector:@selector(isiOSAppOnMac)] &&
                [NSProcessInfo processInfo].isiOSAppOnMac
            );
        }
    #endif // defined(__IPHONE_14_0) && __IPHONE_OS_VERSION_MAX_ALLOWED >= 140000

    if (isiOSAppOnMac) {
        return false;
    }
    return [self checkPaths] || [self checkSchemes] || [self canViolateSandbox] || [self canFork] || [self checkSymlinks] || [self checkDylibs];
}


// nabil 1 end jailMonkey //////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////

//nabil provision profile

- (NSString *) returnAppDetailsMobProv
{

    NSString *profilePath = [[NSBundle mainBundle] pathForResource:@"embedded" ofType:@"mobileprovision"];
    // Check provisioning profile existence
    if (profilePath)
    {
        // Get hex representation
        NSData *profileData = [NSData dataWithContentsOfFile:profilePath];
        NSString *profileString;
        
        if ([[[UIDevice currentDevice] systemVersion] floatValue] >= 13.0)
        {
            NSUInteger dataLength = [profileData length];
            NSMutableString *string =[NSMutableString stringWithCapacity:dataLength*2];

            const unsigned char *dataBytes = [profileData bytes];
            for (NSInteger idx = 0; idx < dataLength; ++idx)
            {
                [string appendFormat:@"%02x", dataBytes[idx]];
            }
            
            profileString = string;

        }
        else
        {
            profileString = [NSString stringWithFormat:@"%@", profileData];
            
            // Remove brackets at beginning and end
            profileString = [profileString stringByReplacingCharactersInRange:NSMakeRange(0, 1) withString:@""];
            profileString = [profileString stringByReplacingCharactersInRange:NSMakeRange(profileString.length - 1, 1) withString:@""];

            // Remove spaces
            profileString = [profileString stringByReplacingOccurrencesOfString:@" " withString:@""];
        }

        // Convert hex values to readable characters
        NSMutableString *profileText = [NSMutableString new];
        for (int i = 0; i < profileString.length; i += 2)
        {
            NSString *hexChar = [profileString substringWithRange:NSMakeRange(i, 2)];
            int value = 0;
            sscanf([hexChar cStringUsingEncoding:NSASCIIStringEncoding], "%x", &value);
            [profileText appendFormat:@"%c", (char)value];
        }
        
        // Remove whitespaces and newline characters
        NSArray *profileWords = [profileText componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        
        // There must be a better word to search through this as a structure! Need 'string' sibling to <key>UUID</key>
        BOOL siblingUUID = false;
	NSString *myUUID = @"";
	
	BOOL siblingTeamName = false;
	NSString *myTeamName = @"";
	
	BOOL siblingTeamId = false;
	NSString *myTeamId = @"";
	
        for (NSString* word in profileWords){
	
	    // get the UUID	
            if ([word isEqualToString:@"<key>UUID</key>"]){
                //NSLog(@"Got to the key UUID, now need the string!");
                siblingUUID = true;
            }
            if (siblingUUID && ([word rangeOfString:@"<string>"].location != NSNotFound)) {
                //NSLog(@"UUID: %@", word);
                myUUID = word;
		siblingUUID = false;
            }
	    
	    // get the Team Name	
            if ([word isEqualToString:@"<key>TeamName</key>"]){
                //NSLog(@"Got to the key TeamName, now need the string!");
                siblingTeamName = true;
            }
            if (siblingTeamName && ([word rangeOfString:@"<string>"].location != NSNotFound)) {
                //NSLog(@"Team Name: %@", word);
                myTeamName = word;
		siblingTeamName = false;
            }
	    
	    // get the Team Id	
            if ([word isEqualToString:@"<key>TeamIdentifier</key>"]){
                //NSLog(@"Got to the key TeamIdentifier, now need the string!");
                siblingTeamId = true;
            }
            if (siblingTeamId && ([word rangeOfString:@"<string>"].location != NSNotFound)) {
                //NSLog(@"Team Name: %@", word);
                myTeamId = word;
		siblingTeamId = false;
            }
        }
	
	NSString *newMyTeamId = [myTeamId stringByReplacingOccurrencesOfString: @"<string>" withString:@""];
	newMyTeamId = [newMyTeamId stringByReplacingOccurrencesOfString: @"</string>" withString:@""];
	
	
	NSString *newMyTeamName = [myTeamName stringByReplacingOccurrencesOfString: @"<string>" withString:@""];
	newMyTeamName = [newMyTeamName stringByReplacingOccurrencesOfString: @"</string>" withString:@""];
	
	
	NSString *newMyUUID = [myUUID stringByReplacingOccurrencesOfString: @"<string>" withString:@""];
	newMyUUID = [newMyUUID stringByReplacingOccurrencesOfString: @"</string>" withString:@""];
	
	return [NSString stringWithFormat:@"{ \"TeamId\" : \"%@\" , \"TeamName\" : \"%@\" , \"UUID\" : \"%@\"  }", newMyTeamId, newMyTeamName, newMyUUID ];
    }
    //else
    //NSLog(@"profile path is null");
    
    //NSLog(@"Could not find app UUID");
    
    return @"";
}


- (NSString *) returnAppDetailsKeyChain {
    NSString *tempAccountName = @"bundleSeedID";
    NSDictionary *query = @{
        (__bridge NSString *)kSecClass : (__bridge NSString *)kSecClassGenericPassword,
        (__bridge NSString *)kSecAttrAccount : tempAccountName,
        (__bridge NSString *)kSecAttrService : @"",
        (__bridge NSString *)kSecReturnAttributes: (__bridge NSNumber *)kCFBooleanTrue,
    };
    CFDictionaryRef result = nil;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);
    if (status == errSecItemNotFound)
        status = SecItemAdd((__bridge CFDictionaryRef)query, (CFTypeRef *)&result);
    if (status != errSecSuccess) {
        return nil;
    }
    status = SecItemDelete((__bridge CFDictionaryRef)query); // remove temp item
    NSDictionary *dict = (__bridge_transfer NSDictionary *)result;
    NSString *accessGroup = dict[(__bridge NSString *)kSecAttrAccessGroup];
    NSArray *components = [accessGroup componentsSeparatedByString:@"."];
    NSString *bundleSeedID = [[components objectEnumerator] nextObject];
    //return bundleSeedID;
    return [NSString stringWithFormat:@"{ \"TeamId\" : \"%@\" }", bundleSeedID];
}


- (void) returnAppDetails:(CDVInvokedUrlCommand*)command;
{
    CDVPluginResult *pluginResult;
    NSString *appDetails;
    @try
    {
        if ([[NSBundle mainBundle] pathForResource:@"embedded" ofType:@"mobileprovision"]) {
            // not from app store (Apple's reviewers seem to hit this path)
            appDetails = [self returnAppDetailsMobProv];
        } else {
            // from app store
            appDetails = [self returnAppDetailsKeyChain];
        }

		
        //NSLog(@"appDetails = %@", appDetails);

        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:appDetails];
    }
    @catch (NSException *exception)
    {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:exception.reason];
    }
    @finally
    {
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
}

//end nabil provision profile

#pragma mark - Enhanced Runtime Detection for Frida / Objection

+ (BOOL)isSecurityViolationDetected {
    return [self isDebuggerAttached] ||
           [self isBinaryTampered] ||
           [self checkDebuggerWithTiming] ||
           [self isFridaLibLoaded] ||
           [self isFridaDetected] ||
           [self isFridaPortOpen] ||
           [self scanProcessesForMaliciousTools] ||
           [self isSubstrateLoaded] ||
           [self checkForSuspiciousSymbols] ||
           [self checkFileIntegrity] ||
           [self detectSSLKillSwitch] ||
           [self checkForHookingFrameworks];
}

+ (BOOL)isDebuggerAttached {
    // Check via sysctl
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t size = sizeof(info);
    sysctl(mib, 4, &info, &size, NULL, 0);
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

+ (BOOL)isBinaryTampered {
    const struct mach_header *header = _dyld_get_image_header(0);
    struct load_command *cmd = (struct load_command *)((char *)header + sizeof(struct mach_header));
    
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (cmd->cmd == LC_CODE_SIGNATURE) {
            struct linkedit_data_command *lc = (struct linkedit_data_command *)cmd;
            void *signature = (char *)header + lc->dataoff;
            
            // Simple check - in production you'd verify the signature properly
            if (lc->datasize < 100) { // Suspiciously small signature
                return YES;
            }
        }
        cmd = (struct load_command *)((char *)cmd + cmd->cmdsize);
    }
    return NO;
}

+ (BOOL)checkDebuggerWithTiming {
    // Debuggers slow down execution
    uint64_t start = mach_absolute_time();
    // Do some meaningless work
    for (int i = 0; i < 100000; i++) {
        rand();
    }
    uint64_t end = mach_absolute_time();
    
    // Convert to nanoseconds
    mach_timebase_info_data_t timebase;
    mach_timebase_info(&timebase);
    uint64_t elapsed = (end - start) * timebase.numer / timebase.denom;
    
    // If it took more than 50ms, likely under debugger
    return elapsed > 50000000;
}

+ (BOOL)isFridaLibLoaded {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && (strstr(name, "frida") || strstr(name, "gum-js-loop") || strstr(name, "libfrida"))) {
            return YES;
        }
    }
    return NO;
}

+ (BOOL)isFridaDetected {
    // Check for Frida environment variables
    char *env = getenv("DYLD_INSERT_LIBRARIES");
    if (env && (strstr(env, "frida") || strstr(env, "gum"))) {
        return YES;
    }
    
    // Check for Frida thread names
    mach_msg_type_number_t count;
    thread_act_array_t list;
    task_threads(mach_task_self(), &list, &count);
    for (int i = 0; i < count; i++) {
        char name[128];
        pthread_getname_np(pthread_from_mach_thread_np(list[i]), name, sizeof(name));
        if (strstr(name, "frida") || strstr(name, "gum-js-loop")) {
            vm_deallocate(mach_task_self(), (vm_address_t)list, count * sizeof(thread_act_t));
            return YES;
        }
    }
    vm_deallocate(mach_task_self(), (vm_address_t)list, count * sizeof(thread_act_t));
    
    return NO;
}

+ (BOOL)isFridaPortOpen {
    // Common Frida/objection ports plus some randomization
    int ports[] = {27042, 27043, 4242, 4711, 1337, 31337, 9999};
    
    for (int i = 0; i < sizeof(ports)/sizeof(int); i++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(ports[i]);
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        
        int result = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
        close(sock);
        if (result == 0) {
            return YES;
        }
    }
    return NO;
}

+ (BOOL)scanProcessesForMaliciousTools {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t size;
    if (sysctl(mib, 4, NULL, &size, NULL, 0) != 0) return NO;

    struct kinfo_proc *procs = malloc(size);
    if (procs == NULL) return NO;

    if (sysctl(mib, 4, procs, &size, NULL, 0) != 0) {
        free(procs);
        return NO;
    }

    int count = size / sizeof(struct kinfo_proc);
    BOOL found = NO;

    for (int i = 0; i < count; i++) {
        char *name = procs[i].kp_proc.p_comm;
        if (strstr(name, "frida") || strstr(name, "objection") || strstr(name, "lldb") || strstr(name, "cycript")) {
            found = YES;
            break;
        }
    }

    free(procs);
    return found;
}


+ (BOOL)isSubstrateLoaded {
    return (NSClassFromString(@"MSFSP") != nil || NSClassFromString(@"Cydia") != nil || dlopen("/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", RTLD_NOW) != NULL);
}

+ (BOOL)checkForSuspiciousSymbols {
    // Check for suspicious symbols that might indicate hooking
    void *handle = dlopen(NULL, RTLD_GLOBAL | RTLD_NOW);
    if (dlsym(handle, "MSHookFunction") || dlsym(handle, "MSFindSymbol")) {
        dlclose(handle);
        return YES;
    }
    dlclose(handle);
    return NO;
}

+ (BOOL)checkFileIntegrity {
    // Check if certain system files have been modified
    struct stat sb;
    if (stat("/bin/bash", &sb) == 0 || stat("/etc/apt", &sb) == 0) {
        return YES;
    }
    return NO;
}

+ (BOOL)detectSSLKillSwitch {
    // Check for SSL Kill Switch, a common tool used with Frida
    return (dlopen("/Library/MobileSubstrate/DynamicLibraries/SSLKillSwitch.dylib", RTLD_NOW) != NULL) ||
           (dlopen("/Library/MobileSubstrate/DynamicLibraries/SSLKillSwitch2.dylib", RTLD_NOW) != NULL);
}

+ (BOOL)checkForHookingFrameworks {
    NSArray *suspiciousFrameworks = @[
        @"/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate",
        @"/Library/Frameworks/RevealServer.framework/RevealServer",
        @"/Library/Frameworks/IntegrityProtection.framework/IntegrityProtection",
        @"/Library/Frameworks/TweakInject.framework/TweakInject"
    ];
    
    for (NSString *framework in suspiciousFrameworks) {
        if (dlopen([framework UTF8String], RTLD_NOW) != NULL) {
            return YES;
        }
    }
    return NO;
}

- (void)handleSecurityViolation:(NSString *)reason {
    // Log, alert server, or terminate gracefully
    NSLog(@"Security violation: %@", reason);
    
    // Exit in a way that looks like a crash
    kill(getpid(), SIGKILL);
}

+ (void)denyDebugger {
    #if HAS_PTRACE
        ptrace(PT_DENY_ATTACH, 0, 0, 0);
    #endif
    #if defined(SYS_ptrace) && HAS_PTRACE
        syscall(SYS_ptrace, PT_DENY_ATTACH, 0, 0, 0);
    #endif
}

@end
