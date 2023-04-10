#import <Flutter/Flutter.h>
#import <UIKit/UIKit.h>
#import "AppDelegate.h"
#import <hello/HelloPlugin.h>

int main(int argc, char* argv[]) {
  @autoreleasepool {
      [HelloPlugin print];
    return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
  }
}
