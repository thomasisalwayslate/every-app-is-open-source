#import <Foundation/Foundation.h>

@interface FixtureAlpha : NSObject
- (int)value:(int)input;
@end
@implementation FixtureAlpha
- (int)value:(int)input { return input + 17; }
@end

@interface FixtureBeta : NSObject
- (int)value:(int)input;
@end
@implementation FixtureBeta
- (int)value:(int)input { return input * 3; }
@end

__attribute__((noinline)) int fixture_first(int x) { return x + 23; }
__attribute__((noinline)) int fixture_second(int x) { return x * 5; }
const char *fixture_literal = "EAOS quick fixture unique literal";
int main(void) { return fixture_first(2) + fixture_second(4); }
