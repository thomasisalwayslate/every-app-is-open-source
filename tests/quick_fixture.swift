import Foundation

@objc(EAOSSwiftFixture)
class EAOSSwiftFixture: NSObject {
    @objc func value(_ input: Int32) -> Int32 { input + 29 }
}
let fixture = EAOSSwiftFixture()
print(fixture.value(2))
