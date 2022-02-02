#import <Foundation/Foundation.h>
#import <NetworkExtension/NEVPNManager.h>
#import <NetworkExtension/NEVPNConnection.h>
#import <NetworkExtension/NEVPNProtocolIPSec.h>
#import <NetworkExtension/NEOnDemandRule.h>
#import <Security/Security.h>

#import "VPNManager.h"
#import "Reachability.h"
#import "UICKeyChainStore.h"
#import <Cordova/CDV.h>


@interface VPNManager () {
    NEVPNManager *vpnManager;
    UICKeyChainStore *store;
}

@end

@implementation VPNManager

static NSString * serviceName;

static BOOL allowWiFi;

- (void)pluginInitialize {
    NSLog(@"AppLog Lib Plugin Initialization");
    serviceName = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleIdentifier"];
    allowWiFi = [[[NSBundle mainBundle] objectForInfoDictionaryKey:@"AllowWiFi"] boolValue];
    vpnManager = [NEVPNManager sharedManager];
    store = [UICKeyChainStore keyChainStoreWithService:serviceName];

//    [vpnManager loadFromPreferencesWithCompletionHandler:^(NSError *error) {
//        if(error)
//            NSLog(@"AppLog Lib Load error: %@", error);
//        else if(vpnManager.protocol) {
//            NEVPNProtocolIPSec *proto = (NEVPNProtocolIPSec *)vpnManager.protocol;
//            proto.passwordReference = [self searchKeychainCopyMatching:@"VPNPassword"];
//            proto.identityDataPassword = [store stringForKey:@"VPNCertPassword"];
//            [vpnManager setProtocol:proto];
//            [vpnManager setEnabled:YES];
//            [vpnManager saveToPreferencesWithCompletionHandler:^(NSError *error) {
//                if(error)
//                    NSLog(@"AppLog Lib Save config failed [%@]", error.localizedDescription);
//                else
//                    [self dumpConfig];
//            }];
//        }
//    }];
}

- (void)registerCallback:(CDVInvokedUrlCommand*)command {
    NSString* localCallbackId = command.callbackId;
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [[NSNotificationCenter defaultCenter] addObserverForName:NEVPNStatusDidChangeNotification object:nil queue:[NSOperationQueue mainQueue] usingBlock:^(NSNotification *notif) {
        CDVPluginResult* pluginResult = [self vpnStatusToResult:vpnManager.connection.status];
        [pluginResult setKeepCallback:[NSNumber numberWithBool:YES]];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:localCallbackId];
        NSLog(@"AppLog Lib Successfully received VPN status change notification: %d", vpnManager.connection.status);
    }];
}

- (void)unregisterCallback:(CDVInvokedUrlCommand*)command {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

- (void)loadVPNProfile:(CDVInvokedUrlCommand*)command {
    NSMutableDictionary* options = [command.arguments objectAtIndex:0];
    NSString* localCallbackId = command.callbackId;

    [self.commandDelegate runInBackground:^{
        NSLog(@"AppLog Lib Provisioning the VPN");

//        NSString* vpnUsername = [options objectForKey:@"vpnUsername"];
        NSString* vpnPassword = [options objectForKey:@"vpnPassword"];
        NSString* vpnHost = [options objectForKey:@"vpnHost"];
        NSString* appName = [options objectForKey:@"appName"];
//        NSString* vpnCert = [options objectForKey:@"userCertificate"];
//        NSString* vpnCertPassword = [options objectForKey:@"userCertificatePassword"];
//        NSString* appName = [options objectForKey:@"appName"];
//
//        NSData* certData = [[NSData alloc]initWithBase64EncodedString:vpnCert options:NSDataBase64DecodingIgnoreUnknownCharacters];
        [self->store setString:vpnPassword forKey:@"VPNPassword"];
//        [store setString:vpnCertPassword forKey:@"VPNCertPassword"];
//        [store setData:certData forKey:@"VPNCert"];
        [self->store synchronize];
        [self->vpnManager loadFromPreferencesWithCompletionHandler:^(NSError *error) {
            __block CDVPluginResult* pluginResult = nil;

            if(error) {
                NSLog(@"AppLog Lib Load error: %@", error);
                [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR] callbackId:localCallbackId];
            } else {
                NEVPNProtocolIKEv2 *proto = [[NEVPNProtocolIKEv2 alloc] init];
                proto.serverAddress = vpnHost;
                proto.authenticationMethod = NEVPNIKEAuthenticationMethodSharedSecret;
                
                // PROFILE_PASSWORD = "GcY6jC92zwv01Q4xqEM3Cmd1jC0jGXAy"; // 142
                
//                let kcs = KeychainService();
//                kcs.save(key: "SHARED", value: "password")
                //        kcs.save(key: "VPN_PASSWORD", value: "password1")
                //        kcs.save(key: "VPN_PASSWORD", value: "sadman@123")
                proto.sharedSecretReference = [self searchKeychainCopyMatching:@"VPNPassword"];
                //        proto.sharedSecretReference = kcs.load(key: "VPN_PASSWORD")
                //        proto.passwordReference = kcs.load(key: "VPN_PASSWORD")
                proto.useExtendedAuthentication = false;
                proto.disconnectOnSleep = false;
                proto.remoteIdentifier = vpnHost; /// Required
                
                proto.IKESecurityAssociationParameters.diffieHellmanGroup = NEVPNIKEv2DiffieHellmanGroup2;
                proto.IKESecurityAssociationParameters.encryptionAlgorithm = NEVPNIKEv2EncryptionAlgorithmAES128;
                proto.IKESecurityAssociationParameters.integrityAlgorithm = NEVPNIKEv2IntegrityAlgorithmSHA96;
                proto.IKESecurityAssociationParameters.lifetimeMinutes = 1140;
                
                proto.childSecurityAssociationParameters.diffieHellmanGroup = NEVPNIKEv2DiffieHellmanGroup2;
                proto.childSecurityAssociationParameters.encryptionAlgorithm = NEVPNIKEv2EncryptionAlgorithmAES128;
                proto.childSecurityAssociationParameters.integrityAlgorithm = NEVPNIKEv2IntegrityAlgorithmSHA96;
                proto.childSecurityAssociationParameters.lifetimeMinutes = 1140;
                
                [self->vpnManager setLocalizedDescription:appName];
                [self->vpnManager setProtocolConfiguration:proto];
                [self->vpnManager setEnabled:YES];
                if(!allowWiFi) {
                    [self->vpnManager setOnDemandEnabled:YES];
                    NSMutableArray *rules = [[NSMutableArray alloc] init];
                    NEOnDemandRuleDisconnect *disconnectRule = [NEOnDemandRuleDisconnect new];
                    disconnectRule.interfaceTypeMatch = NEOnDemandRuleInterfaceTypeWiFi;
                    [rules addObject:disconnectRule];
                    [[NEVPNManager sharedManager] setOnDemandRules:rules];
                }
                [self->vpnManager saveToPreferencesWithCompletionHandler:^(NSError *error) {
                    if(error) {
                        NSLog(@"AppLog Lib Save config failed [%@]", error.localizedDescription);
                        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsBool:NO];
                    } else {
//                        [self dumpConfig];
                        NSLog(@"AppLog Lib starting vpn");
                        NSError *startError;
                        [self->vpnManager.connection startVPNTunnelAndReturnError:&startError];
                        if (startError) {
                            NSLog(@"AppLog Lib Start error: %@", startError.localizedDescription);
                            [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR] callbackId:localCallbackId];
                        }else{
                            [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:@"CONNECTING"] callbackId:localCallbackId];
//                            [self registerCallback:command];
                        }
                        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsBool:YES];
                    }
                    [self.commandDelegate sendPluginResult:pluginResult callbackId:localCallbackId];
                }];
            }
        }];
    }];
}

- (void)enable:(CDVInvokedUrlCommand*)command {
    NSString* localCallbackId = command.callbackId;

    NEVPNStatus status = vpnManager.connection.status;
    NSLog(@"AppLog Lib Current VPN Status %ld",(long)status);

        switch (status) {
            case NEVPNStatusInvalid:
                NSLog(@"AppLog Lib NEVPNConnection: Invalid");
                break;
            case NEVPNStatusDisconnected:
                NSLog(@"AppLog Lib NEVPNConnection: Disconnected");
                break;
            case NEVPNStatusConnecting:
                NSLog(@"AppLog Lib NEVPNConnection: Connecting");
                break;
            case NEVPNStatusConnected:
                NSLog(@"AppLog Lib NEVPNConnection: Connected");
                break;
            case NEVPNStatusReasserting:
                NSLog(@"AppLog Lib NEVPNConnection: Reasserting");
                break;
            case NEVPNStatusDisconnecting:
                NSLog(@"AppLog Lib NEVPNConnection: Disconnecting");
                break;
            default:
                NSLog(@"Error");
        }

    [self.commandDelegate runInBackground:^{
        Reachability *reachability = [Reachability reachabilityForInternetConnection];
        NetworkStatus status = [reachability currentReachabilityStatus];
        
        if (self->vpnManager.connection.status != NEVPNStatusConnected) {
            NSLog(@"AppLog Lib Enabling the VPN.");
            NSError *startError;
//            [self->vpnManager loadFromPreferencesWithCompletionHandler:loadVPNProfile:command];
            [self loadVPNProfile:command];
//            [self->vpnManager.connection startVPNTunnelAndReturnError:&startError];
//            if (startError) {
//                NSLog(@"AppLog Lib Start error: %@", startError.localizedDescription);
//                [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR] callbackId:localCallbackId];
//            }else{
//                [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:@"CONNECTING"] callbackId:localCallbackId];
//            }
        }
        
//        if(!allowWiFi && status == ReachableViaWiFi) {
//            NSLog(@"AppLog Lib Failed to enable the Kickbit VPN because WiFi is enabled.");
//            [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR] callbackId:localCallbackId];
//        } else if(vpnManager.connection.status != NEVPNStatusDisconnected) {
//            NSLog(@"AppLog Lib Failed to enable the Kickbit VPN because the vpn is already enabled.");
//            [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR] callbackId:localCallbackId];
//        } else {
//            NSLog(@"AppLog Lib Enabling the Kickbit VPN.");
//            NSError *startError;
//            [vpnManager.connection startVPNTunnelAndReturnError:&startError];
//            if(startError) {
//                NSLog(@"AppLog Lib Start error: %@", startError.localizedDescription);
//                [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR] callbackId:localCallbackId];
//            } else
//                [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:@"CONNECTING"] callbackId:localCallbackId];
//        }
    }];
}

- (void)disable:(CDVInvokedUrlCommand*)command {
    NSString* localCallbackId = command.callbackId;

    [self.commandDelegate runInBackground:^{
        CDVPluginResult* pluginResult = nil;
        
        if(vpnManager.connection.status != NEVPNStatusConnected)
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR];
        else {
            NSLog(@"AppLog Lib Disabling the VPN.");
            [self->vpnManager.connection stopVPNTunnel];
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:@"DISABLED"];
//            [self unregisterCallback:command];
        }
        [self.commandDelegate sendPluginResult:pluginResult callbackId:localCallbackId];
        
    }];
}

- (CDVPluginResult *) vpnStatusToResult:(NEVPNStatus)status {
    CDVPluginResult *result = nil;

    switch(status) {
        case NEVPNStatusInvalid:
            result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR];
            break;
        case NEVPNStatusDisconnected:
            result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:@"DISCONNECTED"];
            break;
        case NEVPNStatusConnecting:
            result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:@"CONNECTING"];
            break;
        case NEVPNStatusConnected:
            result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:@"CONNECTED"];
            break;
        case NEVPNStatusReasserting:
            result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:@"CONNECTING"];
            break;
        case NEVPNStatusDisconnecting:
            result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:@"DISCONNECTING"];
            break;
        default:
            result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR];
    }

    return result;
}



- (void)provision:(CDVInvokedUrlCommand*)command {
    NSMutableDictionary* options = [command.arguments objectAtIndex:0];
    NSString* localCallbackId = command.callbackId;

    [self.commandDelegate runInBackground:^{
        NSLog(@"AppLog Lib Provisioning the Kickbit VPN");

        NSString* vpnUsername = [options objectForKey:@"vpnUsername"];
        NSString* vpnPassword = [options objectForKey:@"vpnPassword"];
        NSString* vpnHost = [options objectForKey:@"vpnHost"];
        NSString* vpnCert = [options objectForKey:@"userCertificate"];
        NSString* vpnCertPassword = [options objectForKey:@"userCertificatePassword"];
        NSString* appName = [options objectForKey:@"appName"];

        NSData* certData = [[NSData alloc]initWithBase64EncodedString:vpnCert options:NSDataBase64DecodingIgnoreUnknownCharacters];
        [store setString:vpnPassword forKey:@"VPNPassword"];
        [store setString:vpnCertPassword forKey:@"VPNCertPassword"];
        [store setData:certData forKey:@"VPNCert"];
        [store synchronize];
        [vpnManager loadFromPreferencesWithCompletionHandler:^(NSError *error) {
            __block CDVPluginResult* pluginResult = nil;

            if(error) {
                NSLog(@"AppLog Lib Load error: %@", error);
                [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR] callbackId:localCallbackId];
            } else {
                NEVPNProtocolIPSec *proto = [[NEVPNProtocolIPSec alloc] init];
                proto.username = vpnUsername;
                proto.passwordReference = [self searchKeychainCopyMatching:@"VPNPassword"];
                proto.serverAddress = vpnHost;
                proto.authenticationMethod = NEVPNIKEAuthenticationMethodCertificate;
                proto.identityData = certData;
                proto.identityDataPassword = vpnCertPassword;
                proto.localIdentifier = [NSString stringWithFormat:@"%@@%@", vpnUsername, vpnHost];
                proto.remoteIdentifier = vpnHost;
                proto.useExtendedAuthentication = YES;
                proto.disconnectOnSleep = NO;
                [vpnManager setLocalizedDescription:appName];
                [vpnManager setProtocol:proto];
                [vpnManager setEnabled:YES];
                if(!allowWiFi) {
                    [vpnManager setOnDemandEnabled:YES];
                    NSMutableArray *rules = [[NSMutableArray alloc] init];
                    NEOnDemandRuleDisconnect *disconnectRule = [NEOnDemandRuleDisconnect new];
                    disconnectRule.interfaceTypeMatch = NEOnDemandRuleInterfaceTypeWiFi;
                    [rules addObject:disconnectRule];
                    [[NEVPNManager sharedManager] setOnDemandRules:rules];
                }
                [vpnManager saveToPreferencesWithCompletionHandler:^(NSError *error) {
                    if(error) {
                        NSLog(@"AppLog Lib Save config failed [%@]", error.localizedDescription);
                        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsBool:NO];
                    } else {
                        [self dumpConfig];
                        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsBool:YES];
                    }
                    [self.commandDelegate sendPluginResult:pluginResult callbackId:localCallbackId];
                }];
            }
        }];
    }];
}

- (void)status:(CDVInvokedUrlCommand*)command {
    NSString* localCallbackId = command.callbackId;

    [self.commandDelegate runInBackground:^{
        CDVPluginResult* pluginResult = [self vpnStatusToResult:vpnManager.connection.status];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:localCallbackId];
    }];
}

- (void)needsProfile:(CDVInvokedUrlCommand*)command {
    NSMutableDictionary* options = [command.arguments objectAtIndex:0];
    NSString* localCallbackId = command.callbackId;

    [self.commandDelegate runInBackground:^{
        NSString* vpnUsername = [options objectForKey:@"vpnUsername"];
        NSString* vpnPassword = [options objectForKey:@"vpnPassword"];
        NSString* vpnHost = [options objectForKey:@"vpnHost"];
        NSString* vpnCert = [options objectForKey:@"userCertificate"];
        NSString* vpnCertPassword = [options objectForKey:@"userCertificatePassword"];
        if (vpnUsername != nil && vpnHost != nil && vpnCert != nil && vpnCertPassword != nil && vpnPassword != nil) {
            [vpnManager loadFromPreferencesWithCompletionHandler:^(NSError *error) {
                if(error)
                    [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR] callbackId:localCallbackId];
                else {
                    NEVPNProtocolIPSec *proto = (NEVPNProtocolIPSec *)vpnManager.protocol;
                    NSString* passwdCmp = [store stringForKey:@"VPNPassword"];
                    NSString* certPasswdCmp = [store stringForKey:@"VPNCertPassword"];
                    NSData* certDataCmp = [store dataForKey:@"VPNCert"];
                    NSData* certData = [[NSData alloc]initWithBase64EncodedString:vpnCert options:NSDataBase64DecodingIgnoreUnknownCharacters];
                    NSLog(@"AppLog Lib Username: %@", [proto.username isEqualToString:vpnUsername] ? @"YES" : @"NO");
                    NSLog(@"AppLog Lib Server Address: %@", [proto.serverAddress isEqualToString:vpnHost] ? @"YES" : @"NO");
                    NSLog(@"AppLog Lib Certificate: %@", [certDataCmp isEqualToData:certData] ? @"YES" : @"NO");
                    NSLog(@"AppLog Lib Certificate Password: %@", [certPasswdCmp isEqualToString:vpnCertPassword] ? @"YES" : @"NO");
                    NSLog(@"AppLog Lib Password: %@", [passwdCmp isEqualToString:vpnPassword] ? @"YES" : @"NO");
                    if (proto && [proto.username isEqualToString:vpnUsername] && [proto.serverAddress isEqualToString:vpnHost] &&
                        [certDataCmp isEqualToData:certData] && [certPasswdCmp isEqualToString:vpnCertPassword] && [passwdCmp isEqualToString:vpnPassword]) {
                        proto.passwordReference = [self searchKeychainCopyMatching:@"VPNPassword"];
                        proto.identityDataPassword = [store stringForKey:@"VPNCertPassword"];
                        [vpnManager setProtocol:proto];
                        [vpnManager setEnabled:YES];
                        [vpnManager saveToPreferencesWithCompletionHandler:^(NSError *error) {
                            CDVPluginResult* pluginResult = nil;
                            if(error) {
                                NSLog(@"AppLog Lib Save config failed [%@]", error.localizedDescription);
                                pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR];
                            } else
                                pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsBool:NO];
                            [self.commandDelegate sendPluginResult:pluginResult callbackId:localCallbackId];
                        }];
                    } else {
                        [store removeItemForKey:@"VPNPassword"];
                        [store removeItemForKey:@"VPNCertPassword"];
                        [store removeItemForKey:@"VPNCert"];
                        [store synchronize];
                        [vpnManager removeFromPreferencesWithCompletionHandler:^(NSError *error) {
                            if(error)
                                NSLog(@"AppLog Lib Remove config failed [%@]", error.localizedDescription);
                            [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsBool:YES] callbackId:localCallbackId];
                        }];
                    }
                }
            }];
        } else
            [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR] callbackId:localCallbackId];
    }];
}

- (void)dumpConfig {
    NSLog(@"AppLog Lib dumpConfig description: %@", vpnManager.localizedDescription);
    NEVPNProtocolIKEv2 *proto = (NEVPNProtocolIKEv2 *)vpnManager.protocolConfiguration;
//    NSLog(@"AppLog Lib dumpConfig username: %@", proto.username);
    NSLog(@"AppLog Lib dumpConfig passwordReference: %@", proto.passwordReference);
    NSLog(@"AppLog Lib dumpConfig serverAddress: %@", proto.serverAddress);
//    NSLog(@"AppLog Lib dumpConfig authenticationMethod: %d", proto.authenticationMethod);
//    NSLog(@"AppLog Lib dumpConfig identityData: %@", proto.identityData);
//    NSLog(@"AppLog Lib dumpConfig identityDataPassword: %@", proto.identityDataPassword);
//    NSLog(@"AppLog Lib dumpConfig localIdentifier: %@", proto.localIdentifier);
    NSLog(@"AppLog Lib dumpConfig remoteIdentifier: %@", proto.remoteIdentifier);
//    NSLog(@"AppLog Lib dumpConfig useExtendedAuthentication: %d", proto.useExtendedAuthentication);
    NSLog(@"AppLog Lib dumpConfig disconnectOnSleep: %d", proto.disconnectOnSleep);
}

- (NSData *)searchKeychainCopyMatching:(NSString *)identifier {
    NSMutableDictionary *searchDictionary = [[NSMutableDictionary alloc] init];
    
    NSData *encodedIdentifier = [identifier dataUsingEncoding:NSUTF8StringEncoding];
    
    searchDictionary[(__bridge id)kSecClass] = (__bridge id)kSecClassGenericPassword;
    searchDictionary[(__bridge id)kSecAttrGeneric] = encodedIdentifier;
    searchDictionary[(__bridge id)kSecAttrAccount] = encodedIdentifier;
    searchDictionary[(__bridge id)kSecAttrService] = serviceName;
    
    searchDictionary[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
    searchDictionary[(__bridge id)kSecReturnPersistentRef] = @YES;
    
    CFTypeRef result = NULL;
    SecItemCopyMatching((__bridge CFDictionaryRef)searchDictionary, &result);
    
    return (__bridge_transfer NSData *)result;
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

@end
