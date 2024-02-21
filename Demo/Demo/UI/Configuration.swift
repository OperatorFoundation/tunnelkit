//
//  Configuration.swift
//  Demo
//
//  Created by Davide De Rosa on 6/13/20.
//  Copyright (c) 2024 Davide De Rosa. All rights reserved.
//
//  https://github.com/keeshux
//
//  This file is part of TunnelKit.
//
//  TunnelKit is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  TunnelKit is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with TunnelKit.  If not, see <http://www.gnu.org/licenses/>.
//

import Foundation
import TunnelKitCore
import TunnelKitOpenVPN
import TunnelKitWireGuard

#if os(macOS)
let appGroup = "67Y4NSLDQ3.group.org.operatorfoundation.TunnelKit.Demo"
private let bundleComponent = "macos"
#elseif os(iOS)
let appGroup = "group.org.operatorfoundation.TunnelKit.Demo"
private let bundleComponent = "ios"
#else
let appGroup = "group.org.operatorfoundation.TunnelKit.Demo"
private let bundleComponent = "tvos"
#endif

enum TunnelIdentifier {
    static let openVPN = "org.operatorfoundation.\(bundleComponent).TunnelKit.Demo.OpenVPN-Tunnel"

    static let wireGuard = "org.operatorfoundation.\(bundleComponent).TunnelKit.Demo.WireGuard-Tunnel"
}

extension OpenVPN {
    struct DemoConfiguration {
        static let ca = OpenVPN.CryptoContainer(pem: """
-----BEGIN CERTIFICATE-----
MIIB+zCCAYKgAwIBAgIUbUY2OgOE0mRUmQJHBArHOb+gs00wCgYIKoZIzj0EAwQw
FjEUMBIGA1UEAwwLRWFzeS1SU0EgQ0EwHhcNMjMxMTMwMDAxNjM2WhcNMzMxMTI3
MDAxNjM2WjAWMRQwEgYDVQQDDAtFYXN5LVJTQSBDQTB2MBAGByqGSM49AgEGBSuB
BAAiA2IABORLqJENSIREI4AWlymdGd47qultm9p7OWbrLqjLQqLfyn9DUoTQwwrO
DR6tsVPZg/wgk/lsiR2mklULcXRdRfGU9SYcuSdnv/MeZi+md7wBbCo3WviqIzdd
kcAWdfbu6KOBkDCBjTAdBgNVHQ4EFgQUhxWhtR4M7ph/YohOBz79PSeTt5UwUQYD
VR0jBEowSIAUhxWhtR4M7ph/YohOBz79PSeTt5WhGqQYMBYxFDASBgNVBAMMC0Vh
c3ktUlNBIENBghRtRjY6A4TSZFSZAkcECsc5v6CzTTAMBgNVHRMEBTADAQH/MAsG
A1UdDwQEAwIBBjAKBggqhkjOPQQDBANnADBkAjBnXN3yN5Fx/fT0zKIigmwgYDAZ
YDORij7Ez4H//xgRMPk7sbqbcDGjcgvlT6bzeKgCMEMLabceFTqd9PwRkIHWYKYX
Nwm0ENHsezJpISREWcXWjp57LN5jCSpuh1Kl81P5MQ==
-----END CERTIFICATE-----
""")

        static let tlsKey = OpenVPN.StaticKey(file: """
# 2048 bit OpenVPN static key
-----BEGIN OpenVPN Static key V1-----
557bc54a91fc624026b02be474c4949d
7e4475d89519f148c258e0ca0830433f
75d068c9cd47f84a268c1abfd0c3ffa4
84e8c1d77c5aa0a186d0c9900be54a60
35e86ec6a14b54c929f3c621ef0263f9
8bd15ca6f32e958013fed26e53f33cf3
09249a1a55f1b54d2e00ad2a95cde7c1
239799d7cb655cb2ae41d95f8a461ce3
8b37bfc7128adf563a7e4d904dc83326
916304f7bcd35d733d924fad3d8587cc
4ac82df3273d8ae0c08460333bb57864
d8ff15b8e8dac7c0e150df3fee1be227
f59282e4c227c3b04a94726e169faf64
2a5b9d63983f6dc61a82a6acb0f6df29
9fb206571ea40dd55a2995383812dcc2
e1abb6e5807d0a8b59e0f23a978013be
-----END OpenVPN Static key V1-----
""", direction: .client)!

        struct Parameters {
            let title: String

            let appGroup: String

            let hostname: String

            let port: UInt16

            let socketType: SocketType
        }

        static func make(params: Parameters) -> OpenVPN.ProviderConfiguration {
            var builder = OpenVPN.ConfigurationBuilder()
            builder.ca = ca
            builder.cipher = .aes256gcm
            builder.digest = .sha256
            builder.compressionFraming = .compLZO
            builder.renegotiatesAfter = nil
            builder.remotes = [Endpoint(params.hostname, EndpointProtocol(params.socketType, params.port))]
            builder.tlsWrap = TLSWrap(strategy: .auth, key: tlsKey)
            builder.mtu = 1350
            builder.routingPolicies = [.IPv4, .IPv6]
            let cfg = builder.build()

            var providerConfiguration = OpenVPN.ProviderConfiguration(params.title, appGroup: params.appGroup, configuration: cfg)
            providerConfiguration.shouldDebug = true
            providerConfiguration.masksPrivateData = false
            return providerConfiguration
        }
    }
}

extension WireGuard {
    struct Parameters {
        let title: String

        let appGroup: String

        let clientPrivateKey: String

        let clientAddress: String

        let serverPublicKey: String

        let serverAddress: String

        let serverPort: String
    }

    struct DemoConfiguration {
        static func make(params: Parameters) -> WireGuard.ProviderConfiguration? {
            var builder: WireGuard.ConfigurationBuilder
            do {
                builder = try WireGuard.ConfigurationBuilder(params.clientPrivateKey)
            } catch {
                print(">>> \(error)")
                return nil
            }
            builder.addresses = [params.clientAddress]
            builder.dnsServers = ["1.1.1.1", "1.0.0.1"]
            do {
                try builder.addPeer(params.serverPublicKey, endpoint: "\(params.serverAddress):\(params.serverPort)")
            } catch {
                print(">>> \(error)")
                return nil
            }
            builder.addDefaultGatewayIPv4(toPeer: 0)
            let cfg = builder.build()

            return WireGuard.ProviderConfiguration(params.title, appGroup: params.appGroup, configuration: cfg)
        }
    }
}
