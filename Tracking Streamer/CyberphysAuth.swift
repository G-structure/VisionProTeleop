//
//  CyberphysAuth.swift
//  Tracking Streamer (visionOS)
//
//  OpenAuth (GitHub) sign-in for Cybernetic Physics.
//

import AuthenticationServices
import Combine
import Foundation
import OSLog
import Security
import SwiftUI
import UIKit

private enum CyberphysAuthConfig {
    static let issuerBaseURL = URL(string: "https://auth.cyberneticphysics.com")!
    static let apiBaseURL = URL(string: "https://api.cyberneticphysics.com")!
    static let clientID = "cybernetic-physics"
    // NOTE: Use an "auth.cyberneticphysics.com" hostname so OpenAuth's default
    // redirect allow-check (domain match) passes even if the worker isn't deployed
    // with a custom allowlist yet.
    static let redirectURI = "cyberphys://auth.cyberneticphysics.com/callback"
    static let callbackURLScheme = "cyberphys"
}

private let cyberphysAuthLogger = Logger(
    subsystem: Bundle.main.bundleIdentifier ?? "VisionProTeleop",
    category: "CyberphysAuth"
)

@MainActor
final class CyberphysAuthManager: NSObject, ObservableObject {
    static let shared = CyberphysAuthManager()

    @Published var isAuthenticating: Bool = false
    @Published var isAuthenticated: Bool = false
    @Published var isRestoringSession: Bool = false
    @Published var authError: String?
    @Published private(set) var userLogin: String?
    @Published private(set) var userId: String?
    @Published private(set) var workspaces: [CyberphysWorkspace] = []
    @Published private(set) var activeWorkspaceId: String?

    private(set) var accessToken: String?
    private(set) var refreshToken: String?

    private var authSession: ASWebAuthenticationSession?
    private let tokenStore = CyberphysTokenStore()

    private override init() {
        super.init()
        bootstrapAuthState()
    }

    private func bootstrapAuthState() {
        accessToken = tokenStore.loadString(forKey: .accessToken)
        refreshToken = tokenStore.loadString(forKey: .refreshToken)

        if let accessToken {
            userLogin = extractUserLogin(fromAccessToken: accessToken)
            isAuthenticated = !isAccessTokenExpired(accessToken)
        } else {
            userLogin = nil
            userId = nil
            isAuthenticated = false
        }

        let shouldAttemptRestore = !isAuthenticated && refreshToken != nil
        if shouldAttemptRestore {
            isRestoringSession = true
            Task { await self.restoreSessionIfNeeded() }
        } else {
            isRestoringSession = false
        }
    }

    func reloadFromStore() {
        bootstrapAuthState()
    }

    func startOAuthFlow() async {
        isAuthenticating = true
        authError = nil

        var components = URLComponents(
            url: CyberphysAuthConfig.issuerBaseURL.appendingPathComponent("authorize"),
            resolvingAgainstBaseURL: false
        )!
        components.queryItems = [
            URLQueryItem(name: "provider", value: "github"),
            URLQueryItem(name: "client_id", value: CyberphysAuthConfig.clientID),
            URLQueryItem(name: "redirect_uri", value: CyberphysAuthConfig.redirectURI),
            URLQueryItem(name: "response_type", value: "code"),
        ]

        guard let authURL = components.url else {
            authError = "Failed to build authorization URL"
            isAuthenticating = false
            return
        }

        dlog("🔐 [CyberphysAuth] Starting GitHub sign-in…")

        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            authSession = ASWebAuthenticationSession(
                url: authURL,
                callbackURLScheme: CyberphysAuthConfig.callbackURLScheme
            ) { [weak self] callbackURL, error in
                Task { @MainActor in
                    defer { continuation.resume() }
                    guard let self else { return }

                    self.isAuthenticating = false

                    if let error {
                        if case ASWebAuthenticationSessionError.canceledLogin = error {
                            self.authError = "Sign in was cancelled"
                        } else {
                            self.authError = "Authentication failed: \(error.localizedDescription)"
                        }
                        dlog("❌ [CyberphysAuth] Auth error: \(error)")
                        return
                    }

                    guard let callbackURL else {
                        self.authError = "Missing callback URL"
                        return
                    }

                    guard let code = Self.extractQueryParam(name: "code", from: callbackURL) else {
                        let errorParam = Self.extractQueryParam(name: "error", from: callbackURL)
                        let errorDescription = Self.extractQueryParam(
                            name: "error_description",
                            from: callbackURL
                        )
                        let decodedErrorParam = errorParam?.replacingOccurrences(of: "+", with: " ")
                        let decodedErrorDescription = errorDescription?.replacingOccurrences(of: "+", with: " ")
                        self.authError = decodedErrorDescription
                            ?? decodedErrorParam
                            ?? "Failed to get authorization code"
                        return
                    }

                    await self.exchangeCodeForTokens(code: code)
                }
            }

            authSession?.presentationContextProvider = self
            authSession?.prefersEphemeralWebBrowserSession = false
            authSession?.start()
        }
    }

    func signOut() {
        tokenStore.delete(key: .accessToken)
        tokenStore.delete(key: .refreshToken)
        accessToken = nil
        refreshToken = nil
        userLogin = nil
        userId = nil
        workspaces = []
        activeWorkspaceId = nil
        isAuthenticated = false
        isRestoringSession = false
        authError = nil
    }

    func fetchMe() async -> Bool {
        guard let token = accessToken, !token.isEmpty else {
            return false
        }
        return await requestMe(accessToken: token, allowRefreshRetry: true)
    }

    func restoreSessionIfNeeded() async {
        defer { isRestoringSession = false }

        guard let storedRefreshToken = tokenStore.loadString(forKey: .refreshToken),
              !storedRefreshToken.isEmpty else {
            return
        }

        // If we already have a valid token, nothing to do.
        if let storedAccessToken = tokenStore.loadString(forKey: .accessToken),
           !isAccessTokenExpired(storedAccessToken) {
            accessToken = storedAccessToken
            refreshToken = storedRefreshToken
            userLogin = extractUserLogin(fromAccessToken: storedAccessToken)
            isAuthenticated = true
            return
        }

        _ = await refreshAccessToken()
    }

    func refreshAccessToken() async -> Bool {
        struct RefreshRequest: Encodable {
            let refreshToken: String
        }
        struct RefreshResponse: Decodable {
            let accessToken: String
            let refreshToken: String
        }

        guard let currentRefreshToken = refreshToken, !currentRefreshToken.isEmpty else {
            return false
        }

        let url = CyberphysAuthConfig.apiBaseURL.appendingPathComponent("v1/auth/refresh")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONEncoder().encode(RefreshRequest(refreshToken: currentRefreshToken))

        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse else {
                authError = "Token refresh failed"
                return false
            }

            if httpResponse.statusCode == 401 {
                signOut()
                authError = "Session expired. Please sign in again."
                return false
            }

            guard httpResponse.statusCode == 200 else {
                let body = String(data: data, encoding: .utf8) ?? ""
                dlog("❌ [CyberphysAuth] Refresh failed: HTTP \(httpResponse.statusCode) \(body)")
                authError = "Token refresh failed (HTTP \(httpResponse.statusCode))"
                return false
            }

            let refreshResponse = try JSONDecoder().decode(RefreshResponse.self, from: data)
            applyTokens(accessToken: refreshResponse.accessToken, refreshToken: refreshResponse.refreshToken)
            _ = persistTokens(accessToken: refreshResponse.accessToken, refreshToken: refreshResponse.refreshToken)
            return true
        } catch {
            authError = "Token refresh failed: \(error.localizedDescription)"
            dlog("❌ [CyberphysAuth] Refresh error: \(error)")
            return false
        }
    }

    private func exchangeCodeForTokens(code: String) async {
        let url = CyberphysAuthConfig.issuerBaseURL.appendingPathComponent("token")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

        let params: [String: String] = [
            "grant_type": "authorization_code",
            "code": code,
            "client_id": CyberphysAuthConfig.clientID,
            "redirect_uri": CyberphysAuthConfig.redirectURI,
        ]
        request.httpBody = Self.formURLEncoded(params).data(using: .utf8)

        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse else {
                authError = "Token exchange failed"
                return
            }

            guard httpResponse.statusCode == 200 else {
                let body = String(data: data, encoding: .utf8) ?? ""
                dlog("❌ [CyberphysAuth] Token exchange failed: HTTP \(httpResponse.statusCode) \(body)")
                authError = "Token exchange failed (HTTP \(httpResponse.statusCode))"
                return
            }

            let tokenResponse = try JSONDecoder().decode(CyberphysTokenResponse.self, from: data)

            applyTokens(accessToken: tokenResponse.accessToken, refreshToken: tokenResponse.refreshToken)
            let didPersist = persistTokens(
                accessToken: tokenResponse.accessToken,
                refreshToken: tokenResponse.refreshToken
            )
            if !didPersist {
                authError = "Signed in, but couldn’t save your session on this build."
            }

            _ = await fetchMe()
            dlog("✅ [CyberphysAuth] Signed in as \(userLogin ?? "unknown")")
        } catch {
            authError = "Token exchange failed: \(error.localizedDescription)"
            dlog("❌ [CyberphysAuth] Token exchange error: \(error)")
        }
    }

    private func requestMe(accessToken: String, allowRefreshRetry: Bool) async -> Bool {
        var request = URLRequest(url: CyberphysAuthConfig.apiBaseURL.appendingPathComponent("v1/me"))
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")

        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse else {
                authError = "Failed to validate session"
                return false
            }

            if httpResponse.statusCode == 401, allowRefreshRetry {
                if await refreshAccessToken(), let newToken = self.accessToken {
                    return await requestMe(accessToken: newToken, allowRefreshRetry: false)
                }
                return false
            }

            guard httpResponse.statusCode == 200 else {
                let body = String(data: data, encoding: .utf8) ?? ""
                authError = "Failed to validate session (HTTP \(httpResponse.statusCode))"
                dlog("❌ [CyberphysAuth] /v1/me failed: HTTP \(httpResponse.statusCode) \(body)")
                return false
            }

            let me = try JSONDecoder().decode(CyberphysMeResponse.self, from: data)
            userId = me.user.userId
            if !me.user.login.isEmpty {
                userLogin = me.user.login
            }
            workspaces = me.workspaces
            activeWorkspaceId = me.activeWorkspaceId
            isAuthenticated = true
            authError = nil
            return true
        } catch {
            authError = "Failed to validate session: \(error.localizedDescription)"
            return false
        }
    }

    private static func extractQueryParam(name: String, from url: URL) -> String? {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return nil
        }
        return components.queryItems?.first(where: { $0.name == name })?.value
    }

    private static func formURLEncoded(_ params: [String: String]) -> String {
        params
            .map { key, value in
                let encodedKey = key.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? key
                let encodedValue = value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? value
                return "\(encodedKey)=\(encodedValue)"
            }
            .joined(separator: "&")
    }

    private func extractUserLogin(fromAccessToken token: String) -> String? {
        guard let payload = Self.decodeJwtPayload(token) else {
            return nil
        }
        if let props = payload["properties"] as? [String: Any],
           let login = props["login"] as? String,
           !login.isEmpty {
            return login
        }
        if let login = payload["login"] as? String, !login.isEmpty {
            return login
        }
        return nil
    }

    private func isAccessTokenExpired(_ token: String) -> Bool {
        // Be tolerant: if exp is missing/unparseable, treat as not expired and
        // let the API validate it (we can always refresh/sign-out on 401).
        guard let exp = Self.decodeJwtExp(token) else {
            return false
        }
        return Date().addingTimeInterval(30) >= exp
    }

    private static func decodeJwtExp(_ token: String) -> Date? {
        guard let payload = decodeJwtPayload(token) else {
            return nil
        }

        let rawExp = payload["exp"]
        let expSeconds: TimeInterval?
        if let exp = rawExp as? TimeInterval {
            expSeconds = exp
        } else if let exp = rawExp as? Int {
            expSeconds = TimeInterval(exp)
        } else if let exp = rawExp as? NSNumber {
            expSeconds = exp.doubleValue
        } else if let exp = rawExp as? String, let expDouble = Double(exp) {
            expSeconds = expDouble
        } else {
            expSeconds = nil
        }

        guard let expSeconds else {
            return nil
        }

        return Date(timeIntervalSince1970: expSeconds)
    }

    private static func decodeJwtPayload(_ token: String) -> [String: Any]? {
        let parts = token.split(separator: ".")
        guard parts.count == 3 else {
            return nil
        }

        guard let data = base64UrlDecode(String(parts[1])),
              let object = try? JSONSerialization.jsonObject(with: data),
              let dict = object as? [String: Any] else {
            return nil
        }
        return dict
    }

    private static func base64UrlDecode(_ string: String) -> Data? {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        let remainder = base64.count % 4
        if remainder != 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }

        return Data(base64Encoded: base64)
    }

    private func applyTokens(accessToken: String, refreshToken: String?) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        userLogin = extractUserLogin(fromAccessToken: accessToken)
        isAuthenticated = !isAccessTokenExpired(accessToken)
        isRestoringSession = false
    }

    @discardableResult
    private func persistTokens(accessToken: String, refreshToken: String?) -> Bool {
        let savedAccess = tokenStore.save(accessToken, forKey: .accessToken)
        let savedRefresh = refreshToken == nil ? true : tokenStore.save(refreshToken ?? "", forKey: .refreshToken)
        if savedAccess, savedRefresh {
            authError = nil
        } else {
            cyberphysAuthLogger.error("Failed to persist session tokens")
        }
        return savedAccess && savedRefresh
    }
}

private struct CyberphysTokenResponse: Decodable {
    let accessToken: String
    let refreshToken: String?

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
    }
}

private struct CyberphysMeResponse: Decodable {
    let user: CyberphysUser
    let workspaces: [CyberphysWorkspace]
    let activeWorkspaceId: String
}

private struct CyberphysUser: Decodable {
    let userId: String
    let login: String
    let email: String
    let avatar: String
    let orgs: [String]
    let teams: [String]
    let orgRoles: [String]
    let teamRoles: [String]
}

struct CyberphysWorkspace: Decodable, Identifiable {
    let id: String
    let type: String
    let slug: String
    let role: String
}

private final class CyberphysTokenStore {
    enum Key: String {
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
    }

    private let service = "VisionProTeleop.CyberphysAuth"
    private let userDefaults = UserDefaults.standard
    private var shouldUseUserDefaultsFallback = false
    private var loggedKeychainFallback = false

    private var allowUserDefaultsFallback: Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }

    private func userDefaultsKey(for key: Key) -> String {
        "\(service).\(key.rawValue)"
    }

    private func saveToUserDefaults(_ data: Data, forKey key: Key) -> Bool {
        userDefaults.set(data, forKey: userDefaultsKey(for: key))
        return true
    }

    private func loadFromUserDefaults(forKey key: Key) -> Data? {
        userDefaults.data(forKey: userDefaultsKey(for: key))
    }

    private func deleteFromUserDefaults(key: Key) {
        userDefaults.removeObject(forKey: userDefaultsKey(for: key))
    }

    private func shouldFallbackForKeychainStatus(_ status: OSStatus) -> Bool {
        if status == -34018 {
            return true
        }
        return false
    }

    private func recordKeychainFallback(status: OSStatus) {
        guard allowUserDefaultsFallback else {
            return
        }
        shouldUseUserDefaultsFallback = true
        guard !loggedKeychainFallback else {
            return
        }
        loggedKeychainFallback = true
        cyberphysAuthLogger.warning(
            "Keychain unavailable (status: \(status, privacy: .public)); falling back to UserDefaults for this build"
        )
    }

    @discardableResult
    func save(_ value: String, forKey key: Key) -> Bool {
        guard let data = value.data(using: .utf8) else {
            return false
        }
        return save(data, forKey: key)
    }

    @discardableResult
    func save(_ data: Data, forKey key: Key) -> Bool {
        if shouldUseUserDefaultsFallback {
            return saveToUserDefaults(data, forKey: key)
        }

        let deleteStatus = keychainDelete(key: key)
        if deleteStatus != errSecSuccess,
           deleteStatus != errSecItemNotFound,
           allowUserDefaultsFallback,
           shouldFallbackForKeychainStatus(deleteStatus) {
            recordKeychainFallback(status: deleteStatus)
            return saveToUserDefaults(data, forKey: key)
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key.rawValue,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecSuccess {
            deleteFromUserDefaults(key: key)
            return true
        }

        if allowUserDefaultsFallback, shouldFallbackForKeychainStatus(status) {
            recordKeychainFallback(status: status)
            return saveToUserDefaults(data, forKey: key)
        }

        return false
    }

    func loadString(forKey key: Key) -> String? {
        guard let data = loadData(forKey: key) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    func loadData(forKey key: Key) -> Data? {
        if shouldUseUserDefaultsFallback {
            return loadFromUserDefaults(forKey: key)
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key.rawValue,
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var dataTypeRef: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)
        guard status == errSecSuccess else {
            if allowUserDefaultsFallback, shouldFallbackForKeychainStatus(status) {
                recordKeychainFallback(status: status)
                return loadFromUserDefaults(forKey: key)
            }
            return nil
        }

        guard let data = dataTypeRef as? Data else {
            return nil
        }
        return data
    }

    @discardableResult
    func delete(key: Key) -> Bool {
        deleteFromUserDefaults(key: key)
        if shouldUseUserDefaultsFallback {
            return true
        }

        let status = keychainDelete(key: key)
        if allowUserDefaultsFallback, shouldFallbackForKeychainStatus(status) {
            recordKeychainFallback(status: status)
            return true
        }
        return status == errSecSuccess || status == errSecItemNotFound
    }

    private func keychainDelete(key: Key) -> OSStatus {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key.rawValue,
        ]
        return SecItemDelete(query as CFDictionary)
    }
}

struct CyberphysSignInPromptView: View {
    @ObservedObject var auth: CyberphysAuthManager
    @Environment(\.dismiss) private var dismiss
    @AppStorage("dontShowCyberphysAuthPrompt") private var dontShowAgain: Bool = false

    var body: some View {
        VStack(spacing: 16) {
            VStack(spacing: 6) {
                Text("Cybernetic Physics")
                    .font(.title2.weight(.semibold))
                Text("Sign in with GitHub to view your sessions.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            if let error = auth.authError, !error.isEmpty {
                Text(error)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
            }

            Button {
                Task { await auth.startOAuthFlow() }
            } label: {
                HStack(spacing: 10) {
                    Image(systemName: "person.crop.circle.badge.checkmark")
                    Text(auth.isAuthenticating ? "Signing in…" : "Sign in with GitHub")
                        .font(.headline)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 12)
            }
            .buttonStyle(.borderedProminent)
            .disabled(auth.isAuthenticating)

            Toggle("Don’t ask again", isOn: $dontShowAgain)
                .font(.footnote)

            Button("Continue without signing in") {
                dismiss()
            }
            .buttonStyle(.bordered)
        }
        .padding(24)
        .frame(maxWidth: 520)
        .onChange(of: auth.isAuthenticated) { _, newValue in
            if newValue {
                dismiss()
            }
        }
    }
}

// MARK: - Sessions (Control Plane API)

private struct CyberphysSessionListResponse: Decodable {
    let items: [CyberphysSession]
}

struct CyberphysSession: Decodable, Identifiable {
    struct Access: Decodable {
        let viewerUrl: String?
    }

    let sessionId: String
    let status: String
    let createdAt: String
    let access: Access?

    var id: String { sessionId }
}

struct CyberphysSessionsCard: View {
    @ObservedObject var auth: CyberphysAuthManager
    @Environment(\.openURL) private var openURL

    @State private var sessions: [CyberphysSession] = []
    @State private var isLoading: Bool = false
    @State private var errorMessage: String?
    @State private var selectedWorkspaceId: String = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Cyberphys Sessions")
                        .font(.headline)
                    Text(auth.isAuthenticated ? signedInSubtitle : "Not signed in")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Spacer()

                if auth.isAuthenticated {
                    if auth.workspaces.count > 1 {
                        Picker("Workspace", selection: $selectedWorkspaceId) {
                            ForEach(auth.workspaces) { workspace in
                                Text(workspace.slug)
                                    .tag(workspace.id)
                            }
                        }
                        .pickerStyle(.menu)
                        .onChange(of: selectedWorkspaceId) { _, _ in
                            Task { await fetchSessions() }
                        }
                    }

                    Button("Refresh") {
                        Task { await fetchSessions() }
                    }
                    .buttonStyle(.bordered)

                    Button("Sign out") {
                        auth.signOut()
                    }
                    .buttonStyle(.bordered)
                } else {
                    Button("Sign in") {
                        Task { await auth.startOAuthFlow() }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(auth.isAuthenticating || auth.isRestoringSession)
                }
            }

            if let authError = auth.authError, !authError.isEmpty {
                Text(authError)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.leading)
            }

            if auth.isRestoringSession {
                HStack(spacing: 10) {
                    ProgressView()
                    Text("Restoring session…")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            } else if !auth.isAuthenticated {
                Text("Sign in with GitHub to view your Isaac Sim sessions.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else if isLoading {
                HStack(spacing: 10) {
                    ProgressView()
                    Text("Loading sessions…")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            } else if let errorMessage {
                Text(errorMessage)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.leading)
            } else if sessions.isEmpty {
                Text("No sessions found.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(sessions.prefix(6)) { session in
                    sessionRow(session)
                        .padding(.vertical, 6)
                    Divider().opacity(0.25)
                }
            }
        }
        .padding(16)
        .background(Color.white.opacity(0.06))
        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
        .task(id: auth.isAuthenticated) {
            if auth.isAuthenticated {
                _ = await auth.fetchMe()
                if selectedWorkspaceId.isEmpty {
                    selectedWorkspaceId = auth.activeWorkspaceId ?? auth.workspaces.first?.id ?? ""
                }
                await fetchSessions()
            } else {
                sessions = []
                selectedWorkspaceId = ""
            }
        }
    }

    private var signedInSubtitle: String {
        let identity = auth.userLogin
            ?? auth.userId
            ?? "unknown"
        if let workspace = selectedWorkspace {
            return "Signed in as \(identity) • \(workspace.slug)"
        }
        return "Signed in as \(identity)"
    }

    private var selectedWorkspace: CyberphysWorkspace? {
        let workspaceId = selectedWorkspaceId.isEmpty ? auth.activeWorkspaceId : selectedWorkspaceId
        guard let workspaceId else {
            return nil
        }
        return auth.workspaces.first(where: { $0.id == workspaceId })
    }

    @ViewBuilder
    private func sessionRow(_ session: CyberphysSession) -> some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                Text(session.sessionId)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.primary)
                    .lineLimit(1)

                HStack(spacing: 8) {
                    Text(session.status.uppercased())
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)

                    Text(formatIso(session.createdAt))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Spacer()

            if let urlString = session.access?.viewerUrl,
               let url = URL(string: urlString) {
                Button("Open") {
                    openURL(url)
                }
                .buttonStyle(.bordered)
            }
        }
    }

    private func fetchSessions() async {
        guard !isLoading else { return }
        isLoading = true
        errorMessage = nil
        defer { isLoading = false }

        _ = await auth.fetchMe()
        if selectedWorkspaceId.isEmpty || !auth.workspaces.contains(where: { $0.id == selectedWorkspaceId }) {
            selectedWorkspaceId = auth.activeWorkspaceId ?? auth.workspaces.first?.id ?? ""
        }

        guard let token = auth.accessToken, !token.isEmpty else {
            errorMessage = "Not signed in."
            sessions = []
            return
        }

        do {
            let data = try await requestSessions(
                accessToken: token,
                workspaceId: selectedWorkspaceId.isEmpty ? nil : selectedWorkspaceId,
                allowRefreshRetry: true
            )
            let response = try JSONDecoder().decode(CyberphysSessionListResponse.self, from: data)
            sessions = response.items
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func requestSessions(
        accessToken: String,
        workspaceId: String?,
        allowRefreshRetry: Bool
    ) async throws -> Data {
        var components = URLComponents(
            url: CyberphysAuthConfig.apiBaseURL.appendingPathComponent("v1/sessions"),
            resolvingAgainstBaseURL: false
        )!
        components.queryItems = [
            URLQueryItem(name: "page", value: "1"),
            URLQueryItem(name: "pageSize", value: "20"),
        ]
        if let workspaceId, !workspaceId.isEmpty {
            components.queryItems?.append(URLQueryItem(name: "workspaceId", value: workspaceId))
        }

        guard let url = components.url else {
            throw URLError(.badURL)
        }

        var request = URLRequest(url: url)
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw URLError(.badServerResponse)
        }

        if httpResponse.statusCode == 401, allowRefreshRetry {
            if await auth.refreshAccessToken(), let newToken = auth.accessToken {
                return try await requestSessions(
                    accessToken: newToken,
                    workspaceId: workspaceId,
                    allowRefreshRetry: false
                )
            }
        }

        guard httpResponse.statusCode == 200 else {
            let body = String(data: data, encoding: .utf8) ?? ""
            throw NSError(
                domain: "CyberphysSessions",
                code: httpResponse.statusCode,
                userInfo: [NSLocalizedDescriptionKey: "Failed to load sessions (HTTP \(httpResponse.statusCode))\n\(body)"]
            )
        }

        return data
    }

    private func formatIso(_ isoString: String) -> String {
        // API returns ISO-8601 strings (typically with fractional seconds).
        let fractionalFormatter = ISO8601DateFormatter()
        fractionalFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]

        let plainFormatter = ISO8601DateFormatter()
        plainFormatter.formatOptions = [.withInternetDateTime]

        let date = fractionalFormatter.date(from: isoString) ?? plainFormatter.date(from: isoString)
        guard let date else {
            return isoString
        }

        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .short
        return formatter.string(from: date)
    }
}

// MARK: - ASWebAuthenticationPresentationContextProviding

extension CyberphysAuthManager: ASWebAuthenticationPresentationContextProviding {
    nonisolated func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        #if os(visionOS)
        if let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
           let window = windowScene.windows.first {
            return window
        }
        return UIWindow()
        #else
        return UIWindow()
        #endif
    }
}
